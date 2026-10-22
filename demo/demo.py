"""Offline Airlock demo: no API key, no network.

Runs real requests through the real proxy (in-process) in front of a mock
model that echoes what it received, then proves the audit chain detects
tampering.

    python -m demo.demo            # full story
    python -m demo.demo --slow     # pauses between scenes (for recording)
    python -m demo.demo --print secret | python -m airlock scan -
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402

from airlock.audit import verify  # noqa: E402
from airlock.engine import Airlock  # noqa: E402
from airlock.policy import HARNESS_POLICY  # noqa: E402
from airlock.proxy import create_app  # noqa: E402
from airlock.tools import FingerprintStore  # noqa: E402
from demo.mock_upstream import create_mock_app  # noqa: E402

PLACEHOLDER = "{{FAKE_AWS_KEY}}"
HEADERS = {"x-api-key": "demo-key-not-real", "anthropic-version": "2023-06-01"}


def fake_aws_key() -> str:
    """Built at runtime so no key-shaped literal lives in the repo."""
    return "AKIA" + "Z7XQ" + "DEMO" + "4K2P" + "9W3R"


def load_request(rel: str) -> dict[str, Any]:
    text = (HERE / rel).read_text(encoding="utf-8")
    return json.loads(text.replace(PLACEHOLDER, fake_aws_key()))


@dataclass
class Scene:
    title: str
    file: str
    story: str
    marker: str | None  # attack text that must not reach the model


SCENES = {
    "web": Scene(
        "Indirect prompt injection in a fetched web page",
        "requests/01_web_injection.json",
        "The agent fetched a changelog. An HTML comment tells it to send ~/.env to a webhook.",
        "webhook.site",
    ),
    "mcp": Scene(
        "MCP tool poisoning",
        "requests/02_mcp_poisoning.json",
        "An MCP server ships 'mcp__calc__add_numbers' whose description orders the model to leak mcp.json.",
        "mcp.json",
    ),
    "secret": Scene(
        "Secret pasted by the user",
        "requests/03_secret_paste.json",
        "The user pastes a config with a (fake) AWS access key into the chat.",
        None,
    ),
    "clean": Scene(
        "Clean request",
        "requests/04_clean.json",
        "A normal code review: read a file, suggest a refactor.",
        None,
    ),
}

COLOR = bool(os.environ.get("FORCE_COLOR")) or (
    sys.stdout.isatty() and not os.environ.get("NO_COLOR")
)
ACTION_COLOR = {"ALLOW": "32", "WARN": "33", "REDACT": "35", "BLOCK": "31", "PASSTHROUGH": "36"}


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if COLOR else text


def bold(text: str) -> str:
    return c(text, "1")


def dim(text: str) -> str:
    return c(text, "2")


def act(name: str) -> str:
    return c(f" {name} ", f"1;{ACTION_COLOR.get(name, '37')};7")


def wrap(text: str, indent: str = "    ") -> str:
    return textwrap.fill(
        " ".join(text.split()), width=96, initial_indent=indent, subsequent_indent=indent
    )


def find_path(obj: Any, needle: str, path: tuple = ()) -> tuple | None:
    """Path of the first string leaf that contains needle."""
    if isinstance(obj, str):
        return path if needle in obj else None
    items = (
        obj.items() if isinstance(obj, dict) else enumerate(obj) if isinstance(obj, list) else ()
    )
    for key, value in items:
        hit = find_path(value, needle, (*path, key))
        if hit is not None:
            return hit
    return None


def get_path(obj: Any, path: tuple) -> Any:
    try:
        for key in path:
            obj = obj[key]
        return obj
    except (KeyError, IndexError, TypeError):
        return None


def excerpt(text: str, needle: str, span: int = 70) -> str:
    text = " ".join(text.split())
    i = text.find(needle)
    if i < 0:
        return text[: span * 2] + ("..." if len(text) > span * 2 else "")
    lo, hi = max(0, i - span), min(len(text), i + len(needle) + span)
    return ("..." if lo else "") + text[lo:hi] + ("..." if hi < len(text) else "")


class Demo:
    def __init__(self, workdir: Path, slow: bool) -> None:
        self.slow = slow
        self.audit_path = workdir / "airlock-audit.jsonl"
        self.mock = create_mock_app()
        # Same tool-trust policy as `python -m airlock serve` (native tools trusted, mcp__* not).
        self.engine = Airlock(
            policy=HARNESS_POLICY,
            fingerprints=FingerprintStore(path=str(workdir / "fingerprints.json")),
        )
        self.proxy = create_app(
            airlock=self.engine,
            upstream_url="http://mock-model.local",
            audit_path=str(self.audit_path),
            transport=httpx.ASGITransport(app=self.mock),
        )

    def pause(self) -> None:
        if self.slow:
            time.sleep(1.5)

    def last_audit(self) -> dict[str, Any]:
        lines = self.audit_path.read_text(encoding="utf-8").splitlines()
        return json.loads(lines[-1])

    async def send(self, client: httpx.AsyncClient, body: dict[str, Any]) -> httpx.Response:
        return await client.post("/v1/messages", json=body, headers=HEADERS)

    def show_findings(self, record: dict[str, Any], limit: int = 6) -> None:
        order = {"BLOCK": 0, "REDACT": 1, "WARN": 2, "ALLOW": 3}
        findings = sorted(record["findings"], key=lambda f: order.get(f["action"], 9))
        for f in findings[:limit]:
            tool = f" tool={f['tool_name']}" if f.get("tool_name") else ""
            print(f"    {act(f['action'])} {bold(f['rule_id'])}  {f['category']} ({f['owasp']}) "
                  f"in {f['source']}{tool}, severity {f['severity']}")
        if len(findings) > limit:
            print(dim(f"    ... and {len(findings) - limit} more"))
        if record.get("quarantined_tools"):
            print(f"    quarantined tools: {c(', '.join(record['quarantined_tools']), '1;35')}")

    async def scene(
        self, client: httpx.AsyncClient, n: int, sc: Scene, body: dict[str, Any] | None = None
    ) -> str:
        body = body or load_request(sc.file)
        marker = sc.marker or (
            fake_aws_key() if PLACEHOLDER in (HERE / sc.file).read_text("utf-8") else None
        )
        print()
        print(bold(f"[{n}] {sc.title}"))
        print(dim(wrap(sc.story, "    ")))
        path = find_path(body, marker) if marker else None
        if path is not None:
            where = dim("at " + ".".join(map(str, path)))
            print(f"    {c('BEFORE', '1;33')} the agent sends: {where}")
            print(wrap(excerpt(get_path(body, path), marker), "      "))

        before = len(self.mock.state.received)
        resp = await self.send(client, body)
        action = resp.headers.get("x-airlock-action", "?")
        record = self.last_audit()
        print(f"    Airlock {act(action)} {resp.headers.get('x-airlock-findings')} finding(s), "
              f"trace {resp.headers.get('x-airlock-trace')}, {record['elapsed_ms']} ms")
        self.show_findings(record)

        reached = len(self.mock.state.received) > before
        if not reached:
            print(f"    {c('AFTER', '1;32')} model called: {c('NO', '1;32')}. "
                  "The agent receives this reply instead:")
            print(wrap(resp.json()["content"][0]["text"], "      "))
        else:
            seen = self.mock.state.received[-1]
            leaked = marker is not None and marker in json.dumps(seen)
            verdict = c("YES", "1;31") if leaked else c("NO", "1;32")
            label = "attack text reached the model" if sc.marker else "secret reached the model"
            if marker:
                print(f"    {c('AFTER', '1;32')} {label}: {verdict}")
                if path is not None and path[0] != "tools":
                    orig, after = get_path(body, path), get_path(seen, path)
                    if isinstance(orig, str) and isinstance(after, str):
                        flat = " ".join(orig.split())
                        at = flat.find(marker)
                        anchor = flat[max(0, at - 24):at] if at > 0 else flat[:20]
                        print(wrap(excerpt(after, anchor, span=40), "      "))
            names = [t.get("name") for t in seen.get("tools") or []]
            if names or body.get("tools"):
                print(f"    tools the model can call: {', '.join(names) or 'none'}")
            if not marker:
                print(f"    {c('AFTER', '1;32')} forwarded unchanged: "
                      f"{c('YES', '1;32') if seen == body else c('NO', '1;33')}")
        self.pause()
        return action

    async def run(self) -> int:
        print(bold("Airlock offline demo") + dim("  (real proxy, mock model, no network)"))
        transport = httpx.ASGITransport(app=self.proxy)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://airlock.local"
        ) as client:
            n = 0
            for sc in SCENES.values():
                n += 1
                await self.scene(client, n, sc)

            n += 1
            print()
            print(bold(f"[{n}] MCP rug pull"))
            print(dim(wrap("Monday the mcp__weather__get_forecast tool is harmless and gets pinned. "
                           "Tuesday the same server silently rewrites its description.", "    ")))
            first = await self.send(client, load_request("rugpull_before.json"))
            day1 = act(first.headers.get("x-airlock-action", "?"))
            print(f"    day 1: Airlock {day1} (fingerprint pinned)")
            rug = Scene("", "rugpull_after.json", "", "id_rsa")
            second = await self.send(client, load_request(rug.file))
            print(f"    day 2: Airlock {act(second.headers.get('x-airlock-action', '?'))}")
            self.show_findings(self.last_audit())
            seen = self.mock.state.received[-1] if self.mock.state.received else {}
            leaked = (
                second.headers.get("x-airlock-action") != "BLOCK"
                and "id_rsa" in json.dumps(seen)
            )
            verdict = c("YES", "1;31") if leaked else c("NO", "1;32")
            print(f"    rewritten description reached the model: {verdict}")
            self.pause()

            print()
            print(bold("[*] Proxy stats and audit chain"))
            stats = (await client.get("/airlock/stats")).json()
            counts = "  ".join(f"{k}={v}" for k, v in stats["actions"].items())
            print(f"    requests={stats['requests']}  {counts}")
            print(f"    quarantined tools seen: {', '.join(stats['quarantined_tools']) or 'none'}")
            check = (await client.get("/airlock/audit/verify")).json()
            ok = c("INTACT", "1;32") if check["ok"] else c("BROKEN", "1;31")
            print(f"    audit log: {check['records_checked']} hash-chained record(s), chain {ok}")
        return self.tamper_test()

    def tamper_test(self) -> int:
        lines = self.audit_path.read_text(encoding="utf-8").splitlines()
        target = next((i for i, ln in enumerate(lines) if '"action":"BLOCK"' in ln), 0)
        rec = json.loads(lines[target])
        rec["action"] = "ALLOW" if rec.get("action") != "ALLOW" else "BLOCK"
        lines[target] = json.dumps(rec, separators=(",", ":"))
        copy = self.audit_path.with_name("tampered-copy.jsonl")
        copy.write_text("\n".join(lines) + "\n", encoding="utf-8")
        ok, checked, bad = verify(str(copy))
        print(f"    tamper test: an attacker edits record seq {target} to say {rec['action']} ...")
        if ok:
            print(f"    verify: {c('NOT DETECTED', '1;31')}")
            return 1
        print(f"    verify: {c('TAMPERING DETECTED', '1;31;7')} at seq {bad} "
              f"({checked} record(s) still valid)")
        print()
        print(dim("Live: python -m airlock serve  then  "
                  "ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude"))
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline Airlock demo")
    parser.add_argument("--slow", action="store_true", help="pause between scenes")
    parser.add_argument("--keep", action="store_true", help="keep the temp audit log")
    parser.add_argument(
        "--print",
        dest="print_scene",
        choices=[*SCENES, "rugpull_before", "rugpull_after"],
        help="print one expanded request body as JSON and exit",
    )
    args = parser.parse_args(argv)

    if args.print_scene:
        rel = (
            SCENES[args.print_scene].file
            if args.print_scene in SCENES
            else f"{args.print_scene}.json"
        )
        print(json.dumps(load_request(rel), indent=2))
        return 0

    workdir = Path(tempfile.mkdtemp(prefix="airlock-demo-"))
    try:
        return asyncio.run(Demo(workdir, args.slow).run())
    finally:
        if args.keep:
            print(dim(f"audit log kept in {workdir}"))
        else:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
