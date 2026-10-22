"""Command line: python -m airlock {scan,serve,audit-verify,redteam}.

scan exit codes: 0 ALLOW/WARN, 1 REDACT, 2 BLOCK, 3 unreadable input.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any

from .engine import Airlock, Decision
from .tools import FingerprintStore
from .types import Action, Source

EXIT_INPUT_ERROR = 3
_EXIT = {Action.ALLOW: 0, Action.WARN: 0, Action.REDACT: 1, Action.BLOCK: 2}
_COLORS = {"ALLOW": "32", "WARN": "33", "REDACT": "35", "BLOCK": "31"}


def make_airlock(fingerprints: str | None = None) -> Airlock:
    """Factory used by scan; tests swap it for a scripted engine."""
    return Airlock(fingerprints=FingerprintStore(path=fingerprints) if fingerprints else None)


def _use_color(stream: Any) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return bool(os.environ.get("FORCE_COLOR")) or (hasattr(stream, "isatty") and stream.isatty())


def _paint(text: str, action: str, color: bool) -> str:
    code = _COLORS.get(action)
    return f"\033[{code}m{text}\033[0m" if color and code else text


def _changed_fields(before: Any, after: Any) -> int:
    """Number of string leaves that differ between two request bodies."""
    if isinstance(before, dict) and isinstance(after, dict):
        return sum(_changed_fields(before[k], after.get(k)) for k in before if k != "tools")
    if isinstance(before, list) and isinstance(after, list):
        return sum(_changed_fields(b, a) for b, a in zip(before, after, strict=False))
    if isinstance(before, str):
        return int(before != after)
    return 0


def render_table(decision: Decision, original: dict[str, Any], color: bool = False) -> str:
    action = decision.action.name
    lines = [
        _paint(f"Airlock decision: {action}", action, color)
        + f"  ({len(decision.findings)} finding(s), {decision.elapsed_ms:.1f} ms, "
        f"trace {decision.trace_id})"
    ]
    if decision.findings:
        header = ("ACTION", "RULE", "CATEGORY", "OWASP", "SOURCE", "TOOL", "SEVERITY", "EVIDENCE")
        rows = [
            (a.name, f.rule_id, f.category.value, f.owasp, f.source.value,
             f.tool_name or "-", f.severity.name, f.evidence)
            for f, a in zip(decision.findings, decision.actions, strict=True)
        ]
        widths = [max(len(str(r[i])) for r in [header, *rows]) for i in range(len(header) - 1)]

        def fmt(row: tuple[str, ...], paint: bool) -> str:
            cells = [str(c).ljust(w) for c, w in zip(row, widths, strict=False)]
            if paint:
                cells[0] = _paint(cells[0], row[0], color)
            return "  ".join([*cells, str(row[-1])])

        lines.append("")
        lines.append(fmt(header, False))
        lines.extend(fmt(r, True) for r in rows)

    if decision.action is Action.REDACT:
        redacted = [
            f for f, a in zip(decision.findings, decision.actions, strict=True)
            if a is Action.REDACT and f.source is not Source.TOOL_DEFINITION
        ]
        lines.append("")
        lines.append(
            f"Sanitized body: {len(redacted)} span(s) redacted in "
            f"{_changed_fields(original, decision.body)} field(s); "
            f"quarantined tools: {', '.join(decision.quarantined_tools) or 'none'}"
        )
    elif decision.action is Action.BLOCK:
        lines.append("")
        lines.append("Request would be blocked: nothing is sent to the model.")
    return "\n".join(lines)


def _load_body(path: str) -> dict[str, Any]:
    if path == "-":
        text = sys.stdin.read()
    else:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    body = json.loads(text)
    if not isinstance(body, dict):
        raise ValueError("request body must be a JSON object")
    return body


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        body = _load_body(args.file)
    except (OSError, ValueError) as exc:
        print(f"airlock scan: cannot read {args.file}: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    decision = make_airlock(args.fingerprints).inspect(body)
    if args.json:
        print(json.dumps(decision.to_record(), indent=2))
    else:
        print(render_table(decision, body, color=_use_color(sys.stdout)))
    return _EXIT[decision.action]


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .proxy import create_app

    if args.upstream:
        os.environ["AIRLOCK_UPSTREAM"] = args.upstream
    if args.audit_log:
        os.environ["AIRLOCK_AUDIT_LOG"] = args.audit_log
    if args.fingerprints:
        os.environ["AIRLOCK_FINGERPRINTS"] = args.fingerprints
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per request, ours
    print(f"Airlock listening on http://{args.host}:{args.port}  "
          f"(use ANTHROPIC_BASE_URL=http://{args.host}:{args.port})", file=sys.stderr)
    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="warning")
    return 0


def cmd_audit_verify(args: argparse.Namespace) -> int:
    from .audit import verify

    ok, checked, first_bad = verify(args.path)
    if ok:
        print(f"OK: {checked} record(s), hash chain intact ({args.path})")
        return 0
    print(
        f"TAMPERED: chain breaks at seq {first_bad} after {checked} valid record(s) ({args.path})"
    )
    return 1


def cmd_redteam(args: argparse.Namespace) -> int:
    return run_redteam(list(args.args))


def run_redteam(argv: list[str]) -> int:
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    try:
        from redteam import run
    except ImportError as exc:
        print(f"airlock redteam: red team harness not available ({exc}). "
              "Run from the repository root where redteam/run.py lives.", file=sys.stderr)
        return EXIT_INPUT_ERROR
    result = run.main(argv)
    return result if isinstance(result, int) else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="airlock",
        description="Prompt-injection and MCP tool-poisoning firewall for LLM agents.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="inspect a Messages API request body (file or - for stdin)")
    scan.add_argument("file")
    scan.add_argument("--json", action="store_true", help="print the audit-safe decision record")
    scan.add_argument("--fingerprints", help="tool fingerprint store (enables rug-pull detection)")
    scan.set_defaults(func=cmd_scan)

    serve = sub.add_parser("serve", help="run the HTTP proxy")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8787)
    serve.add_argument("--upstream", help="default: $AIRLOCK_UPSTREAM or https://api.anthropic.com")
    serve.add_argument("--audit-log", help="default: $AIRLOCK_AUDIT_LOG or airlock-audit.jsonl")
    serve.add_argument("--fingerprints", help="default: $AIRLOCK_FINGERPRINTS (in-memory if unset)")
    serve.set_defaults(func=cmd_serve)

    av = sub.add_parser("audit-verify", help="verify the audit log hash chain")
    av.add_argument("path")
    av.set_defaults(func=cmd_audit_verify)

    rt = sub.add_parser("redteam", help="run the red team corpus against the engine")
    rt.add_argument("args", nargs=argparse.REMAINDER)
    rt.set_defaults(func=cmd_redteam)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] == "redteam":
        # Pass everything (including --flags) straight to the red team harness.
        return run_redteam(argv[1:])
    args = build_parser().parse_args(argv)
    return args.func(args)
