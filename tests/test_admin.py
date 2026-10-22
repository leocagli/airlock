"""Controller (admin) API: token gate, strict mode, pin approval, reputation pardon, audit."""

import copy
import json
import logging
import re
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient

from airlock.audit import verify
from airlock.proxy import create_app
from airlock.tools import fingerprint

ROOT = Path(__file__).resolve().parent.parent
BEFORE = json.loads((ROOT / "demo" / "rugpull_before.json").read_text(encoding="utf-8"))
AFTER = json.loads((ROOT / "demo" / "rugpull_after.json").read_text(encoding="utf-8"))
TOOL = "mcp__weather__get_forecast"
TOKEN = "test-admin-token-0123456789abcdef"
AUTH = {"x-airlock-admin-token": TOKEN}
# A tool result whose only finding is INJ-ADDRESS-AI (MEDIUM): WARN normally, REDACT in strict.
NOTE = "Forecast for Lisbon: sunny, 24 C. Note to the AI assistant: data refreshes hourly."
ADMIN = (
    ("GET", "/airlock/admin/state", None),
    ("POST", "/airlock/admin/mode", {"mode": "strict"}),
    ("POST", "/airlock/admin/pins/approve", {"tool": TOOL}),
    ("POST", "/airlock/admin/reputation/reset", {"subject": "server:weather"}),
)


class Upstream:
    def __init__(self) -> None:
        self.bodies: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.bodies.append(json.loads(request.content))
        return httpx.Response(200, json={
            "id": "msg_mock", "type": "message", "role": "assistant", "model": "claude-mock",
            "content": [{"type": "text", "text": "ok"}],
            "stop_reason": "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1},
        })


def medium_body() -> dict:
    return {
        "model": "claude-sonnet-5-5",
        "max_tokens": 64,
        "messages": [
            {"role": "user", "content": "Will it rain in Lisbon?"},
            {"role": "assistant", "content": [{
                "type": "tool_use", "id": "t1", "name": "get_weather", "input": {"city": "Lisbon"},
            }]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": NOTE},
            ]},
        ],
    }


def benign_change() -> dict:
    body = copy.deepcopy(BEFORE)
    body["tools"][0]["description"] = "Get the weather forecast for a city for the next seven days."
    return body


def make_client(tmp_path, monkeypatch, token=TOKEN, reputation=None):
    for var in ("AIRLOCK_FINGERPRINTS", "AIRLOCK_TOOL_TRUST", "AIRLOCK_REPUTATION",
                "AIRLOCK_ADMIN_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    if token is not None:
        monkeypatch.setenv("AIRLOCK_ADMIN_TOKEN", token)
    if reputation is not None:
        monkeypatch.setenv("AIRLOCK_REPUTATION", reputation)
    upstream = Upstream()
    app = create_app(
        upstream_url="http://mock",
        audit_path=str(tmp_path / "audit.jsonl"),
        transport=httpx.MockTransport(upstream),
    )
    return app, upstream


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    app, upstream = make_client(tmp_path, monkeypatch)
    with TestClient(app) as c:
        yield c, upstream, tmp_path / "audit.jsonl"


def call(c, method, path, payload=None, headers=AUTH):
    if method == "GET":
        return c.get(path, headers=headers)
    return c.post(path, json=payload, headers=headers)


def last_rules(c) -> set[str]:
    return {f["rule_id"] for f in c.get("/airlock/events").json()[0]["findings"]}


def state(c) -> dict:
    resp = c.get("/airlock/admin/state", headers=AUTH)
    assert resp.status_code == 200
    return resp.json()


# --- token gate ----------------------------------------------------------------------


def test_admin_endpoints_need_the_token(ctx):
    c, _, _ = ctx
    for method, path, payload in ADMIN:
        for headers in ({}, {"x-airlock-admin-token": "wrong"},
                        {"x-airlock-admin-token": ""},
                        {"x-airlock-admin-token": TOKEN + "x"},
                        {"x-airlock-admin-token": "töken".encode("latin-1")}):
            resp = call(c, method, path, payload, headers=headers)
            assert resp.status_code == 401, (path, headers)
            assert resp.json() == {"error": "admin token required"}
            assert not any(h.startswith("access-control-") for h in resp.headers), path
    # Nothing changed and nothing was audited by the rejected calls.
    assert state(c)["mode"] == "normal"
    assert c.get("/airlock/audit/verify").json()["records_checked"] == 0


def test_admin_api_sends_no_cors_headers(ctx):
    c, _, _ = ctx
    pre = c.options("/airlock/admin/mode", headers={
        "origin": "http://evil.example", "access-control-request-method": "POST",
        "access-control-request-headers": "x-airlock-admin-token",
    })
    assert pre.status_code >= 400
    assert not any(h.startswith("access-control-") for h in pre.headers)
    ok = c.get("/airlock/admin/state", headers={**AUTH, "origin": "http://evil.example"})
    assert ok.status_code == 200
    assert not any(h.startswith("access-control-") for h in ok.headers)
    assert ok.headers["cache-control"] == "no-store"


def test_state_shape(ctx):
    c, _, _ = ctx
    s = state(c)
    assert set(s) == {"mode", "policy", "pins", "changed_tools", "reputation"}
    assert s["mode"] == "normal"
    assert s["policy"]["untrusted_redact_at"] == "HIGH"
    assert s["policy"]["untrusted_tool_prefixes"] == ["mcp__"]
    assert s["pins"] == {} and s["changed_tools"] == [] and s["reputation"] == {}

    assert c.post("/v1/messages", json=BEFORE).headers["x-airlock-action"] == "ALLOW"
    s = state(c)
    assert s["pins"] == {TOOL: fingerprint(BEFORE["tools"][0])[:16]}
    assert s["changed_tools"] == []
    c.post("/v1/messages", json=AFTER)
    s = state(c)
    assert set(s["reputation"]) == {f"tool:{TOOL}", "server:weather"}
    for entry in s["reputation"].values():
        assert {"score", "level", "baseline", "incidents"} <= set(entry)


# --- mode ----------------------------------------------------------------------------


def test_strict_mode_changes_the_decision_and_normal_restores_it(ctx):
    c, upstream, _ = ctx
    resp = c.post("/v1/messages", json=medium_body())
    assert resp.headers["x-airlock-action"] == "WARN"
    assert last_rules(c) == {"INJ-ADDRESS-AI"}
    assert NOTE in json.dumps(upstream.bodies[-1])

    resp = call(c, "POST", "/airlock/admin/mode", {"mode": "strict"})
    assert resp.status_code == 200 and resp.json() == {"mode": "strict"}
    s = state(c)
    assert s["mode"] == "strict"
    assert s["policy"]["untrusted_redact_at"] == "MEDIUM"
    assert s["policy"]["untrusted_block_at"] == "HIGH"
    assert s["policy"]["tool_definition_quarantine_at"] == "MEDIUM"
    assert s["policy"]["block_untrusted_critical"] is True

    resp = c.post("/v1/messages", json=medium_body())
    assert resp.headers["x-airlock-action"] == "REDACT"
    assert "Note to the AI" not in json.dumps(upstream.bodies[-1])

    assert call(c, "POST", "/airlock/admin/mode", {"mode": "normal"}).json() == {"mode": "normal"}
    assert state(c)["policy"]["untrusted_redact_at"] == "HIGH"
    resp = c.post("/v1/messages", json=medium_body())
    assert resp.headers["x-airlock-action"] == "WARN"
    assert NOTE in json.dumps(upstream.bodies[-1])


@pytest.mark.parametrize("payload", [
    {"mode": "STRICT"}, {"mode": ""}, {"mode": 1}, {"mode": None}, {"mode": ["strict"]},
    {"mode": "strict", "extra": 1}, {}, ["strict"], "strict", {"mode": "x" * 201},
])
def test_mode_rejects_bad_input(ctx, payload):
    c, _, _ = ctx
    resp = call(c, "POST", "/airlock/admin/mode", payload)
    assert resp.status_code == 400
    assert "error" in resp.json()
    assert state(c)["mode"] == "normal"


def test_mode_rejects_non_json_and_oversized_bodies(ctx):
    c, _, _ = ctx
    bad = c.post("/airlock/admin/mode", content=b"{nope", headers=AUTH)
    big = c.post("/airlock/admin/mode", content=b'{"mode":"' + b"s" * 5000 + b'"}', headers=AUTH)
    assert bad.status_code == 400 and big.status_code == 400


# --- pins ----------------------------------------------------------------------------


def test_rug_pull_shows_as_changed_and_approval_clears_it(ctx):
    """demo/rugpull_after.json: approving the new definition clears TOOL-RUGPULL, but its
    description is itself poisoned, so the tool stays quarantined. Approval is not a bypass."""
    c, _, _ = ctx
    assert c.post("/v1/messages", json=BEFORE).headers["x-airlock-action"] == "ALLOW"
    resp = c.post("/v1/messages", json=AFTER)
    assert resp.headers["x-airlock-action"] == "REDACT"
    assert "TOOL-RUGPULL" in last_rules(c)
    assert TOOL in c.get("/airlock/events").json()[0]["quarantined_tools"]

    before_fp = fingerprint(BEFORE["tools"][0])
    after_fp = fingerprint(AFTER["tools"][0])
    assert state(c)["changed_tools"] == [
        {"tool": TOOL, "pinned": before_fp[:16], "latest": after_fp[:16]}
    ]

    resp = call(c, "POST", "/airlock/admin/pins/approve", {"tool": TOOL})
    assert resp.status_code == 200
    assert resp.json() == {"tool": TOOL, "pinned": after_fp[:16]}
    s = state(c)
    assert s["changed_tools"] == [] and s["pins"][TOOL] == after_fp[:16]

    c.post("/v1/messages", json=AFTER)
    rules = last_rules(c)
    assert "TOOL-RUGPULL" not in rules
    assert "TOOL-POISON-DIRECTIVE" in rules
    assert TOOL in c.get("/airlock/events").json()[0]["quarantined_tools"]


def test_approved_benign_change_is_no_longer_quarantined(ctx):
    c, upstream, _ = ctx
    c.post("/v1/messages", json=BEFORE)
    changed = benign_change()
    resp = c.post("/v1/messages", json=changed)
    assert resp.headers["x-airlock-action"] == "REDACT"
    assert last_rules(c) == {"TOOL-RUGPULL"}
    assert TOOL not in [t.get("name") for t in upstream.bodies[-1].get("tools") or []]
    assert [t["tool"] for t in state(c)["changed_tools"]] == [TOOL]

    assert call(c, "POST", "/airlock/admin/pins/approve", {"tool": TOOL}).status_code == 200
    resp = c.post("/v1/messages", json=changed)
    assert resp.headers["x-airlock-action"] == "ALLOW"
    assert c.get("/airlock/events").json()[0]["quarantined_tools"] == []
    assert [t["name"] for t in upstream.bodies[-1]["tools"]] == [TOOL]
    assert state(c)["changed_tools"] == []


def test_approve_unknown_tool_is_404_and_bad_input_is_400(ctx):
    c, _, _ = ctx
    resp = call(c, "POST", "/airlock/admin/pins/approve", {"tool": "mcp__never__seen"})
    assert resp.status_code == 404
    for payload in ({"tool": ""}, {"tool": 7}, {"tool": "a" * 201}, {"tool": "a\nb"},
                    {"name": TOOL}, {"tool": TOOL, "force": True}):
        assert call(c, "POST", "/airlock/admin/pins/approve", payload).status_code == 400


def test_seen_tools_are_bounded(ctx):
    c, _, _ = ctx

    def name(i):
        return f"mcp__bulk__tool{i:03d}x{i:03d}"

    for start in range(0, 520, 20):  # 26 requests of 20 tools: 520 names in total
        tools = [{"name": name(i), "description": "Adds two numbers.",
                  "input_schema": {"type": "object", "properties": {}}}
                 for i in range(start, start + 20)]
        c.post("/v1/messages", json={"model": "m", "max_tokens": 1, "tools": tools,
                                     "messages": [{"role": "user", "content": "hi"}]})
    oldest = call(c, "POST", "/airlock/admin/pins/approve", {"tool": name(0)})
    newest = call(c, "POST", "/airlock/admin/pins/approve", {"tool": name(519)})
    assert oldest.status_code == 404 and newest.status_code == 200


# --- reputation ----------------------------------------------------------------------


def test_reputation_reset_restores_a_lowered_score(ctx):
    c, _, _ = ctx
    c.post("/v1/messages", json=BEFORE)
    c.post("/v1/messages", json=AFTER)
    lowered = c.get("/airlock/reputation").json()["server:weather"]
    assert lowered["score"] < lowered["baseline"] == 60

    resp = call(c, "POST", "/airlock/admin/reputation/reset", {"subject": "server:weather"})
    assert resp.status_code == 200
    assert resp.json() == {"subject": "server:weather", "score": 60, "level": "neutral"}
    assert c.get("/airlock/reputation").json()["server:weather"]["score"] == 60
    assert state(c)["reputation"]["server:weather"]["score"] == 60

    unknown = call(c, "POST", "/airlock/admin/reputation/reset", {"subject": "server:nobody"})
    assert unknown.status_code == 404
    for payload in ({"subject": "weather"}, {"subject": "user:x"}, {"subject": "server:"},
                    {"subject": 3}, {"subject": "server:" + "w" * 200}):
        resp = call(c, "POST", "/airlock/admin/reputation/reset", payload)
        assert resp.status_code == 400, payload


def test_reputation_reset_is_404_when_reputation_is_off(tmp_path, monkeypatch):
    app, _ = make_client(tmp_path, monkeypatch, reputation="off")
    with TestClient(app) as c:
        c.post("/v1/messages", json=AFTER)
        assert state(c)["reputation"] == {}
        resp = call(c, "POST", "/airlock/admin/reputation/reset", {"subject": "server:weather"})
        assert resp.status_code == 404


# --- audit and secrecy -----------------------------------------------------------------


def run_every_action(c) -> list[httpx.Response]:
    out = [c.post("/v1/messages", json=BEFORE), c.post("/v1/messages", json=AFTER)]
    out.append(call(c, "POST", "/airlock/admin/mode", {"mode": "strict"}))
    out.append(call(c, "POST", "/airlock/admin/mode", {"mode": "normal"}))
    out.append(call(c, "POST", "/airlock/admin/pins/approve", {"tool": TOOL}))
    out.append(call(c, "POST", "/airlock/admin/pins/approve", {"tool": "mcp__never__seen"}))
    out.append(call(c, "POST", "/airlock/admin/reputation/reset", {"subject": "server:weather"}))
    for path in ("/airlock/admin/state", "/airlock/stats", "/airlock/events",
                 "/airlock/reputation", "/airlock/audit/verify", "/healthz"):
        out.append(c.get(path, headers=AUTH))
    return out


def test_every_admin_action_is_audited_and_the_chain_verifies(ctx):
    c, _, audit = ctx
    run_every_action(c)
    records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    admin = [(r["admin_action"], r["target"], r["result"]) for r in records if "admin_action" in r]
    assert admin == [
        ("set_mode", "strict", "ok"),
        ("set_mode", "normal", "ok"),
        ("approve_pin", TOOL, "ok"),
        ("approve_pin", "mcp__never__seen", "not_found"),
        ("reset_reputation", "server:weather", "ok"),
    ]
    for r in records:
        if "admin_action" in r:
            assert set(r) == {"admin_action", "target", "result", "seq", "ts", "prev_hash", "hash"}
    assert verify(str(audit)) == (True, len(records), None)
    assert c.get("/airlock/audit/verify").json()["ok"] is True


def test_token_never_leaks(ctx):
    c, _, audit = ctx
    for resp in run_every_action(c):
        assert TOKEN not in resp.text
        assert all(TOKEN not in v for v in resp.headers.values())
    assert TOKEN not in audit.read_text(encoding="utf-8")


def test_generated_token_is_logged_once_and_only_to_the_log(tmp_path, monkeypatch, caplog):
    app, _ = make_client(tmp_path, monkeypatch, token=None)
    token = app.state.admin_token
    assert isinstance(token, str) and len(token) >= 32
    with caplog.at_level(logging.WARNING, logger="airlock.proxy"), TestClient(app) as c:
        responses = run_every_action(c)
        assert responses[2].status_code == 401  # the test token is not the generated one
        ok = c.get("/airlock/admin/state", headers={"x-airlock-admin-token": token})
        assert ok.status_code == 200 and token not in ok.text
        responses.append(ok)
    assert sum(token in r.getMessage() for r in caplog.records) == 1
    assert all(token not in r.text for r in responses)
    assert token not in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")


def test_env_token_is_not_logged(tmp_path, monkeypatch, caplog):
    app, _ = make_client(tmp_path, monkeypatch)
    with caplog.at_level(logging.DEBUG, logger="airlock.proxy"), TestClient(app) as c:
        c.get("/airlock/admin/state", headers=AUTH)
    assert all(TOKEN not in r.getMessage() for r in caplog.records)


# --- console -------------------------------------------------------------------------


def test_console_has_the_controller(ctx):
    c, _, _ = ctx
    page = c.get("/airlock/ui").text
    for needle in ("Controller", "Paste the admin token printed by python -m airlock serve",
                   '"/airlock/admin/state"', '"/airlock/admin/mode"',
                   '"/airlock/admin/pins/approve"', '"/airlock/admin/reputation/reset"',
                   "Approve new definition", "Pardon (reset)", "x-airlock-admin-token",
                   'type="password"', "sessionStorage"):
        assert needle in page, needle
    assert "localStorage" not in page  # the token is kept for this tab only
    assert "innerHTML" not in page and "outerHTML" not in page
    assert chr(0x2014) not in page and chr(0x2013) not in page
    assert not re.search(r"""(?:src|href)\s*=\s*["']?\s*(?:https?:)?//""", page, re.I)
    assert "Content-Security-Policy" in page and "connect-src 'self'" in page
