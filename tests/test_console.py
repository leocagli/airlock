"""Live console: the page is self-contained and the endpoints it polls carry its fields."""

import json
import re
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient

from airlock.proxy import create_app

DEMO = Path(__file__).resolve().parent.parent / "demo" / "requests" / "02_mcp_poisoning.json"
SECTIONS = (
    "AIRLOCK",
    "Untrusted content goes through the airlock first",
    "Shield",
    "Achievements",
    "Live decision feed",
    "Reputation ladder",
    "Quarantined tools",
    "Audit chain",
    "Live data from this proxy. No content is stored, only rule ids and hashes.",
)
ENDPOINTS = ("/airlock/stats", "/airlock/events", "/airlock/reputation", "/airlock/audit/verify")
LEVELS = {"trusted", "neutral", "suspicious", "blocked"}


def _upstream(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={
        "id": "msg_mock", "type": "message", "role": "assistant", "model": "claude-mock",
        "content": [{"type": "text", "text": "ok"}],
        "stop_reason": "end_turn", "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 1},
    })


@pytest.fixture
def client(tmp_path, monkeypatch):
    for var in ("AIRLOCK_FINGERPRINTS", "AIRLOCK_TOOL_TRUST", "AIRLOCK_REPUTATION"):
        monkeypatch.delenv(var, raising=False)
    app = create_app(
        upstream_url="http://mock",
        audit_path=str(tmp_path / "audit.jsonl"),
        transport=httpx.MockTransport(_upstream),
    )
    with TestClient(app) as c:
        yield c


def test_console_page_is_served_and_self_contained(client):
    resp = client.get("/airlock/ui")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    page = resp.text
    for title in SECTIONS:
        assert title in page, title
    for path in ENDPOINTS:
        assert f'"{path}"' in page, path
    # Offline and scan friendly: no external scripts, styles, fonts or links.
    assert "<script src" not in page.lower()
    assert not re.search(r"""(?:src|href)\s*=\s*["']?\s*(?:https?:)?//""", page, re.I)
    assert "http://" not in page and "https://" not in page
    assert "@import" not in page
    # Untrusted strings (tool names, rule ids) only reach the DOM through textContent.
    assert "innerHTML" not in page and "outerHTML" not in page
    assert "insertAdjacentHTML" not in page and "document.write" not in page
    assert chr(0x2014) not in page and chr(0x2013) not in page  # no long dashes


def test_endpoints_carry_the_fields_the_console_reads(client):
    resp = client.post("/v1/messages", json=json.loads(DEMO.read_text(encoding="utf-8")))
    assert resp.status_code == 200
    assert resp.headers["x-airlock-action"] in {"ALLOW", "WARN", "REDACT", "BLOCK"}

    stats = client.get("/airlock/stats").json()
    for key in ("started_at", "requests", "actions", "passthrough", "errors", "quarantined_tools"):
        assert key in stats, key
    assert set(stats["actions"]) >= {"ALLOW", "WARN", "REDACT", "BLOCK"}
    assert stats["requests"] == 1
    assert isinstance(stats["quarantined_tools"], list)

    events = client.get("/airlock/events").json()
    assert isinstance(events, list) and len(events) == 1
    event = events[0]
    for key in ("ts", "trace_id", "action", "elapsed_ms", "quarantined_tools", "findings"):
        assert key in event, key
    assert event["action"] == resp.headers["x-airlock-action"]
    assert event["findings"], "the poisoned tool description must produce findings"
    for finding in event["findings"]:
        for key in ("rule_id", "source", "tool_name", "action", "severity", "category"):
            assert key in finding, key
        assert "evidence" not in finding  # the console never sees raw content

    rep = client.get("/airlock/reputation").json()
    assert isinstance(rep, dict)
    for entry in rep.values():
        for key in ("score", "level", "incidents"):
            assert key in entry, key
        assert entry["level"] in LEVELS

    audit = client.get("/airlock/audit/verify").json()
    for key in ("ok", "records_checked", "first_bad_seq"):
        assert key in audit, key
    assert audit["ok"] is True and audit["records_checked"] == 1


def test_console_survives_an_idle_proxy(client):
    """Before any traffic every endpoint still answers with the empty shapes the page handles."""
    assert client.get("/airlock/events").json() == []
    assert client.get("/airlock/audit/verify").json()["records_checked"] == 0
    assert isinstance(client.get("/airlock/reputation").json(), dict)
    stats = client.get("/airlock/stats").json()
    assert stats["requests"] == 0 and stats["quarantined_tools"] == []
