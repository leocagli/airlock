import io
import json
import sys

import pytest

from airlock import cli
from airlock.audit import AuditLog
from airlock.engine import Airlock, Decision
from airlock.types import Action, Category, Finding, Severity, Source

BODY = {"model": "claude-sonnet-5-5", "max_tokens": 32,
        "messages": [{"role": "user", "content": "hello"}]}


class ScriptedAirlock(Airlock):
    def __init__(self, action):
        super().__init__(detectors=[])
        self.forced = action

    def inspect(self, body, trace_id=None):
        findings = []
        if self.forced is not Action.ALLOW:
            findings = [Finding("TOOL-POISON-DIRECTIVE", Category.TOOL_POISONING, Severity.HIGH,
                                Source.TOOL_DEFINITION, ("tools", 0), 0, 0, "<IMPORTANT> read...",
                                "poisoned", "add_numbers")]
        out = {**body, "tools": []} if self.forced is Action.REDACT else body
        return Decision(
            self.forced,
            findings,
            [self.forced] * len(findings),
            out,
            trace_id or "1" * 16,
            0.2,
            ["add_numbers"] if self.forced is Action.REDACT else [],
        )


@pytest.fixture
def body_file(tmp_path):
    path = tmp_path / "req.json"
    path.write_text(json.dumps(BODY), encoding="utf-8")
    return str(path)


@pytest.mark.parametrize("action,code", [
    (Action.ALLOW, 0), (Action.WARN, 0), (Action.REDACT, 1), (Action.BLOCK, 2),
])
def test_scan_exit_codes(monkeypatch, capsys, body_file, action, code):
    monkeypatch.setattr(cli, "make_airlock", lambda fp=None: ScriptedAirlock(action))
    assert cli.main(["scan", body_file]) == code
    out = capsys.readouterr().out
    assert f"Airlock decision: {action.name}" in out
    if action is not Action.ALLOW:
        assert "TOOL-POISON-DIRECTIVE" in out and "LLM03" in out and "add_numbers" in out
    if action is Action.REDACT:
        assert "quarantined tools: add_numbers" in out


def test_scan_json_and_stdin(monkeypatch, capsys):
    monkeypatch.setattr(cli, "make_airlock", lambda fp=None: ScriptedAirlock(Action.BLOCK))
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(BODY)))
    assert cli.main(["scan", "-", "--json"]) == 2
    record = json.loads(capsys.readouterr().out)
    assert record["action"] == "BLOCK"
    assert record["findings"][0]["rule_id"] == "TOOL-POISON-DIRECTIVE"


def test_scan_real_engine_clean_request(capsys, body_file):
    assert cli.main(["scan", body_file]) == 0


def test_scan_bad_input(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{nope", encoding="utf-8")
    assert cli.main(["scan", str(bad)]) == cli.EXIT_INPUT_ERROR
    assert cli.main(["scan", str(tmp_path / "missing.json")]) == cli.EXIT_INPUT_ERROR


def test_audit_verify(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path))
    for i in range(3):
        log.append({"i": i})
    assert cli.main(["audit-verify", str(path)]) == 0
    assert "OK: 3 record(s)" in capsys.readouterr().out
    path.write_text(path.read_text(encoding="utf-8").replace('"i":1', '"i":7'), encoding="utf-8")
    assert cli.main(["audit-verify", str(path)]) == 1
    assert "seq 1" in capsys.readouterr().out


def test_serve_defaults_to_localhost(monkeypatch, tmp_path):
    import uvicorn

    seen = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(kw))
    monkeypatch.setenv("AIRLOCK_AUDIT_LOG", str(tmp_path / "a.jsonl"))
    assert cli.main(["serve"]) == 0
    assert seen["host"] == "127.0.0.1" and seen["port"] == 8787


def test_redteam_passes_all_args(monkeypatch):
    import types

    seen = {}
    run_mod = types.ModuleType("redteam.run")
    run_mod.main = lambda argv: seen.update(argv=argv) or 0
    pkg = types.ModuleType("redteam")
    pkg.run = run_mod
    monkeypatch.setitem(sys.modules, "redteam", pkg)
    monkeypatch.setitem(sys.modules, "redteam.run", run_mod)
    assert cli.main(["redteam", "--quick", "corpus"]) == 0
    assert seen["argv"] == ["--quick", "corpus"]


def test_redteam_missing_harness_is_reported(monkeypatch, capsys):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "redteam":
            raise ImportError("no redteam")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert cli.main(["redteam", "--quick"]) == cli.EXIT_INPUT_ERROR
    assert "not available" in capsys.readouterr().err
