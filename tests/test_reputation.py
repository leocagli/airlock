"""Reputation layer: scores, persistence, detector, ERC-8004 feedback, end to end.

All findings here are synthetic Finding objects or come from a fake detector;
tool definitions are plain and harmless.
"""

from __future__ import annotations

import hashlib
import json
import threading

import pytest

from airlock.detectors import TEXT_DETECTORS
from airlock.engine import Airlock, Decision
from airlock.policy import HARNESS_POLICY
from airlock.reputation import (
    RULE_ID,
    ReputationAirlock,
    ReputationBook,
    ReputationCache,
    UnboundSubjectError,
    level_for,
    penalty,
    server_of,
    subjects_for,
    with_reputation,
)
from airlock.types import Action, Category, Finding, Segment, Severity, Source

EVIL = "mcp__evil__fetch"
EVIL_2 = "mcp__evil__search"
GOOD = "mcp__github__create_issue"
FIXED_CLOCK = 1_700_000_000.0


def make_finding(
    tool: str | None = EVIL,
    severity: Severity = Severity.HIGH,
    source: Source = Source.TOOL_RESULT,
    rule: str = "FAKE-RULE",
    evidence: str = "e1",
    category: Category = Category.PROMPT_INJECTION,
) -> Finding:
    return Finding(
        rule_id=rule, category=category, severity=severity, source=source,
        path=("messages", 2, "content", 0, "content"), start=0, end=1,
        evidence=evidence, message="synthetic", tool_name=tool,
    )


def make_decision(pairs=(), tools=(), trace="trace-1") -> Decision:
    findings = [f for f, _ in pairs]
    actions = [a for _, a in pairs]
    return Decision(
        action=max(actions, default=Action.ALLOW), findings=findings, actions=actions,
        body={"tools": [{"name": n} for n in tools]}, trace_id=trace, elapsed_ms=0.0,
    )


def tool_def(name: str) -> dict:
    return {
        "name": name,
        "description": "Returns a short text.",
        "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}},
    }


def plain_body(*tools: str) -> dict:
    return {
        "model": "test",
        "tools": [tool_def(n) for n in tools],
        "messages": [{"role": "user", "content": "hello"}],
    }


def body_with_result(tool: str, text: str, tools: tuple[str, ...]) -> dict:
    return {
        "model": "test",
        "tools": [tool_def(n) for n in tools],
        "messages": [
            {"role": "user", "content": "Look this up."},
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "tu_1", "name": tool, "input": {"query": "weather"}},
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "tu_1", "content": text},
            ]},
        ],
    }


def rep_findings(decision: Decision) -> list[Finding]:
    return [f for f in decision.findings if f.rule_id == RULE_ID]


# --- subjects -------------------------------------------------------------------


def test_mcp_tool_maps_to_server():
    assert server_of(GOOD) == "github"
    assert subjects_for(GOOD) == [f"tool:{GOOD}", "server:github"]


def test_plain_names_have_no_server():
    assert server_of("read_file") is None
    assert server_of("mcp__onlyserver") is None
    assert server_of(None) is None
    assert subjects_for("read_file") == ["tool:read_file"]


# --- scoring --------------------------------------------------------------------


def test_unknown_subject_has_prior_and_neutral_level():
    book = ReputationBook()
    assert book.score("tool:anything") == 60
    assert book.level("tool:anything") == "neutral"


def test_level_thresholds():
    assert [level_for(s) for s in (100, 75, 74, 40, 39, 20, 19, 0)] == [
        "trusted", "trusted", "neutral", "neutral",
        "suspicious", "suspicious", "blocked", "blocked",
    ]


def test_penalty_grows_with_action():
    scores = {}
    for action in (Action.WARN, Action.REDACT, Action.BLOCK):
        book = ReputationBook()
        book.observe(make_decision([(make_finding(severity=Severity.MEDIUM), action)]))
        scores[action] = book.score(f"tool:{EVIL}")
    assert scores[Action.WARN] == 57
    assert scores[Action.REDACT] == 52
    assert scores[Action.BLOCK] == 40
    assert penalty(Action.ALLOW, Severity.CRITICAL) == 0


def test_penalty_scales_with_severity():
    scores = []
    for severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL):
        book = ReputationBook(prior=100)
        book.observe(make_decision([(make_finding(severity=severity), Action.REDACT)]))
        scores.append(book.score(f"tool:{EVIL}"))
    assert scores == [96, 92, 88, 84]


def test_penalty_hits_tool_and_server_and_records_incident():
    book = ReputationBook()
    changed = book.observe(make_decision([(make_finding(), Action.REDACT)], trace="tr-9"))
    assert changed == {f"tool:{EVIL}": 48, "server:evil": 48}
    incident = book.incidents("server:evil")[0]
    assert incident["trace_id"] == "tr-9"
    assert incident["rule_id"] == "FAKE-RULE"
    assert incident["category"] == "prompt_injection"
    assert incident["action"] == "REDACT"


def test_tool_definition_and_tool_use_findings_count():
    book = ReputationBook()
    book.observe(make_decision([
        (make_finding(source=Source.TOOL_DEFINITION, evidence="a"), Action.WARN),
        (make_finding(source=Source.TOOL_USE, evidence="b"), Action.WARN),
    ]))
    assert book.score(f"tool:{EVIL}") == 51  # two WARN x HIGH (4.5 each)


def test_user_findings_and_own_flags_do_not_penalize():
    book = ReputationBook()
    book.observe(make_decision([
        (make_finding(tool=None, source=Source.USER), Action.WARN),
        (make_finding(rule=RULE_ID, category=Category.REPUTATION), Action.WARN),
    ]))
    assert book.snapshot() == {}


def test_same_incident_resent_with_history_counts_once():
    book = ReputationBook()
    pair = (make_finding(evidence="same"), Action.REDACT)
    book.observe(make_decision([pair], trace="t1"))
    book.observe(make_decision([pair], trace="t2"))
    assert book.score(f"tool:{EVIL}") == 48
    assert len(book.incidents(f"tool:{EVIL}")) == 1


def test_recovery_is_capped_at_baseline_and_once_per_request():
    book = ReputationBook()
    book.observe(make_decision([(make_finding(severity=Severity.MEDIUM), Action.WARN)]))
    assert book.score("server:evil") == 57
    # Two tools of the same server in one request: the server recovers once.
    book.observe(make_decision(tools=(EVIL, EVIL_2)))
    assert book.score("server:evil") == 58
    for _ in range(10):
        book.observe(make_decision(tools=(EVIL,)))
    assert book.score(f"tool:{EVIL}") == 60
    assert book.score("server:evil") == 60
    # Unknown clean tools are not added to the book.
    assert "tool:read_file" not in book.snapshot()


def test_blocked_subject_does_not_recover_until_reset():
    book = ReputationBook()
    book.seed([{"subject": f"tool:{EVIL}", "score": 10}])
    book.observe(make_decision(tools=(EVIL,)))
    assert book.score(f"tool:{EVIL}") == 10
    assert book.reset(f"tool:{EVIL}", score=50) == 50
    assert book.level(f"tool:{EVIL}") == "neutral"


def test_incident_history_is_bounded():
    book = ReputationBook(max_incidents=3)
    for k in range(6):
        book.observe(make_decision([(make_finding(evidence=f"e{k}"), Action.WARN)], trace=f"t{k}"))
    kept = book.incidents(f"tool:{EVIL}")
    assert [i["trace_id"] for i in kept] == ["t3", "t4", "t5"]
    assert book.snapshot()[f"tool:{EVIL}"]["incidents"] == 6


def test_concurrent_observe_is_consistent():
    book = ReputationBook(prior=100)

    def worker(n: int) -> None:
        for k in range(5):
            finding = make_finding(severity=Severity.MEDIUM, evidence=f"w{n}-{k}")
            book.observe(make_decision([(finding, Action.WARN)]))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert book.score(f"tool:{EVIL}") == 40  # 20 incidents x 3 points


# --- persistence and seeding ------------------------------------------------------


def test_persistence_round_trip(tmp_path):
    path = str(tmp_path / "rep" / "reputation.json")
    book = ReputationBook(path=path)
    book.bind("server:evil", 42, registry="eip155:1:0xRegistry")
    book.observe(make_decision([(make_finding(), Action.BLOCK)], trace="t-persist"))
    again = ReputationBook(path=path)
    assert again.score("server:evil") == book.score("server:evil") == 30
    assert again.incidents("server:evil")[0]["trace_id"] == "t-persist"
    assert again.snapshot()["server:evil"]["agent_id"] == 42
    assert again.snapshot()["server:evil"]["registry"] == "eip155:1:0xRegistry"


def test_corrupt_file_is_ignored_and_rewritten(tmp_path):
    path = tmp_path / "reputation.json"
    path.write_text("{not json", encoding="utf-8")
    book = ReputationBook(path=str(path))
    assert book.score(f"tool:{EVIL}") == 60
    book.observe(make_decision([(make_finding(), Action.WARN)]))
    data = json.loads(path.read_text(encoding="utf-8"))
    assert f"tool:{EVIL}" in data["subjects"]


def test_seed_sets_score_baseline_and_binding():
    book = ReputationBook()
    applied = book.seed([
        {"subject": "server:github", "score": 82, "agent_id": 123, "source": "erc8004"},
        {"subject": "nonsense", "score": 50},
        {"subject": "tool:x", "score": "high"},
        {"subject": "tool:y", "score": float("nan")},
    ])
    assert applied == 1
    snap = book.snapshot()["server:github"]
    assert snap["score"] == 82 and snap["level"] == "trusted"
    assert snap["baseline"] == 82 and snap["agent_id"] == 123 and snap["source"] == "erc8004"


# --- detector in the real Airlock ---------------------------------------------------


def make_airlock(book: ReputationBook) -> Airlock:
    return Airlock(detectors=(*TEXT_DETECTORS, book.detector()), cache=ReputationCache(book))


def test_detector_ignores_neutral_and_trusted_tools():
    book = ReputationBook()
    book.seed([{"subject": f"tool:{GOOD}", "score": 90}])
    decision = make_airlock(book).inspect(plain_body(EVIL, GOOD))
    assert rep_findings(decision) == []
    assert decision.action is Action.ALLOW


def test_suspicious_tool_is_flagged_with_warn():
    book = ReputationBook()
    book.seed([{"subject": f"tool:{EVIL}", "score": 30}])
    decision = make_airlock(book).inspect(plain_body(EVIL, "read_file"))
    (finding,) = rep_findings(decision)
    assert finding.severity is Severity.MEDIUM
    assert finding.category is Category.REPUTATION
    assert finding.path == ("tools", 0)
    assert decision.action is Action.WARN
    assert [t["name"] for t in decision.body["tools"]] == [EVIL, "read_file"]


def test_blocked_tool_is_quarantined_by_the_sanitizer():
    book = ReputationBook()
    book.seed([{"subject": f"tool:{EVIL}", "score": 10}])
    body = plain_body(EVIL, "read_file")
    decision = make_airlock(book).inspect(body)
    (finding,) = rep_findings(decision)
    assert finding.severity is Severity.HIGH and (finding.start, finding.end) == (0, 0)
    assert decision.action is Action.REDACT
    assert decision.quarantined_tools == [EVIL]
    assert [t["name"] for t in decision.body["tools"]] == ["read_file"]
    assert [t["name"] for t in body["tools"]] == [EVIL, "read_file"]  # input untouched


def test_blocked_server_quarantines_all_its_tools():
    book = ReputationBook()
    book.seed([{"subject": "server:evil", "score": 5}])
    decision = make_airlock(book).inspect(plain_body(EVIL, GOOD, EVIL_2))
    assert decision.quarantined_tools == [EVIL, EVIL_2]
    assert [t["name"] for t in decision.body["tools"]] == [GOOD]


def test_tool_result_from_suspicious_tool_is_flagged():
    book = ReputationBook()
    book.seed([{"subject": f"tool:{EVIL}", "score": 30}])
    text = "Sunny, 21 degrees."
    decision = make_airlock(book).inspect(body_with_result(EVIL, text, (EVIL,)))
    result_flags = [f for f in rep_findings(decision) if f.source is Source.TOOL_RESULT]
    (finding,) = result_flags
    assert finding.path == ("messages", 2, "content", 0, "content")
    assert (finding.start, finding.end) == (0, len(text))
    assert "30/100" in finding.message
    assert decision.action is Action.WARN


def test_detector_ignores_other_segments():
    book = ReputationBook()
    book.seed([{"subject": f"tool:{EVIL}", "score": 0}])
    detect = book.detector()
    assert detect(Segment(Source.USER, "hello", ("messages", 0, "content"))) == []
    desc = Segment(Source.TOOL_DEFINITION, "Returns text.", ("tools", 0, "description"), EVIL)
    assert detect(desc) == []


# --- ERC-8004 ---------------------------------------------------------------------


def test_erc8004_feedback_shape_and_hash():
    book = ReputationBook(clock=lambda: FIXED_CLOCK)
    book.bind("server:evil", 7)
    book.observe(make_decision([
        (make_finding(evidence="a"), Action.WARN),
        (make_finding(evidence="b", category=Category.EXFILTRATION), Action.WARN),
        (make_finding(evidence="c", category=Category.EXFILTRATION), Action.WARN),
    ], trace="tr-x"))
    fb = book.erc8004_feedback("server:evil")
    assert set(fb) == {"agentId", "score", "tag1", "tag2", "fileuri", "filehash", "evidence"}
    assert fb["agentId"] == 7 and fb["score"] == book.score("server:evil")
    assert 0 <= fb["score"] <= 100 and isinstance(fb["score"], int)
    assert (fb["tag1"], fb["tag2"]) == ("airlock", "exfiltration")
    assert fb["fileuri"] == "airlock://audit/server:evil"
    ev = fb["evidence"]
    assert ev["incidents"]["by_category"] == {"exfiltration": 2, "prompt_injection": 1}
    assert ev["incidents"]["by_action"] == {"WARN": 3}
    assert ev["last_trace_ids"] == ["tr-x"]
    assert ev["generated_at"] == "2023-11-14T22:13:20Z"
    canonical = json.dumps(ev, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert fb["filehash"] == hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def test_erc8004_feedback_is_deterministic_and_takes_a_uri():
    book = ReputationBook(clock=lambda: FIXED_CLOCK)
    book.seed([{"subject": "server:github", "score": 82, "agent_id": 123}])
    first = book.erc8004_feedback("server:github", fileuri="ipfs://evidence")
    second = book.erc8004_feedback("server:github", fileuri="ipfs://evidence")
    assert first == second
    assert first["fileuri"] == "ipfs://evidence"
    assert first["tag2"] == "clean"


def test_unbound_subject_raises():
    book = ReputationBook()
    book.observe(make_decision([(make_finding(), Action.WARN)]))
    with pytest.raises(UnboundSubjectError):
        book.erc8004_feedback(f"tool:{EVIL}")
    with pytest.raises(LookupError):
        book.erc8004_feedback("server:never-seen")
    with pytest.raises(ValueError):
        book.bind("github", 1)
    with pytest.raises(ValueError):
        book.bind("server:github", -1)


def test_export_writes_bound_subjects_only(tmp_path):
    book = ReputationBook(clock=lambda: FIXED_CLOCK)
    book.bind("server:evil", 9)
    book.observe(make_decision([(make_finding(), Action.REDACT)]))
    out = tmp_path / "feedback.json"
    assert book.export(str(out)) == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["standard"] == "ERC-8004"
    assert [fb["agentId"] for fb in doc["feedback"]] == [9]
    assert doc["feedback"][0]["evidence"]["subject"] == "server:evil"


# --- end to end ---------------------------------------------------------------------


def fake_detector(segment: Segment) -> list[Finding]:
    """Flags every result of the EVIL tool as a synthetic HIGH finding (REDACT)."""
    if segment.source is Source.TOOL_RESULT and segment.tool_name == EVIL:
        return [Finding(
            "FAKE-BAD", Category.PROMPT_INJECTION, Severity.HIGH, Source.TOOL_RESULT,
            segment.path, 0, len(segment.text), segment.text, "synthetic", segment.tool_name,
        )]
    return []


def test_reputation_airlock_learns_and_quarantines_automatically():
    book = ReputationBook()
    guard = ReputationAirlock(book, detectors=(*TEXT_DETECTORS, fake_detector))
    tools = (EVIL, "read_file")
    levels = []
    saw_warning_stage = False
    for k in range(10):
        decision = guard.inspect(body_with_result(EVIL, f"synthetic result {k}", tools))
        assert decision.quarantined_tools == []
        saw_warning_stage |= any(f.severity is Severity.MEDIUM for f in rep_findings(decision))
        levels.append(book.level(f"tool:{EVIL}"))
        if levels[-1] == "blocked":
            break
    assert levels[-1] == "blocked"
    assert "suspicious" in levels and saw_warning_stage
    assert book.level("server:evil") == "blocked"
    assert book.level("tool:read_file") == "neutral"

    decision = guard.inspect(plain_body(*tools))
    assert decision.action is Action.REDACT
    assert decision.quarantined_tools == [EVIL]
    assert [t["name"] for t in decision.body["tools"]] == ["read_file"]


def test_reputation_cache_never_replays_stale_scores():
    book = ReputationBook()
    guard = ReputationAirlock(book)
    body = plain_body(EVIL, "read_file")
    assert guard.inspect(body).action is Action.ALLOW
    book.seed([{"subject": f"tool:{EVIL}", "score": 10}])
    decision = guard.inspect(body)
    assert decision.quarantined_tools == [EVIL]
    assert len(guard.cache) > 0  # the stateless detectors are still cached


def test_with_reputation_keeps_the_harness_policy():
    # Proxy default: only mcp__* tool definitions are third party, so a blocked
    # MCP tool is quarantined while a blocked harness tool is only flagged.
    book = ReputationBook()
    book.seed([{"subject": "server:evil", "score": 5}, {"subject": "tool:read_file", "score": 5}])
    guard = with_reputation(Airlock(policy=HARNESS_POLICY), book)
    assert guard.policy is HARNESS_POLICY
    decision = guard.inspect(plain_body(EVIL, "read_file"))
    assert decision.quarantined_tools == [EVIL]
    flags = {f.tool_name: a for f, a in zip(decision.findings, decision.actions, strict=True)}
    assert flags == {EVIL: Action.REDACT, "read_file": Action.WARN}


def test_reputation_airlock_delegates_to_inner_airlock():
    guard = ReputationAirlock()
    assert guard.policy is guard.airlock.policy
    assert isinstance(guard.cache, ReputationCache)
    assert guard.inspect(plain_body("read_file"), trace_id="abc").trace_id == "abc"
