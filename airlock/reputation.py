"""Reputation for tools and MCP servers, shaped for ERC-8004 (Trustless Agents).

Findings are per request: a tool that returned an attack an hour ago looks
clean on its next call. ReputationBook is the memory across requests. Every
finding attributed to a tool (tool results, tool definitions, tool calls)
lowers a 0..100 score for that tool and for the MCP server that hosts it, and
clean appearances slowly restore it. The score feeds back into the firewall
as a text detector, so the existing policy and sanitizer act on it:

- suspicious tool or server: its definition and its results get a
  REP-LOW-SCORE finding with severity MEDIUM (WARN under the default policy);
- blocked tool or server: its definition gets a HIGH finding on tools[i],
  which the default policy turns into REDACT and the sanitizer into a
  quarantine (the tool is removed from the forwarded request).

Scoring model (see docs/REPUTATION.md):
- unknown subjects start at the prior (60, "neutral");
- penalty = ACTION_PENALTY[action] * SEVERITY_WEIGHT[severity], applied to the
  tool subject and to its server subject;
- REP-* findings never penalize: a flag raised because of a low score is a
  consequence, not new evidence, so there is no feedback loop;
- an incident is counted once: agents re-send the whole history on every turn,
  so identical findings are deduplicated (bounded, in memory);
- recovery: +1 per request in which a tool appears with no findings, capped at
  the subject's baseline (its seeded score, else the prior). Trust above the
  prior can only come from outside evidence (seed). A blocked subject does not
  recover on its own: seed() or reset() lifts it, so an attacker cannot simply
  wait it out.

ERC-8004 mapping, in terms of the standard's concepts (not a contract ABI):
- Identity: bind() links a subject to an ERC-8004 agentId (and optionally the
  identity registry it lives in).
- Reputation in: seed() loads scores summarized from a Reputation Registry
  indexer.
- Reputation out: erc8004_feedback() builds a feedback entry (agentId, score
  0..100, two tags, an off-chain evidence URI and the hash of that evidence).

Standard library only. Thread-safe. Persisted atomically when a path is set.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import math
import os
import tempfile
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

from .detectors import TEXT_DETECTORS
from .engine import Airlock, Decision, SegmentCache
from .types import Action, Category, Finding, Segment, Severity, Source

RULE_ID = "REP-LOW-SCORE"
RULE_PREFIX = "REP-"

# Levels: score >= TRUSTED_AT trusted, >= NEUTRAL_AT neutral,
# >= SUSPICIOUS_AT suspicious, below that blocked.
TRUSTED_AT = 75
NEUTRAL_AT = 40
SUSPICIOUS_AT = 20
LEVELS = ("trusted", "neutral", "suspicious", "blocked")

ACTION_PENALTY: dict[Action, float] = {
    Action.WARN: 3.0,
    Action.REDACT: 8.0,
    Action.BLOCK: 20.0,
}
SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.LOW: 0.5,
    Severity.MEDIUM: 1.0,
    Severity.HIGH: 1.5,
    Severity.CRITICAL: 2.0,
}
RECOVERY = 1.0
OBSERVED_SOURCES = frozenset({Source.TOOL_RESULT, Source.TOOL_DEFINITION, Source.TOOL_USE})

_SEEN_MAX = 8192
_EVIDENCE_TRACE_IDS = 10

Detector = Callable[[Segment], list[Finding]]
Clock = Callable[[], float]


class UnboundSubjectError(LookupError):
    """erc8004_feedback() needs an agentId: call bind() first."""


# --- subjects -------------------------------------------------------------------


def server_of(tool_name: str | None) -> str | None:
    """'mcp__github__create_issue' -> 'github' (Claude Code naming); plain names -> None."""
    if not isinstance(tool_name, str) or not tool_name.startswith("mcp__"):
        return None
    server, sep, tool = tool_name[len("mcp__"):].partition("__")
    return server if sep and server and tool else None


def subjects_for(tool_name: str) -> list[str]:
    """Reputation keys touched by a tool: 'tool:<name>' and, for MCP tools, 'server:<server>'."""
    subjects = [f"tool:{tool_name}"]
    server = server_of(tool_name)
    if server:
        subjects.append(f"server:{server}")
    return subjects


def penalty(action: Action, severity: Severity) -> float:
    """Points removed for one incident. ALLOW costs nothing."""
    return ACTION_PENALTY.get(action, 0.0) * SEVERITY_WEIGHT.get(severity, 1.0)


def level_for(score: float) -> str:
    if score >= TRUSTED_AT:
        return "trusted"
    if score >= NEUTRAL_AT:
        return "neutral"
    if score >= SUSPICIOUS_AT:
        return "suspicious"
    return "blocked"


def _valid_subject(subject: object) -> bool:
    if not isinstance(subject, str):
        return False
    kind, sep, name = subject.partition(":")
    return bool(sep and name) and kind in ("tool", "server")


def _valid_agent_id(agent_id: object) -> bool:
    return isinstance(agent_id, int) and not isinstance(agent_id, bool) and agent_id >= 0


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return max(0.0, min(100.0, value)) if math.isfinite(value) else None


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical(doc: Any) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _atomic_write_json(path: str, data: Any, prefix: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _tool_names(decision: Decision) -> list[str]:
    """Tools offered in the request: the forwarded tools[] plus quarantined ones."""
    names: list[str] = []
    body = getattr(decision, "body", None)
    tools = body.get("tools") if isinstance(body, dict) else None
    if isinstance(tools, list):
        for tool in tools:
            name = tool.get("name") if isinstance(tool, dict) else None
            if isinstance(name, str) and name:
                names.append(name)
    for name in getattr(decision, "quarantined_tools", None) or []:
        if isinstance(name, str) and name:
            names.append(name)
    return names


def _incident_key(finding: Finding) -> str:
    raw = [
        finding.rule_id,
        getattr(finding.source, "value", str(finding.source)),
        list(finding.path),
        finding.start,
        finding.end,
        finding.evidence,
        finding.tool_name,
    ]
    return hashlib.sha256(json.dumps(raw, default=str).encode("utf-8")).hexdigest()


# --- the book -------------------------------------------------------------------


class ReputationBook:
    """Scores 0..100 for 'tool:<name>' and 'server:<server>' subjects."""

    def __init__(
        self,
        path: str | None = None,
        prior: int = 60,
        max_incidents: int = 50,
        clock: Clock = time.time,
    ) -> None:
        start = _number(prior)
        if start is None:
            raise ValueError("prior must be a number between 0 and 100")
        self.path = path
        self.prior = start
        self.max_incidents = max(1, int(max_incidents))
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: dict[str, dict[str, Any]] = {}
        self._seen: OrderedDict[str, None] = OrderedDict()
        if path:
            self._load()

    # -- storage (callers hold the lock) --

    def _new_entry(self, baseline: float) -> dict[str, Any]:
        return {
            "score": baseline,
            "baseline": baseline,
            "agent_id": None,
            "registry": None,
            "source": "local",
            "incidents": deque(maxlen=self.max_incidents),
            "by_category": {},
            "by_action": {},
        }

    def _entry(self, subject: str) -> dict[str, Any]:
        entry = self._entries.get(subject)
        if entry is None:
            entry = self._entries[subject] = self._new_entry(self.prior)
        return entry

    def _load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as fh:  # type: ignore[arg-type]
                data = json.load(fh)
        except (OSError, ValueError):
            return  # missing or corrupt: start empty, the next save rewrites it
        subjects = data.get("subjects") if isinstance(data, dict) else None
        if not isinstance(subjects, dict):
            return
        for subject, raw in subjects.items():
            if not _valid_subject(subject) or not isinstance(raw, dict):
                continue
            baseline = _number(raw.get("baseline"))
            entry = self._new_entry(self.prior if baseline is None else baseline)
            score = _number(raw.get("score"))
            entry["score"] = entry["baseline"] if score is None else score
            if _valid_agent_id(raw.get("agent_id")):
                entry["agent_id"] = raw["agent_id"]
            if isinstance(raw.get("registry"), str):
                entry["registry"] = raw["registry"]
            if isinstance(raw.get("source"), str):
                entry["source"] = raw["source"]
            incidents = raw.get("incidents")
            if isinstance(incidents, list):
                entry["incidents"].extend(i for i in incidents if isinstance(i, dict))
            for key in ("by_category", "by_action"):
                counts = raw.get(key)
                if isinstance(counts, dict):
                    entry[key] = {
                        str(k): v for k, v in counts.items()
                        if isinstance(v, int) and not isinstance(v, bool)
                    }
            self._entries[subject] = entry

    def _save(self) -> None:
        if not self.path:
            return
        subjects = {
            subject: {**entry, "incidents": list(entry["incidents"])}
            for subject, entry in self._entries.items()
        }
        data = {"version": 1, "prior": self.prior, "subjects": subjects}
        _atomic_write_json(self.path, data, ".reputation-")

    def _first_time(self, finding: Finding) -> bool:
        key = _incident_key(finding)
        if key in self._seen:
            self._seen.move_to_end(key)
            return False
        self._seen[key] = None
        while len(self._seen) > _SEEN_MAX:
            self._seen.popitem(last=False)
        return True

    def _score_locked(self, subject: str) -> int:
        entry = self._entries.get(subject)
        return int(round(entry["score"] if entry is not None else self.prior))

    # -- reading --

    def score(self, subject: str) -> int:
        with self._lock:
            return self._score_locked(subject)

    def level(self, subject: str) -> str:
        return level_for(self.score(subject))

    def worst(self, tool_name: str) -> tuple[str, int, str]:
        """(subject, score, level) of the lowest scoring subject of a tool (tool or server)."""
        with self._lock:
            scored = [(self._score_locked(s), s) for s in subjects_for(tool_name)]
        value, subject = min(scored, key=lambda pair: pair[0])
        return subject, value, level_for(value)

    def incidents(self, subject: str) -> list[dict[str, Any]]:
        with self._lock:
            entry = self._entries.get(subject)
            return [dict(i) for i in entry["incidents"]] if entry else []

    def snapshot(self) -> dict[str, dict[str, Any]]:
        """Every known subject with its score, level, binding and incident count."""
        with self._lock:
            out = {}
            for subject, entry in sorted(self._entries.items()):
                value = self._score_locked(subject)
                out[subject] = {
                    "score": value,
                    "level": level_for(value),
                    "baseline": int(round(entry["baseline"])),
                    "agent_id": entry["agent_id"],
                    "registry": entry["registry"],
                    "source": entry["source"],
                    "incidents": sum(entry["by_action"].values()),
                }
            return out

    # -- writing --

    def observe(self, decision: Decision) -> dict[str, int]:
        """Learn from one Airlock decision. Returns {subject: new score} for changed subjects."""
        findings = list(getattr(decision, "findings", None) or [])
        actions = list(getattr(decision, "actions", None) or [])
        trace_id = str(getattr(decision, "trace_id", "") or "")
        now = self._clock()
        touched: set[str] = set()
        changed: set[str] = set()
        with self._lock:
            for finding, action in zip(findings, actions, strict=False):
                if finding.rule_id.startswith(RULE_PREFIX):
                    continue  # our own flag: consequence, not evidence
                if finding.source not in OBSERVED_SOURCES or not finding.tool_name:
                    continue
                subjects = subjects_for(finding.tool_name)
                touched.update(subjects)
                amount = penalty(action, finding.severity)
                if amount <= 0 or not self._first_time(finding):
                    continue
                category = getattr(finding.category, "value", str(finding.category))
                incident = {
                    "ts": round(now, 3),
                    "trace_id": trace_id,
                    "rule_id": finding.rule_id,
                    "category": category,
                    "action": action.name,
                    "severity": finding.severity.name,
                    "delta": -amount,
                }
                for subject in subjects:
                    entry = self._entry(subject)
                    entry["score"] = max(0.0, entry["score"] - amount)
                    entry["incidents"].append(dict(incident))
                    by_cat, by_act = entry["by_category"], entry["by_action"]
                    by_cat[category] = by_cat.get(category, 0) + 1
                    by_act[action.name] = by_act.get(action.name, 0) + 1
                    changed.add(subject)
            for name in _tool_names(decision):
                for subject in subjects_for(name):
                    if subject in touched:
                        continue
                    touched.add(subject)  # at most one recovery per subject per request
                    entry = self._entries.get(subject)
                    if entry is None or level_for(self._score_locked(subject)) == "blocked":
                        continue
                    if entry["score"] < entry["baseline"]:
                        entry["score"] = min(entry["baseline"], entry["score"] + RECOVERY)
                        changed.add(subject)
            if changed:
                self._save()
            return {subject: self._score_locked(subject) for subject in sorted(changed)}

    def seed(self, entries: Iterable[Mapping[str, Any]]) -> int:
        """Preload external scores, e.g. summaries from an ERC-8004 Reputation Registry indexer.

        Each entry: {"subject": "server:github", "score": 82, "agent_id": 123,
        "registry": "...", "source": "erc8004"}; agent_id, registry and source
        are optional. The seeded score also becomes the subject's baseline (the
        ceiling for local recovery). Invalid entries are skipped. Returns the
        number of entries applied.
        """
        applied = 0
        with self._lock:
            for item in entries or []:
                if not isinstance(item, Mapping):
                    continue
                subject, value = item.get("subject"), _number(item.get("score"))
                if not _valid_subject(subject) or value is None:
                    continue
                entry = self._entry(subject)
                entry["score"] = entry["baseline"] = value
                entry["source"] = str(item.get("source") or "seed")
                if _valid_agent_id(item.get("agent_id")):
                    entry["agent_id"] = item["agent_id"]
                    if isinstance(item.get("registry"), str):
                        entry["registry"] = item["registry"]
                applied += 1
            if applied:
                self._save()
        return applied

    def bind(self, subject: str, agent_id: int, registry: str | None = None) -> None:
        """Link a subject to its ERC-8004 agentId (Identity Registry token id)."""
        if not _valid_subject(subject):
            raise ValueError(f"subject must be 'tool:<name>' or 'server:<name>', got {subject!r}")
        if not _valid_agent_id(agent_id):
            raise ValueError(f"agent_id must be a non-negative int, got {agent_id!r}")
        with self._lock:
            entry = self._entry(subject)
            entry["agent_id"] = agent_id
            entry["registry"] = registry if isinstance(registry, str) else None
            self._save()

    def reset(self, subject: str, score: float | None = None) -> int:
        """Operator override: set a subject back to its baseline (or to `score`)."""
        value = None if score is None else _number(score)
        if score is not None and value is None:
            raise ValueError("score must be a number between 0 and 100")
        with self._lock:
            entry = self._entry(subject)
            entry["score"] = entry["baseline"] if value is None else value
            self._save()
            return self._score_locked(subject)

    # -- firewall integration --

    def _detect(self, segment: Segment) -> list[Finding]:
        name = segment.tool_name
        if not name:
            return []
        path = segment.path
        if segment.source is Source.TOOL_DEFINITION:
            if len(path) != 3 or path[0] != "tools" or path[2] != "name":
                return []
            if not isinstance(path[1], int):
                return []
            subject, value, level = self.worst(name)
            if level not in ("suspicious", "blocked"):
                return []
            blocked = level == "blocked"
            return [Finding(
                rule_id=RULE_ID,
                category=Category.REPUTATION,
                severity=Severity.HIGH if blocked else Severity.MEDIUM,
                source=Source.TOOL_DEFINITION,
                path=("tools", path[1]),
                start=0,
                end=0,
                evidence=f"{subject} score {value}/100",
                message=(
                    f"Reputation of {subject} is {value}/100 ({level}): "
                    + ("tool quarantined" if blocked else "tool flagged")
                ),
                tool_name=name,
            )]
        if segment.source is Source.TOOL_RESULT:
            subject, value, level = self.worst(name)
            if level not in ("suspicious", "blocked"):
                return []
            return [Finding(
                rule_id=RULE_ID,
                category=Category.REPUTATION,
                severity=Severity.MEDIUM,
                source=Source.TOOL_RESULT,
                path=path,
                start=0,
                end=len(segment.text),
                evidence=f"{subject} score {value}/100",
                message=f"Result from {subject} with reputation {value}/100 ({level})",
                tool_name=name,
            )]
        return []

    def detector(self) -> Detector:
        """Text detector for Airlock(detectors=(*TEXT_DETECTORS, book.detector())).

        Its findings depend on live scores, so pair it with ReputationCache(book)
        (ReputationAirlock does): the engine's default SegmentCache would replay
        stale findings for a tool definition it has already seen.
        """

        def detect(segment: Segment) -> list[Finding]:
            return self._detect(segment)

        detect.__name__ = "reputation_detect"
        return detect

    # -- ERC-8004 --

    def erc8004_feedback(self, subject: str, fileuri: str | None = None) -> dict[str, Any]:
        """A feedback entry for an ERC-8004 Reputation Registry, built from local evidence.

        Mapping to the standard's concepts: agentId (from bind()), a 0..100
        score, two tags (tag1 "airlock", tag2 the dominant incident category),
        and an off-chain evidence document referenced by URI plus its sha256
        hash, so anyone can check the document was not altered.

        Submitting it on-chain (the registry's feedback call, signed by the
        operator wallet) is intentionally out of scope: Airlock never holds
        keys. The exact on-chain field encoding (for example tags or the hash as
        bytes32) depends on the registry version deployed and belongs to the
        submitter.
        """
        with self._lock:
            entry = self._entries.get(subject)
            if entry is None or entry["agent_id"] is None:
                raise UnboundSubjectError(f"{subject} has no ERC-8004 agentId: call bind() first")
            value = self._score_locked(subject)
            by_category = dict(sorted(entry["by_category"].items()))
            by_action = dict(sorted(entry["by_action"].items()))
            traces: list[str] = []
            for incident in reversed(entry["incidents"]):
                trace = incident.get("trace_id")
                if isinstance(trace, str) and trace and trace not in traces:
                    traces.append(trace)
                if len(traces) >= _EVIDENCE_TRACE_IDS:
                    break
            evidence = {
                "schema": "airlock.reputation.v1",
                "subject": subject,
                "agent_id": entry["agent_id"],
                "registry": entry["registry"],
                "score": value,
                "level": level_for(value),
                "incidents": {
                    "total": sum(by_action.values()),
                    "by_category": by_category,
                    "by_action": by_action,
                },
                "last_trace_ids": traces,
                "generated_at": _iso(self._clock()),
            }
            agent_id = entry["agent_id"]
        ranked = sorted(by_category.items(), key=lambda kv: (-kv[1], kv[0]))
        dominant = ranked[0][0] if ranked else "clean"
        return {
            "agentId": agent_id,
            "score": value,
            "tag1": "airlock",
            "tag2": dominant,
            "fileuri": fileuri or f"airlock://audit/{subject}",
            "filehash": hashlib.sha256(_canonical(evidence).encode("utf-8")).hexdigest(),
            "evidence": evidence,
        }

    def export(self, path: str) -> int:
        """Write the feedback entries of every bound subject to a JSON file. Returns the count."""
        with self._lock:
            bound = sorted(s for s, e in self._entries.items() if e["agent_id"] is not None)
        feedback = [self.erc8004_feedback(subject) for subject in bound]
        doc = {
            "version": 1,
            "standard": "ERC-8004",
            "generated_at": _iso(self._clock()),
            "feedback": feedback,
        }
        _atomic_write_json(path, doc, ".reputation-export-")
        return len(feedback)


# --- engine glue ----------------------------------------------------------------


class ReputationCache(SegmentCache):
    """SegmentCache that never memoizes reputation findings.

    The engine caches text-detector findings per Segment, which is right for
    stateless detectors and wrong for this one: a score can drop between two
    requests that carry the same tool definition. Stored entries exclude REP-*
    findings, and every cache hit recomputes them from the live book.
    """

    def __init__(self, book: ReputationBook, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._book = book

    def get(self, segment: Segment) -> tuple[Finding, ...] | None:
        hit = super().get(segment)
        if hit is None:
            return None
        kept = tuple(f for f in hit if not f.rule_id.startswith(RULE_PREFIX))
        return kept + tuple(self._book._detect(segment))

    def put(self, segment: Segment, findings: Iterable[Finding]) -> None:
        kept = [f for f in findings if not f.rule_id.startswith(RULE_PREFIX)]
        super().put(segment, kept)


class ReputationAirlock:
    """Airlock plus memory: inspect with the current reputation, then learn from the decision.

    ReputationAirlock(book, policy=..., fingerprints=..., detectors=...) builds
    an Airlock with the book's detector appended and a ReputationCache (unless
    a cache is passed). Other attributes are delegated to the inner Airlock.
    """

    def __init__(self, book: ReputationBook | None = None, **airlock_kwargs: Any) -> None:
        self.book = book if book is not None else ReputationBook()
        detectors = tuple(airlock_kwargs.pop("detectors", TEXT_DETECTORS))
        airlock_kwargs.setdefault("cache", ReputationCache(self.book))
        self.airlock = Airlock(detectors=(*detectors, self.book.detector()), **airlock_kwargs)

    def inspect(self, body: dict[str, Any], trace_id: str | None = None) -> Decision:
        decision = self.airlock.inspect(body, trace_id=trace_id)
        self.book.observe(self._third_party_view(decision))
        return decision

    def _third_party_view(self, decision: Decision) -> Decision:
        """Only third-party tools earn a reputation. Under a harness policy the harness's
        own tools (Bash, Edit, ...) are trusted like its system prompt, so their findings
        never move a score."""
        policy = getattr(self.airlock, "policy", None)
        if policy is None or not getattr(policy, "untrusted_tool_prefixes", ()):
            return decision
        keep = [
            (f, a)
            for f, a in zip(decision.findings, decision.actions, strict=True)
            if f.tool_name is None or policy.tool_is_untrusted(f.tool_name)
        ]
        return dataclasses.replace(
            decision, findings=[f for f, _ in keep], actions=[a for _, a in keep]
        )

    def __getattr__(self, name: str) -> Any:
        airlock = self.__dict__.get("airlock")
        if airlock is None:
            raise AttributeError(name)
        return getattr(airlock, name)


def with_reputation(airlock: Airlock, book: ReputationBook) -> ReputationAirlock:
    """Wrap an existing Airlock (its policy, pins and detectors) with a reputation book."""
    return ReputationAirlock(
        book,
        policy=airlock.policy,
        fingerprints=airlock.fingerprints,
        detectors=airlock.detectors,
    )
