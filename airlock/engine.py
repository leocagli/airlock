"""Airlock.inspect(): the one call the proxy, the CLI and the red team use."""

from __future__ import annotations

import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from .detectors import TEXT_DETECTORS
from .policy import DEFAULT_POLICY, Policy, decide
from .sanitize import sanitize
from .segments import extract_segments
from .tools import FingerprintStore, check_tools
from .types import Action, Category, Finding, Path, Segment, Severity, Source, clip

Detector = Callable[[Segment], list[Finding]]

FAIL_CLOSED_RULE = "AIR-FAIL-CLOSED"
_PART_SOURCE = {"system": Source.SYSTEM, "tools": Source.TOOL_DEFINITION}


def fail_closed_finding(errors: list[tuple[Path, str]]) -> Finding:
    """One BLOCK finding for content the engine could not parse, scan or rewrite.

    A firewall that skips what it cannot read forwards it uninspected, so any
    such error blocks the whole request. Evidence names paths, never content.
    """
    path, _ = errors[0]
    where = "; ".join(f"{'/'.join(map(str, p)) or 'body'}: {why}" for p, why in errors[:3])
    return Finding(
        rule_id=FAIL_CLOSED_RULE,
        category=Category.PROMPT_INJECTION,
        severity=Severity.CRITICAL,
        source=_PART_SOURCE.get(str(path[0]) if path else "", Source.USER),
        path=tuple(path),
        start=0,
        end=0,
        evidence=clip(where),
        message=f"{len(errors)} part(s) of the request could not be inspected; failing closed",
    )


@dataclass
class Decision:
    action: Action
    findings: list[Finding]
    actions: list[Action]
    body: dict[str, Any]
    trace_id: str
    elapsed_ms: float
    quarantined_tools: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.action is Action.BLOCK

    def top(self) -> Finding | None:
        """The finding that decided the action (strictest, then most severe)."""
        if not self.findings:
            return None
        pairs = sorted(
            zip(self.findings, self.actions, strict=True),
            key=lambda p: (p[1], p[0].severity),
            reverse=True,
        )
        return pairs[0][0]

    def summary(self) -> str:
        if not self.findings:
            return f"{self.action.name}: no findings"
        rules = sorted({f.rule_id for f in self.findings})
        return f"{self.action.name}: {len(self.findings)} finding(s) [{', '.join(rules)}]"

    def to_record(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "action": self.action.name,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "quarantined_tools": self.quarantined_tools,
            "findings": [
                {**f.to_record(), "action": a.name}
                for f, a in zip(self.findings, self.actions, strict=True)
            ],
        }


class SegmentCache:
    """Bounded LRU memo of text-detector findings, keyed by the whole Segment.

    Agents re-send the full history on every turn and text detectors are
    stateless and deterministic, so a segment seen before (same text, source,
    path and tool) gets the same findings without being scanned again. Tool
    checks are not cached: rug-pull pins are state.
    """

    def __init__(self, max_entries: int = 4096, max_chars: int = 32_000_000) -> None:
        self.max_entries = max_entries
        self.max_chars = max_chars
        self._data: OrderedDict[Segment, tuple[Finding, ...]] = OrderedDict()
        self._chars = 0
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._data)

    def get(self, segment: Segment) -> tuple[Finding, ...] | None:
        with self._lock:
            hit = self._data.get(segment)
            if hit is not None:
                self._data.move_to_end(segment)
            return hit

    def put(self, segment: Segment, findings: Iterable[Finding]) -> None:
        size = len(segment.text)
        if self.max_entries <= 0 or size > self.max_chars:
            return
        with self._lock:
            if segment in self._data:
                return
            self._data[segment] = tuple(findings)
            self._chars += size
            while len(self._data) > self.max_entries or self._chars > self.max_chars:
                old, _ = self._data.popitem(last=False)
                self._chars -= len(old.text)


def _dedupe(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.path, f.start, f.end)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


class Airlock:
    def __init__(
        self,
        policy: Policy = DEFAULT_POLICY,
        fingerprints: FingerprintStore | None = None,
        detectors: Iterable[Detector] = TEXT_DETECTORS,
        cache: SegmentCache | None = None,
    ) -> None:
        self.policy = policy
        self.fingerprints = fingerprints if fingerprints is not None else FingerprintStore()
        self.detectors = tuple(detectors)
        self.cache = cache if cache is not None else SegmentCache()

    def _scan(self, segment: Segment) -> tuple[Finding, ...]:
        cached = self.cache.get(segment)
        if cached is None:
            cached = tuple(f for detector in self.detectors for f in detector(segment))
            self.cache.put(segment, cached)
        return cached

    def inspect(self, body: dict[str, Any], trace_id: str | None = None) -> Decision:
        started = time.perf_counter()
        trace_id = trace_id or secrets.token_hex(8)

        findings: list[Finding] = []
        errors: list[tuple[Path, str]] = []
        for segment in extract_segments(body, errors=errors):
            findings.extend(self._scan(segment))
        findings.extend(check_tools(body.get("tools") or [], self.fingerprints, errors=errors))
        findings = _dedupe(findings)

        action, actions = decide(findings, self.policy)
        out_body = body
        quarantined: list[str] = []
        if action is Action.REDACT and not errors:
            to_fix = [f for f, a in zip(findings, actions, strict=True) if a is Action.REDACT]
            out_body, quarantined = sanitize(body, to_fix, errors=errors)
        if errors:
            # Fail closed: what could not be parsed, scanned or rewritten never ships.
            findings = [*findings, fail_closed_finding(errors)]
            actions = [*actions, Action.BLOCK]
            action, out_body, quarantined = Action.BLOCK, body, []

        return Decision(
            action=action,
            findings=findings,
            actions=actions,
            body=out_body,
            trace_id=trace_id,
            elapsed_ms=(time.perf_counter() - started) * 1000,
            quarantined_tools=quarantined,
        )
