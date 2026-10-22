"""Autonomous mode: Airlock stays safe and keeps the agent working with no human.

Plain Airlock is already fail-closed, but three situations used to need a
person: approving a tool whose definition changed (rug pull), removing a tool
that keeps returning attacks, and tightening the policy for a session that is
under active attack. AutonomousAirlock wraps an Airlock (composition, the
engine is untouched) and handles all three on its own:

1. Rug pull auto-remediation. A TOOL-RUGPULL finding triggers a re-scan of the
   NEW definition alone, with a fresh FingerprintStore, so it is judged on its
   own content. Clean: re-pin it (store.approve) and let the request through
   with the tool. Poisoned, unscannable or churning: keep it quarantined.
2. Tool reputation. Every TOOL_RESULT finding with action >= REDACT is an
   incident for that tool (deduplicated by tool_use_id, because agents re-send
   the whole history on every turn). N incidents inside a sliding window put
   the tool in quarantine: it is stripped from body["tools"] before
   inspection, for a cooldown that doubles for repeat offenders. Release is
   automatic.
3. Session escalation. Repeated BLOCKs for the same session (an API key hash
   or any caller key) switch that session to a stricter Policy for a cooldown,
   then relax automatically.

Every autonomous action becomes an event: kept in a bounded log (events()),
pushed to an optional notifier (webhook, Slack, audit chain), and reversible
through the manual override methods. Standard library only, deterministic
under an injected clock.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .policy import Policy
from .types import Action, Category, Finding, Severity, Source

RUGPULL_RULE = "TOOL-RUGPULL"
QUARANTINE_RULE = "AUTO-TOOL-QUARANTINE"
RUGPULL_QUARANTINE_RULE = "AUTO-RUGPULL-QUARANTINE"

Notifier = Callable[[dict[str, Any]], None]
Clock = Callable[[], float]


@dataclass(frozen=True)
class AutonomyConfig:
    # Rug pulls: auto-approve a changed tool only if its new definition alone
    # has no tool-definition or tool-poisoning finding at or above this level.
    auto_approve_rugpulls: bool = True
    rescan_block_at: Severity = Severity.MEDIUM
    # A tool that changes too often is itself a signal (rug-pull churn).
    max_auto_approvals: int = 3
    approval_window_s: float = 3600.0
    # Tool reputation.
    incident_threshold: int = 3
    incident_window_s: float = 600.0
    quarantine_cooldown_s: float = 1800.0
    max_quarantine_s: float = 86400.0
    # Session escalation.
    block_threshold: int = 3
    block_window_s: float = 300.0
    escalation_cooldown_s: float = 900.0
    # Memory bounds (the proxy is long-lived and the input is hostile).
    max_events: int = 1000
    max_tracked: int = 10000
    seen_incident_ttl_s: float = 86400.0


DEFAULT_CONFIG = AutonomyConfig()


def session_key_from_headers(headers: Mapping[str, str]) -> str | None:
    """Stable, non-reversible session key from request headers.

    An explicit x-airlock-session wins, then the API key or bearer token. The
    raw value is hashed here and never stored anywhere.
    """
    lowered = {str(k).lower(): v for k, v in headers.items()}
    for name in ("x-airlock-session", "x-api-key", "authorization"):
        value = lowered.get(name)
        if isinstance(value, str) and value.strip():
            return _hash(f"{name}:{value.strip()}")
    return None


def _metadata_session(body: Any) -> str | None:
    """Fallback session key: Messages API metadata.user_id (Claude Code sets it)."""
    meta = body.get("metadata") if isinstance(body, dict) else None
    user_id = meta.get("user_id") if isinstance(meta, dict) else None
    return user_id if isinstance(user_id, str) and user_id.strip() else None


def _hash(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:length]


def _default_store_factory() -> Any:
    from .tools import FingerprintStore

    return FingerprintStore(None)


def _local_fingerprint(tool: Any) -> str:
    canonical = json.dumps(tool, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()


def _is_rugpull(finding: Finding) -> bool:
    return finding.rule_id.startswith(RUGPULL_RULE) or finding.category is Category.RUG_PULL


def _is_poison(finding: Finding, threshold: Severity) -> bool:
    if finding.category is Category.RUG_PULL or finding.severity < threshold:
        return False
    return finding.source is Source.TOOL_DEFINITION or finding.category is Category.TOOL_POISONING


def _tool_name(tool: Any) -> str | None:
    if isinstance(tool, dict) and isinstance(tool.get("name"), str):
        return tool["name"]
    return None


def _strip_tools(body: dict[str, Any], names: set[str]) -> tuple[dict[str, Any], list[str]]:
    """Shallow copy of body without the named tools (same rules as sanitize)."""
    tools = body.get("tools")
    if not names or not isinstance(tools, list):
        return body, []
    kept, removed = [], []
    for tool in tools:
        name = _tool_name(tool)
        if name is not None and name in names:
            removed.append(name)
        else:
            kept.append(tool)
    if not removed:
        return body, []
    out = dict(body)
    out["tools"] = kept
    choice = out.get("tool_choice")
    if isinstance(choice, dict):
        targets_removed = choice.get("type") == "tool" and choice.get("name") in removed
        nothing_left = not kept and choice.get("type") in ("any", "tool")
        if targets_removed or nothing_left:
            out["tool_choice"] = {"type": "auto"}
    return out, removed


def _tool_use_id(body: Any, path: tuple) -> str | None:
    """tool_use_id of the tool_result block that contains path, if any."""
    node, found = body, None
    for key in path:
        if isinstance(node, dict):
            kind = node.get("type")
            if isinstance(kind, str) and kind.endswith("tool_result"):
                tid = node.get("tool_use_id")
                found = tid if isinstance(tid, str) else found
        try:
            node = node[key]
        except (KeyError, IndexError, TypeError):
            break
    return found


class AutonomousAirlock:
    """Drop-in replacement for Airlock.inspect() that needs no human."""

    def __init__(
        self,
        airlock: Any,
        config: AutonomyConfig = DEFAULT_CONFIG,
        *,
        notifier: Notifier | None = None,
        clock: Clock = time.time,
        store_factory: Callable[[], Any] | None = None,
        strict_policy: Policy | None = None,
    ) -> None:
        self.airlock = airlock
        self.config = config
        self.notifier = notifier
        self.notifier_errors = 0
        self._clock = clock
        self._store_factory = store_factory or _default_store_factory
        base: Policy = airlock.policy
        self.strict_policy = strict_policy or dataclasses.replace(
            base, untrusted_block_at=min(base.untrusted_block_at, Severity.HIGH)
        )
        self._strict_engine: Any = None
        self._lock = threading.RLock()
        self._events: deque[dict[str, Any]] = deque(maxlen=config.max_events)
        self._seq = 0
        self._call_events: list[dict[str, Any]] = []
        # Tool reputation.
        self._incidents: dict[str, deque[tuple[float, str]]] = {}
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._quarantine: dict[str, dict[str, Any]] = {}
        self._offenses: dict[str, int] = {}
        # Rug pulls: (tool, new fingerprint) -> "approved" | "quarantined".
        self._verdicts: OrderedDict[tuple[str, str], str] = OrderedDict()
        self._approvals: dict[str, deque[float]] = {}
        # Sessions.
        self._blocks: dict[str, deque[float]] = {}
        self._escalated: dict[str, float] = {}

    # Delegation so the wrapper can stand where an Airlock stood.
    @property
    def policy(self) -> Policy:
        return self.airlock.policy

    @property
    def fingerprints(self) -> Any:
        return self.airlock.fingerprints

    @property
    def detectors(self) -> Any:
        return self.airlock.detectors

    # ------------------------------------------------------------------ API

    def inspect(
        self, body: dict[str, Any], trace_id: str | None = None, session_key: str | None = None
    ) -> Any:
        return self.inspect_with_report(body, trace_id=trace_id, session_key=session_key)[0]

    def inspect_with_report(
        self, body: dict[str, Any], trace_id: str | None = None, session_key: str | None = None
    ) -> tuple[Any, list[dict[str, Any]]]:
        """Inspect and return (Decision, autonomous events raised by this call)."""
        with self._lock:
            self._call_events = []
            now = self._clock()
            self._sweep(now)
            session_key = session_key or _metadata_session(body)
            sid = _hash(f"session:{session_key}") if session_key else None
            prepared, stripped = self._strip_quarantined(body)
            engine = self._engine_for(sid, now)
            decision = engine.inspect(prepared, trace_id=trace_id)
            # Post-processing can only add restrictions or approve a clean
            # rug pull. If it fails, the plain Airlock decision stands.
            for step in (
                lambda d: self._handle_rugpulls(d, prepared, engine, now),
                lambda d: self._mark_stripped(d, stripped),
                lambda d: self._record_incidents(d, prepared, now),
                lambda d: self._record_session(d, sid, now),
            ):
                try:
                    decision = step(decision)
                except Exception as exc:  # noqa: BLE001  fail safe, never fail open
                    self._emit("autonomy_error", trace_id=decision.trace_id,
                               reason=type(exc).__name__)
            raised = list(self._call_events)
            self._call_events = []
        self._notify(raised)
        return decision, raised

    def tick(self) -> list[dict[str, Any]]:
        """Apply expirations (releases, relaxations) without a request."""
        with self._lock:
            self._call_events = []
            self._sweep(self._clock())
            raised = list(self._call_events)
            self._call_events = []
        self._notify(raised)
        return raised

    def events(self, since: int = 0, kind: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(e) for e in self._events
                    if e["seq"] > since and (kind is None or e["type"] == kind)]

    def status(self) -> dict[str, Any]:
        with self._lock:
            now = self._clock()
            return {
                "quarantined_tools": {k: dict(v) for k, v in self._quarantine.items()},
                "escalated_sessions": dict(self._escalated),
                "incidents": {k: len(v) for k, v in self._incidents.items() if v},
                "now": now,
            }

    def quarantine_reason(self, tool: str) -> str | None:
        with self._lock:
            entry = self._quarantine.get(tool)
            return entry["reason"] if entry else None

    # Manual overrides: every autonomous action can be undone or forced.
    def release_tool(self, tool: str) -> bool:
        with self._lock:
            self._call_events = []
            entry = self._quarantine.pop(tool, None)
            self._incidents.pop(tool, None)
            if entry:
                self._emit("tool_released", tool=tool, reason="manual", manual=True)
            raised, self._call_events = list(self._call_events), []
        self._notify(raised)
        return entry is not None

    def quarantine_tool(
        self, tool: str, seconds: float | None = None, reason: str = "manual"
    ) -> None:
        with self._lock:
            self._call_events = []
            now = self._clock()
            until = now + (seconds if seconds is not None else self.config.quarantine_cooldown_s)
            self._quarantine[tool] = {"until": until, "reason": reason, "since": now,
                                      "offenses": self._offenses.get(tool, 0)}
            self._emit("tool_quarantined", tool=tool, reason=reason, until=until, manual=True)
            raised, self._call_events = list(self._call_events), []
        self._notify(raised)

    def approve_tool(self, tool_def: dict[str, Any]) -> None:
        """Override a false positive: pin this definition and forget the verdict."""
        name = _tool_name(tool_def) or "?"
        with self._lock:
            self._call_events = []
            self.airlock.fingerprints.approve(tool_def)
            fp = self._fingerprint(tool_def)
            self._verdicts.pop((name, fp), None)
            self._quarantine.pop(name, None)
            self._emit(
                "manual_approved", tool=name, reason="manual", new_fingerprint=fp, manual=True
            )
            raised, self._call_events = list(self._call_events), []
        self._notify(raised)

    def relax_session(self, session_key: str) -> bool:
        sid = _hash(f"session:{session_key}")
        with self._lock:
            self._call_events = []
            was = self._escalated.pop(sid, None) is not None
            self._blocks.pop(sid, None)
            if was:
                self._emit("session_relaxed", session=sid, reason="manual", manual=True)
            raised, self._call_events = list(self._call_events), []
        self._notify(raised)
        return was

    # ------------------------------------------------------------ internals

    def _emit(self, kind: str, **fields: Any) -> dict[str, Any]:
        self._seq += 1
        event = {"seq": self._seq, "ts": self._clock(), "type": kind}
        event.update({k: v for k, v in fields.items() if v is not None})
        self._events.append(event)
        self._call_events.append(event)
        return event

    def _notify(self, events: list[dict[str, Any]]) -> None:
        if self.notifier is None:
            return
        for event in events:
            try:
                self.notifier(dict(event))
            except Exception:  # noqa: BLE001  a broken webhook must not break inspection
                self.notifier_errors += 1

    def _make_engine(self, policy: Policy, store: Any) -> Any:
        cls = type(self.airlock)
        try:
            return cls(policy=policy, fingerprints=store, detectors=self.airlock.detectors)
        except TypeError:
            clone = copy.copy(self.airlock)
            clone.policy = policy
            clone.fingerprints = store
            return clone

    def _engine_for(self, sid: str | None, now: float) -> Any:
        if sid is not None and self._escalated.get(sid, 0.0) > now:
            if self._strict_engine is None:
                self._strict_engine = self._make_engine(
                    self.strict_policy, self.airlock.fingerprints
                )
            return self._strict_engine
        return self.airlock

    def _fingerprint(self, tool: Any) -> str:
        try:
            from .tools import fingerprint

            return str(fingerprint(tool))
        except Exception:  # noqa: BLE001  unfinished or missing helper
            return _local_fingerprint(tool)

    def _current_pin(self, name: str) -> str | None:
        try:
            pins = self.airlock.fingerprints.pins()
        except Exception:  # noqa: BLE001
            return None
        if isinstance(pins, Mapping):
            value = pins.get(name)
            return str(value) if value else None
        return None

    def _sweep(self, now: float) -> None:
        cfg = self.config
        for tool in [t for t, e in self._quarantine.items() if e["until"] <= now]:
            entry = self._quarantine.pop(tool)
            self._incidents.pop(tool, None)
            self._emit("tool_released", tool=tool, reason="cooldown_elapsed",
                       quarantined_for=round(now - entry["since"], 3))
        for sid in [s for s, until in self._escalated.items() if until <= now]:
            del self._escalated[sid]
            self._emit("session_relaxed", session=sid, reason="cooldown_elapsed")
        for table, window in ((self._blocks, cfg.block_window_s),
                              (self._approvals, cfg.approval_window_s)):
            for key in list(table):
                dq = table[key]
                while dq and dq[0] <= now - window:
                    dq.popleft()
                if not dq:
                    del table[key]
        for tool in list(self._incidents):
            dq = self._incidents[tool]
            while dq and dq[0][0] <= now - cfg.incident_window_s:
                dq.popleft()
            if not dq:
                del self._incidents[tool]
        while self._seen and next(iter(self._seen.values())) <= now - cfg.seen_incident_ttl_s:
            self._seen.popitem(last=False)
        while len(self._seen) > cfg.max_tracked:
            self._seen.popitem(last=False)
        for table in (self._blocks, self._approvals, self._incidents, self._offenses):
            while len(table) > cfg.max_tracked:
                del table[next(iter(table))]

    def _strip_quarantined(self, body: Any) -> tuple[Any, list[str]]:
        if not self._quarantine or not isinstance(body, dict):
            return body, []
        return _strip_tools(body, set(self._quarantine))

    def _add_synthetic(self, decision: Any, finding: Finding) -> None:
        decision.findings = [*decision.findings, finding]
        decision.actions = [*decision.actions, Action.REDACT]
        decision.action = max(decision.action, Action.REDACT)
        if finding.tool_name and finding.tool_name not in decision.quarantined_tools:
            decision.quarantined_tools = [*decision.quarantined_tools, finding.tool_name]

    def _mark_stripped(self, decision: Any, stripped: list[str]) -> Any:
        for name in stripped:
            entry = self._quarantine.get(name, {})
            self._add_synthetic(
                decision,
                Finding(
                    rule_id=QUARANTINE_RULE,
                    category=Category.TOOL_POISONING,
                    severity=Severity.HIGH,
                    source=Source.TOOL_DEFINITION,
                    path=("tools",),
                    start=0,
                    end=0,
                    evidence="",
                    message=(
                        f"tool '{name}' quarantined automatically: "
                        f"{entry.get('reason', 'reputation')}"
                    ),
                    tool_name=name,
                ),
            )
        return decision

    # Rug pulls ------------------------------------------------------------

    def _handle_rugpulls(self, decision: Any, prepared: Any, engine: Any, now: float) -> Any:
        if not self.config.auto_approve_rugpulls or not isinstance(prepared, dict):
            return decision
        pulled: list[str] = []
        for f in decision.findings:
            if _is_rugpull(f) and f.tool_name and f.tool_name not in pulled:
                pulled.append(f.tool_name)
        if not pulled:
            return decision
        by_name = {_tool_name(t): t for t in prepared.get("tools") or [] if _tool_name(t)}
        approved: list[str] = []
        keep_out: list[str] = []
        for name in pulled:
            new_def = by_name.get(name)
            if new_def is None:
                continue
            new_fp = self._fingerprint(new_def)
            if self._verdicts.get((name, new_fp)) == "quarantined":
                keep_out.append(name)
                continue
            verdict, reason, rules = self._judge(name, new_def, decision)
            if (
                verdict == "approve"
                and len(self._approvals.get(name, ())) >= self.config.max_auto_approvals
            ):
                verdict, reason = "quarantine", "rugpull_churn"
            old_fp = self._current_pin(name)
            if verdict == "approve":
                try:
                    self.airlock.fingerprints.approve(new_def)
                except Exception as exc:  # noqa: BLE001  fail closed
                    verdict, reason = "quarantine", f"approve_failed:{type(exc).__name__}"
            self._remember(name, new_fp, "approved" if verdict == "approve" else "quarantined")
            if verdict == "approve":
                self._approvals.setdefault(name, deque()).append(now)
                approved.append(name)
                self._emit("auto_approved", trace_id=decision.trace_id, tool=name,
                           reason=reason, old_fingerprint=old_fp, new_fingerprint=new_fp)
            else:
                keep_out.append(name)
                self._emit("auto_quarantined", trace_id=decision.trace_id, tool=name,
                           reason=reason, rules=rules or None,
                           old_fingerprint=old_fp, new_fingerprint=new_fp)
                if reason == "rugpull_churn":
                    self._quarantine_tool(name, now, "rugpull_churn")
        if approved:
            # Re-pinned: inspect again so this very request keeps the tool.
            decision = engine.inspect(prepared, trace_id=decision.trace_id)
        if keep_out and not decision.blocked:
            out_body, removed = _strip_tools(decision.body, set(keep_out))
            decision.body = out_body
            for name in removed:
                self._add_synthetic(decision, Finding(
                    rule_id=RUGPULL_QUARANTINE_RULE, category=Category.RUG_PULL,
                    severity=Severity.HIGH, source=Source.TOOL_DEFINITION, path=("tools",),
                    start=0, end=0, evidence="",
                    message=f"changed tool '{name}' kept in quarantine automatically",
                    tool_name=name,
                ))
        return decision

    def _judge(self, name: str, new_def: Any, decision: Any) -> tuple[str, str, list[str]]:
        threshold = self.config.rescan_block_at
        bad = [f for f in decision.findings if f.tool_name == name and _is_poison(f, threshold)]
        try:
            scanner = self._make_engine(self.airlock.policy, self._store_factory())
            minimal = {"model": "airlock-rescan", "max_tokens": 1, "messages": [],
                       "tools": [copy.deepcopy(new_def)]}
            rescan = scanner.inspect(minimal)
        except Exception as exc:  # noqa: BLE001  cannot judge it: keep it out
            return "quarantine", f"rescan_error:{type(exc).__name__}", []
        bad += [f for f in rescan.findings if _is_poison(f, threshold)]
        if bad:
            return "quarantine", "poisoned_definition", sorted({f.rule_id for f in bad})
        return "approve", "clean_rescan", []

    def _remember(self, name: str, fp: str, verdict: str) -> None:
        self._verdicts[(name, fp)] = verdict
        self._verdicts.move_to_end((name, fp))
        while len(self._verdicts) > self.config.max_tracked:
            self._verdicts.popitem(last=False)

    # Tool reputation ------------------------------------------------------

    def _quarantine_tool(self, tool: str, now: float, reason: str) -> None:
        cfg = self.config
        offenses = self._offenses.get(tool, 0) + 1
        self._offenses[tool] = offenses
        cooldown = min(cfg.quarantine_cooldown_s * 2 ** (offenses - 1), cfg.max_quarantine_s)
        self._quarantine[tool] = {"until": now + cooldown, "reason": reason,
                                  "since": now, "offenses": offenses}
        self._incidents.pop(tool, None)
        self._emit("tool_quarantined", tool=tool, reason=reason, until=now + cooldown,
                   cooldown_s=cooldown, offenses=offenses)

    def _record_incidents(self, decision: Any, body: Any, now: float) -> Any:
        cfg = self.config
        for f, action in zip(decision.findings, decision.actions, strict=True):
            if f.source is not Source.TOOL_RESULT or action < Action.REDACT or not f.tool_name:
                continue
            tid = _tool_use_id(body, f.path)
            key = f"{f.tool_name}|{tid}" if tid else _hash(
                f"{f.tool_name}|{f.rule_id}|{list(f.path)}|{f.evidence}", 32)
            if key in self._seen:
                continue
            self._seen[key] = now
            dq = self._incidents.setdefault(f.tool_name, deque())
            dq.append((now, f.rule_id))
            while dq and dq[0][0] <= now - cfg.incident_window_s:
                dq.popleft()
            if len(dq) >= cfg.incident_threshold and f.tool_name not in self._quarantine:
                rules = sorted({r for _, r in dq})
                self._quarantine_tool(
                    f.tool_name, now,
                    f"reputation: {len(dq)} incidents in {int(cfg.incident_window_s)}s "
                    f"({', '.join(rules)})",
                )
        return decision

    # Sessions -------------------------------------------------------------

    def _record_session(self, decision: Any, sid: str | None, now: float) -> Any:
        if sid is None or not decision.blocked:
            return decision
        cfg = self.config
        dq = self._blocks.setdefault(sid, deque())
        dq.append(now)
        while dq and dq[0] <= now - cfg.block_window_s:
            dq.popleft()
        if len(dq) >= cfg.block_threshold:
            extended = self._escalated.get(sid, 0.0) > now
            until = now + cfg.escalation_cooldown_s
            self._escalated[sid] = until
            dq.clear()
            self._emit("session_escalation_extended" if extended else "session_escalated",
                       session=sid, trace_id=decision.trace_id, until=until,
                       reason=f"{cfg.block_threshold} blocks in {int(cfg.block_window_s)}s")
        return decision


__all__ = [
    "DEFAULT_CONFIG",
    "AutonomousAirlock",
    "AutonomyConfig",
    "session_key_from_headers",
]
