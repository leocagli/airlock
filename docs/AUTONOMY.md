# Autonomous mode: no human in the loop

Plain Airlock is fail-closed, but three situations used to need a person:

| Situation | Without autonomy | With `AutonomousAirlock` |
|---|---|---|
| An MCP server changes a tool definition (rug pull) | Tool quarantined on every request until someone runs `approve()` | New definition re-scanned alone: clean is re-pinned automatically, poisoned stays out |
| A tool keeps returning prompt injections | Each result is redacted, but the tool stays available and keeps feeding attacks | After N incidents in a window the tool is stripped from `tools` for a cooldown, then released automatically |
| A session is under sustained attack | Same policy for every request | Repeated BLOCKs switch that session to a stricter policy for a cooldown, then it relaxes |

Code: [`airlock/autonomy.py`](../airlock/autonomy.py) (standard library only).
Tests: [`tests/test_autonomy.py`](../tests/test_autonomy.py).

## How it works

`AutonomousAirlock(airlock)` wraps an `Airlock` by composition. The engine is
untouched and the wrapper exposes the same `inspect(body, trace_id)` returning
the same `Decision`, so it drops in wherever an `Airlock` was used.

### 1. Rug pull auto-remediation

When a decision contains a `TOOL-RUGPULL` finding for a tool:

1. The **new** definition is inspected alone: a minimal body with only that
   tool, the same policy and detectors, and a **fresh, in-memory**
   `FingerprintStore`, so it is judged on its own content and not on its
   history.
2. Findings from the full request that depend on context (name collisions,
   shadowing of another tool) are added to the verdict.
3. If no `TOOL_DEFINITION` or `TOOL_POISONING` finding at `MEDIUM` or above
   remains, the definition is re-pinned with `store.approve(new_def)`, an
   `auto_approved` event is recorded (old and new fingerprint), and the request
   is inspected again so **this same turn keeps the tool**.
4. Otherwise the tool is kept out of the request (`auto_quarantined`). The
   verdict is cached by fingerprint, so the same poisoned definition is not
   re-scanned or re-reported on every turn. When the server ships a new
   definition, it is judged again: recovery is automatic too.
5. Churn guard: more than `max_auto_approvals` (3) automatic approvals for one
   tool within an hour is itself suspicious, so the tool goes to a timed
   quarantine (`rugpull_churn`).

### 2. Tool reputation with automatic quarantine

* Every `TOOL_RESULT` finding whose action is `REDACT` or `BLOCK` counts as an
  incident for that `tool_name`.
* Incidents are deduplicated by `tool_use_id`, because agents re-send the whole
  history on every turn: one poisoned web page is one incident, not one per turn.
* `incident_threshold` (3) incidents inside `incident_window_s` (10 min) put the
  tool in quarantine for `quarantine_cooldown_s` (30 min). The tool is removed
  from `body["tools"]` **before** inspection, a `tool_choice` that targets it is
  reset to `auto`, and the decision carries a synthetic `AUTO-TOOL-QUARANTINE`
  finding with the reason, so the proxy, the audit log and the stats show why.
* The cooldown doubles for repeat offenders (capped at 24 h).
* Release is automatic when the cooldown ends (`tool_released`).

### 3. Session escalation without humans

* The session key is the caller's key (for example the API key hash from
  `session_key_from_headers()`), or by default the Messages API
  `metadata.user_id`, which Claude Code already sends. Keys are hashed before
  they are stored; raw keys never appear in events.
* `block_threshold` (3) BLOCKs within `block_window_s` (5 min) switch that
  session to a stricter policy, `dataclasses.replace(policy,
  untrusted_block_at=Severity.HIGH)`, for `escalation_cooldown_s` (15 min).
  A HIGH injection in a tool result is then blocked instead of redacted.
* Other sessions keep the normal policy. The session relaxes automatically
  (`session_relaxed`); reaching the threshold again while escalated extends it.

### Events, notifier and overrides

Every autonomous action is an event: `auto_approved`, `auto_quarantined`,
`tool_quarantined`, `tool_released`, `session_escalated`,
`session_escalation_extended`, `session_relaxed`, `autonomy_error`.

* `events(since=0, kind=None)` reads the bounded in-memory log.
* `inspect_with_report()` returns the decision plus the events of that call.
* `notifier=callable(event)` pushes each event to a webhook, Slack or the
  hash-chained audit log. The module itself never touches the network, and a
  failing notifier is counted (`notifier_errors`) but never breaks inspection.
* `status()` shows quarantined tools (with reason and expiry), escalated
  sessions and incident counts.
* Every action is reversible: `release_tool()`, `quarantine_tool()`,
  `approve_tool()` (false positive) and `relax_session()`. These are optional;
  nothing waits for them.

## Safety argument

1. **Fail-closed for poisoned tools.** A changed tool is approved only when a
   positive check passes: the re-scan ran and found nothing at MEDIUM or above.
   A re-scan error, an approve error, a churning tool or any poisoning finding
   keeps the tool out. Approval never happens because a check could not run.
2. **Auto-approve only clean changes.** The re-scan uses the same detectors and
   policy as the live traffic, plus the context findings of the full request.
   The bar for approval (MEDIUM) is stricter than the bar for quarantine in the
   default policy (HIGH).
3. **Autonomy only tightens, except for one narrow case.** Reputation
   quarantine and session escalation can only remove tools or block more. The
   only relaxing action is re-pinning a changed tool whose new content passed
   the full scan. If any autonomy step raises, the plain Airlock decision for
   that request stands and an `autonomy_error` event is recorded.
4. **Audited and reversible.** Every action is an event with a sequence number,
   timestamp, tool or hashed session, reason, rule ids and fingerprints, and can
   be undone through the override methods. No raw evidence or secrets are
   included in events.
5. **Bounded state.** Event log, incident memory, verdict cache and per-key
   tables are capped (`max_events`, `max_tracked`), so a hostile stream of tool
   names or sessions cannot exhaust memory.
6. **Deterministic.** The clock is injectable; the tests drive every cooldown
   and window without sleeping.

## Continuous security evidence

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs on every push,
pull request and nightly (cron), with read-only repository permissions:
pytest, the HTTP smoke test (`scripts/smoke.sh`), `bandit -r airlock -q`,
`pip-audit`, and Snyk (open source and
Snyk Code). Snyk is a hard gate when the `SNYK_TOKEN` secret is configured and
informational when it is not.

## Enabling it in the proxy

Three lines in `proxy.create_app`, right after `audit = AuditLog(audit_file)`:

```python
    if os.environ.get("AIRLOCK_AUTONOMOUS") == "1":
        from .autonomy import AutonomousAirlock
        airlock = AutonomousAirlock(airlock, notifier=lambda e: audit.append({"kind": "autonomy", "event": e}))
```

The `inspect(body, trace_id=trace)` call stays as it is. Session escalation
uses `metadata.user_id` by default; to key it on the API key instead, pass
`session_key=session_key_from_headers(request.headers)` when the wrapper is
active.

## Limits

* The re-scan is only as good as the detectors. A rug pull that changes what a
  tool **does** on the server, while its description, schema and name stay
  clean, is invisible to any definition-based check. Reputation quarantine is
  the second line for that case: if the tool starts returning injections, it is
  removed.
* State is in memory and per process. Pins persist through
  `FingerprintStore(path)`, but reputation, verdict cache and escalations reset
  on restart (the safe direction for pins, the permissive direction for
  reputation).
* Inspection is serialized by one lock; fine for a local proxy, not for a
  high-throughput shared gateway.
* Stripping the last tool leaves `tools: []`; if the history still contains
  `tool_use` blocks, the upstream API may reject the request. The agent sees an
  error instead of an attack, which is the fail-closed outcome.
* Escalation is per session key. An attacker who can rotate keys (or
  `metadata.user_id`) avoids the stricter policy, but not the base policy.
* Thresholds are defaults chosen for an interactive coding agent; tune
  `AutonomyConfig` for other workloads.
