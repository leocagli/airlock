# Reputation (ERC-8004 compatible)

`airlock/reputation.py` adds memory to the firewall. Findings are per request:
a tool that returned an attack an hour ago looks clean on its next call.
`ReputationBook` keeps a 0..100 score per tool and per MCP server across
requests, and that score flows back into the normal verdicts
(ALLOW / WARN / REDACT / BLOCK) through a regular text detector, so the
existing policy and sanitizer do the enforcing.

## Subjects

- `tool:<name>` for every tool.
- `server:<server>` for MCP tools, using Claude Code naming:
  `mcp__github__create_issue` belongs to `server:github`. Plain names
  (`read_file`) have no server.

A finding on an MCP tool lowers both the tool and its server, so a compromised
server loses trust for all of its tools.

## Scoring model

| Rule | Value |
| --- | --- |
| Prior for unknown subjects | 60 (neutral) |
| Penalty per incident | action base x severity weight |
| Action base | WARN 3, REDACT 8, BLOCK 20 (ALLOW 0) |
| Severity weight | LOW 0.5, MEDIUM 1, HIGH 1.5, CRITICAL 2 |
| Recovery | +1 per request where the tool appears with no findings |
| Recovery ceiling | the subject's baseline: its seeded score, else the prior |

Counted sources: tool results, tool definitions and tool calls that carry a
`tool_name`. Details that keep the score honest:

- An incident is counted once. Agents re-send the whole history every turn, so
  identical findings are deduplicated (bounded memory, not persisted).
- `REP-*` findings never penalize: a flag raised because of a low score is a
  consequence, not new evidence. No feedback loop.
- Trust above the prior only comes from outside evidence (`seed`).
- A blocked subject does not recover on its own. `seed()` or `reset()` lifts
  it, so an attacker cannot simply wait it out.
- The last 50 incidents per subject are kept (ts, trace_id, rule_id,
  category, action, severity, delta), plus lifetime counts.

## Levels and what the firewall does

| Level | Score | Tool definition | Tool result |
| --- | --- | --- | --- |
| trusted | >= 75 | nothing | nothing |
| neutral | >= 40 | nothing | nothing |
| suspicious | >= 20 | `REP-LOW-SCORE` MEDIUM: WARN | `REP-LOW-SCORE` MEDIUM: WARN |
| blocked | < 20 | `REP-LOW-SCORE` HIGH on `tools[i]`: REDACT, tool quarantined | WARN |

The level used is the worst of the tool and its server. Under the proxy's
default `HARNESS_POLICY` only `mcp__*` definitions are third party, so a
blocked harness tool is flagged (WARN) but not removed.

Findings use `Category.REPUTATION` (OWASP LLM03, supply chain).

## Mapping to ERC-8004 (Trustless Agents)

ERC-8004 defines three registries: Identity, Reputation and Validation. The
mapping below is in terms of the standard's concepts, not a contract ABI.

- Identity: `bind(subject, agent_id, registry=None)` links a tool or server
  to its ERC-8004 agentId.
- Reputation in: `seed([...])` loads scores summarized from a Reputation
  Registry indexer, for example
  `{"subject": "server:github", "score": 82, "agent_id": 123, "source": "erc8004"}`.
  The seeded score also becomes the subject's baseline.
- Reputation out: `erc8004_feedback(subject)` returns a feedback entry:
  `agentId`, `score` (0..100), `tag1` = `airlock`, `tag2` = dominant incident
  category, `fileuri` (default `airlock://audit/<subject>`) and `filehash`,
  the sha256 of the canonical JSON evidence document returned alongside it
  (subject, score, incident counts by category and action, last trace ids,
  generated_at). `export(path)` writes the entries for every bound subject.

## Not done tonight

- On-chain submission. Signing and sending feedback to the registry belongs
  to the operator wallet: Airlock never holds keys. The exact on-chain
  encoding (for example tags or the hash as bytes32) depends on the deployed
  registry version and is left to the submitter.
- Registry reads. `seed()` takes data you already fetched; there is no
  indexer client in the core (standard library only).
- Validation Registry hooks, decay over time, and persisted deduplication.

## Usage

```python
from airlock.reputation import ReputationAirlock, ReputationBook

book = ReputationBook(path="reputation.json")   # atomic JSON, survives restarts
book.seed([{"subject": "server:github", "score": 82, "agent_id": 123, "source": "erc8004"}])
book.bind("server:evil", 456)

guard = ReputationAirlock(book)            # same kwargs as Airlock(policy=..., ...)
decision = guard.inspect(body)             # verdict uses current scores, then learns
print(book.level("server:evil"), decision.quarantined_tools)
print(book.erc8004_feedback("server:evil")["filehash"])
book.export("feedback.json")               # entries for every bound subject
```

To use the detector in a plain `Airlock`, pair it with `ReputationCache`: the
engine caches findings per segment, which would replay a stale score.

```python
Airlock(detectors=(*TEXT_DETECTORS, book.detector()), cache=ReputationCache(book))
```

`with_reputation(airlock, book)` wraps an existing Airlock, keeping its
policy, pins and detectors.
