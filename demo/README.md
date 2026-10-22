# Airlock demo

Everything here runs without an API key and without network access.

## 1. Offline story (90 seconds)

From the repository root:

```sh
python -m demo.demo          # or: python demo/demo.py
python -m demo.demo --slow   # pauses between scenes, for screen recording
```

The demo starts the real Airlock proxy in-process, in front of a mock model
(`demo/mock_upstream.py`) that records and echoes every request it receives.
It then plays five scenes:

| Scene | Request | Expected |
| --- | --- | --- |
| Indirect prompt injection in a web page | `requests/01_web_injection.json` | BLOCK: the model is never called, the agent gets an explanation |
| MCP tool poisoning (`add_numbers` with an `<IMPORTANT>` block) | `requests/02_mcp_poisoning.json` | REDACT: the tool is quarantined, the rest of the request goes through |
| Secret pasted by the user | `requests/03_secret_paste.json` | REDACT: the key is masked before it leaves the machine |
| Clean code review | `requests/04_clean.json` | ALLOW: forwarded byte for byte |
| MCP rug pull | `rugpull_before.json`, then `rugpull_after.json` | day 1 ALLOW (pinned), day 2 the changed tool is quarantined |

For each scene it prints what the agent tried to send, the Airlock decision
with every finding (rule, category, OWASP id, source, tool, severity), and what
actually reached the model. It ends with `/airlock/stats`, a check of the
hash-chained audit log, and a tamper test: one record of a copy of the log is
edited and verification points at the broken record.

The secret scene stores `{{FAKE_AWS_KEY}}` in the JSON. The demo expands it at
runtime, so no key-shaped string is committed. To scan it from the CLI:

```sh
python -m demo.demo --print secret | python -m airlock scan -
python -m airlock scan demo/requests/02_mcp_poisoning.json
python -m airlock scan demo/requests/01_web_injection.json --json
```

`scan` exits with 0 for ALLOW/WARN, 1 for REDACT and 2 for BLOCK, so it also
works as a CI gate.

## 2. Live with Claude Code

```sh
python -m airlock serve                      # 127.0.0.1:8787, upstream api.anthropic.com
ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude
```

Then ask Claude Code to fetch a page that hides instructions, or connect a
poisoned MCP server. Every response carries `x-airlock-action`,
`x-airlock-trace` and `x-airlock-findings` headers. A blocked request comes
back as a normal assistant message (JSON or SSE) that explains which rule fired,
so the agent stops instead of crashing.

Useful endpoints while it runs:

```sh
curl -s http://127.0.0.1:8787/healthz
curl -s http://127.0.0.1:8787/airlock/stats
curl -s http://127.0.0.1:8787/airlock/audit/verify
python -m airlock audit-verify airlock-audit.jsonl
```

Settings (environment): `AIRLOCK_UPSTREAM` (default `https://api.anthropic.com`),
`AIRLOCK_AUDIT_LOG` (default `airlock-audit.jsonl`), `AIRLOCK_FINGERPRINTS`
(tool fingerprint file; set it to keep rug-pull pins across restarts).

## 3. Live without an API key

Run the mock model as a server and point Airlock at it:

```sh
python -m demo.mock_upstream                                   # 127.0.0.1:8788
AIRLOCK_UPSTREAM=http://127.0.0.1:8788 python -m airlock serve
curl -s http://127.0.0.1:8787/v1/messages -H 'content-type: application/json' \
  -d @demo/requests/02_mcp_poisoning.json -D - | head -20
```

The echoed request shows that the quarantined tool never reached the model.

## Privacy of the audit log

Audit records hold the decision (rule ids, categories, sources, tool names,
actions), the model name and the SHA-256 of the raw request. They never hold
prompt text, evidence snippets or API keys.
