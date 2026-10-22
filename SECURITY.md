# Security policy

Airlock is a firewall between an LLM agent and the Anthropic Messages API. This
page states what it defends against, whom it trusts, where it stops, and how to
report a problem. The latest scan results are in
[docs/SECURITY_SCAN.md](docs/SECURITY_SCAN.md).

## Threat model

**Assets.** The agent's instructions and goals, the secrets and files it can
reach (API keys, SSH keys, `.env` files, source code), and the user's trust in
the actions the agent takes.

**Main adversary.** A third party who can write text that the agent will read
but who cannot talk to the agent directly: the author of a web page, an email, a
file in a cloned repository, a search result or an MCP server. This is indirect
prompt injection (OWASP LLM01) and its consequences: excessive agency (LLM06),
data exfiltration (LLM02) and supply-chain poisoning of tools (LLM03).

**What Airlock defends.** On every `POST /v1/messages` it splits the request into
segments tagged by origin, runs stateless detectors and decides ALLOW, WARN,
REDACT or BLOCK before anything reaches the model:

- injection phrasing, role spoofing and concealment in tool results;
- invisible Unicode: tag characters, zero-width characters, bidi controls;
- exfiltration: markdown images that carry data to attacker URLs, out-of-band
  callback domains, instructions to send data out, and references to sensitive
  files such as SSH keys or `.env`;
- secrets anywhere in the request (cloud keys, tokens, private keys, passwords in
  connection strings), masked as `[REDACTED:<rule>]`;
- poisoned MCP tool definitions (hidden directives, shadowing of other tools,
  parameters built to carry stolen data, name collisions) and rug pulls (a tool
  whose definition changes after it was first seen).

Anything Airlock cannot parse, scan or rewrite is blocked (`AIR-FAIL-CLOSED`), and
an exception during inspection returns an error without forwarding the request.

## Trust model by source

The same words mean different things depending on who wrote them, so the action
depends on (category, source, severity). Defaults from `airlock/policy.py`:

| Source | Written by | Trust | Strongest action |
|---|---|---|---|
| `system` | the agent harness | trusted | WARN, or REDACT to strip invisible characters |
| `user` | the human user | trusted | WARN, or REDACT to strip invisible characters |
| `assistant` | the model, earlier turns | trusted | WARN, or REDACT to strip invisible characters |
| `tool_use` | the model, tool arguments | partly trusted | BLOCK at CRITICAL (for example an upload command) |
| `tool_result` | third parties | untrusted | CRITICAL: BLOCK, HIGH: REDACT, MEDIUM: WARN |
| `tool_definition` | MCP servers | untrusted | HIGH or above: the tool is quarantined (removed) |

Secrets are redacted wherever they appear, except in the harness's own trusted
tool definitions. A user asking how prompt injection works is never blocked; a
web page giving the same order to the agent is.

**Tool trust setting.** By default the proxy uses the harness policy: only tools
named `mcp__<server>__<tool>` (how Claude Code names MCP tools) are third-party,
and the harness's own tools are trusted like its system prompt. With any other
client, set `AIRLOCK_TOOL_TRUST=all` so every tool definition is treated as
untrusted.

**Trust on first use (TOFU) pinning.** The first definition seen for a tool is
fingerprinted and pinned (in memory, or in the file named by
`AIRLOCK_FINGERPRINTS`). A later request whose definition differs raises
`TOOL-RUGPULL` and the tool is quarantined. Pinning detects change; it does not
prove that the first definition was honest.

## Deployment guidance

- Keep the proxy on loopback (`airlock serve` binds `127.0.0.1` by default). It
  has no client authentication, and `/airlock/stats` and `/airlock/audit/verify`
  are open to whoever can reach the port.
- API keys are forwarded upstream and never logged. Protect the environment that
  sets `AIRLOCK_UPSTREAM`: whoever controls it receives those keys.
- Store the audit log and the fingerprint file where the agent itself cannot
  write, and publish the last audit hash somewhere external if you need to detect
  truncation.

## Known limitations

- **Heuristic detection can be bypassed by paraphrase.** Detectors are regular
  expressions and rules, not a model. Reworded instructions, homoglyphs,
  leetspeak, other languages, reference-style markdown images, CSS hiding through
  classes or the `hidden` attribute, and "send it to my server" without a URL can
  get through. Airlock reduces the attack surface; it does not replace least
  privilege, sandboxing or human confirmation of sensitive actions.
- **First-seen tool definitions are trusted.** A server that is malicious from
  its first response is only caught if its text matches a poisoning rule. Pins
  are keyed by tool name only.
- **Streaming responses are not inspected.** Airlock inspects what goes to the
  model, not what comes back; model output, including streamed tool calls, is
  relayed unchanged.
- **Audit log integrity is tamper-evident, not tamper-proof.** The SHA-256 hash
  chain exposes edited, reordered or deleted records, but anyone with write access
  can rewrite the whole chain, and truncating the tail is invisible without an
  external anchor.
- **Only `POST /v1/messages` is inspected.** Other `/v1/*` paths, including
  Message Batches, pass through untouched.
- **One inspection at a time.** Very large first scans (about 1 to 2 s per MB of
  tool output) queue other requests behind them, although the event loop stays
  responsive.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Email
`<SECURITY_CONTACT_EMAIL>` (placeholder: the maintainers will publish the
address) with the affected version or commit, a minimal request body that
reproduces the issue (with fake secrets only), and the decision you expected.
We aim to acknowledge reports within 3 working days and to agree a disclosure
date with you, by default within 90 days.
