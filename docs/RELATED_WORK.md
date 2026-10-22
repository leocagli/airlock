# Related work

Researched on 2026-10-22, during the hackathon. Vendor features change fast. Anything marked
**(unverified)** comes from a secondary source (aggregator, press, comparison site) or from
memory and was not checked against a primary page tonight. Star counts are as shown on GitHub
on the research date.

## The landscape in one paragraph

The market split into three shapes. **Scanners** inspect installed agent components
(MCP servers, tool descriptions, skills) at install time or on a schedule (Snyk Agent Scan).
**Guardrail APIs and libraries** classify text that the integrator chooses to send them
(Lakera Guard, Prompt Shields, LLM Guard, LlamaFirewall, NeMo Guardrails). **Gateways** sit on
a network path: either the MCP path between client and tool servers (Lasso MCP Gateway,
Docker MCP Gateway) or the LLM API path (Invariant Gateway, Cloudflare). In 2025 most
independent guardrail vendors were bought by platform security companies (Lakera by Check
Point, Prompt Security by SentinelOne, Protect AI by Palo Alto Networks, Aim by Cato Networks,
Pangea by CrowdStrike, CalypsoAI by F5), so the commercial offer is now mostly enterprise
SaaS bundled into larger platforms.

## Comparison

Legend: "Tool results" = content returned by tools (web pages, files, MCP output), the main
indirect prompt injection vector. "Tool defs" = tool names, descriptions and schemas.

| Product | Shape and deployment | Inspects | Tool results | Tool defs | License / price | Gap relative to Airlock's scope |
|---|---|---|---|---|---|---|
| **Snyk Agent Scan** (ex Invariant `mcp-scan`) | CLI scanner, plus scheduled "background mode" reporting to Snyk Evo | MCP servers, tools, prompts, resources, skills | Not documented in current README | Yes, static. `mcp-scan` introduced tool pinning by hash for rug pulls | Apache-2.0 CLI (3.2k stars); analysis uses a remote Snyk API that receives tool names and descriptions; external contributions not accepted | Not in the request path. The `mcp-scan proxy` runtime mode is documented for the old package; whether it survives in v0.6 is **(unverified)** |
| **Invariant Gateway** (Snyk) | LLM API proxy, change base URL; hosted or local Docker | Agent traces; guardrails configured in Invariant Explorer | Captures tool calling traffic; content guardrail detail not documented | Not documented | Apache-2.0, 82 stars; needs an Invariant API key for tracing and guardrails | Closest architectural analog. Default flow sends traces to a hosted Explorer; fully offline guardrails not documented |
| **Lasso MCP Gateway** | Proxy on the MCP path only (client to MCP servers) | Tool requests and responses; `--scan` reputation and description checks | Yes (secrets via local plugin; injection via Lasso API) | Yes, at scan time, reputation threshold | MIT, 396 stars; injection detection needs `LASSO_API_KEY` (SaaS) | Does not see system prompt, user turns, or tool results that do not come from MCP (web fetch, file read, shell) |
| **Lasso claude-hooks** | Claude Code PostToolUse hook | Tool output text | Yes, pattern based (YAML) | No | Open source, about 250 stars **(unverified)** | Claude Code only; reported to warn rather than redact **(unverified)**; no tool definition or history view |
| **Docker MCP Gateway** | Containerized MCP server runner and router | MCP calls | Secrets: blog mentions `--block-secrets` | No content checks documented | MIT | Isolation and secret management, not content inspection; MCP path only |
| **Lakera Guard** (now Check Point AI Guardrails) | SaaS API; self-hosted for enterprise | Whatever text the app sends | Only if the integrator sends it | Only if sent | Proprietary; free community tier about 10K requests per month **(unverified)**; enterprise custom | Trained classifier is stronger on paraphrase. Requires sending agent context to a third party and wiring every call |
| **Microsoft Prompt Shields + Spotlighting** | Azure AI Content Safety API | "User prompt attacks" vs "document attacks" | Yes, as documents, if the app labels them | No | Azure paid service | Already origin aware (user vs document), but the app must split and label; Spotlighting is opt in, base64 based, Chat Completions only |
| **Meta LlamaFirewall** (PromptGuard 2, AlignmentCheck, CodeShield) | Python library / framework | Inputs, untrusted data, agent reasoning, generated code | Yes, if wired in | No | Open source under Llama license terms (700M MAU clause) | Strongest open research baseline (reported AgentDojo ASR drop from 17.6% to 1.75%); needs GPU or LLM calls and code integration, not a drop-in proxy |
| **Protect AI LLM Guard** (Palo Alto) | Python library, optional API | 15 input and 21 output scanners | Not designed for it | No | MIT, 3.2k stars, **repository archived** | Prompt in / answer out model with no notion of message origin |
| **Protect AI Rebuff** | Library + service | Prompts (heuristics, LLM, vector DB, canaries) | No | No | Archived May 2025 **(unverified)** | Unmaintained |
| **NVIDIA NeMo Guardrails** | Python framework, Colang rails | Input, dialog, output, retrieval and execution (tool) rails | Yes, via execution and retrieval rails | No | Apache-2.0 | Powerful but app embedded; rails often call an LLM (latency, cost); no MCP pinning |
| **Cloudflare AI Security for Apps** (ex Firewall for AI) | Edge WAF add-on | PII, unsafe topics, prompt injection in prompts to `cf-llm` endpoints | Not documented | Not documented | Enterprise paid add-on | Protects a public LLM app from its users; not on the agent to model path of a developer workstation |
| **Prompt Security** (SentinelOne), **Aim** (Cato), **Pangea** (CrowdStrike), **CalypsoAI** (F5), **Prisma AIRS** (Palo Alto), **Cisco AI Defense** (ex Robust Intelligence, 2024, **unverified tonight**) | Enterprise SaaS, browser or network inline, SDKs | Employee AI usage, apps, agents | Varies, mostly undocumented publicly | Some MCP features **(unverified)** | Proprietary, sales led | Not inspectable, not local, not free; buying signal shows the problem is real |
| **Zenity**, **HiddenLayer**, **Noma**, **Pillar** | Enterprise agent runtime and posture platforms | Zenity: inline tool invocation controls for Copilot Studio, Foundry, AgentKit. HiddenLayer: "Agent Harness Security" for coding agents **(unverified)**. Noma, Pillar: not checked tonight | Platform specific | Platform specific | Proprietary | Tied to specific agent platforms or enterprise contracts |
| Small OSS MCP firewalls (MCP PoisonGuard, Glyph, MCP Doorman, mcp-watch, MCPRadar) | MCP proxies or scanners | Tool descriptions, some rug pull checks | Some | Yes | Open source, low traction **(unverified)** | MCP path only; no measured corpus published that we found |

## Where Airlock is different

1. **Enforcement point.** Airlock sits on the LLM API path, activated with one environment
   variable (`ANTHROPIC_BASE_URL=http://127.0.0.1:8787`). Every model call carries the whole
   context: system prompt, user turns, history of `tool_use`, every `tool_result` (whatever the
   tool: MCP, web fetch, file read, shell) and the full `tools[]` list. MCP gateways only see
   the MCP path; hooks only see one event type; guardrail APIs only see what the developer
   remembered to send. No account, no API key, no data leaves the machine. Core detectors are
   Python stdlib only.
2. **Origin aware policy.** The same span is judged by who wrote it (`airlock/policy.py`): a
   user asking about "ignore previous instructions" is allowed, the same words inside a fetched
   web page are an attack. Prompt Shields has a similar user vs document split, but the app has
   to label documents by hand; Airlock derives origin automatically from the Messages API block
   types.
3. **Graduated, surgical actions.** ALLOW, WARN, REDACT, BLOCK. REDACT removes only the
   malicious span (or the hidden Unicode, or the secret), and poisoned tool definitions are
   quarantined (dropped from `tools[]`) so the agent keeps working. BLOCK returns a synthetic
   Anthropic shaped reply in JSON or SSE, so the client does not crash.
4. **Runtime rug pull pinning.** Trust on first use sha256 pins per tool, checked on every
   request. The idea (tool hashing) comes from Invariant's `mcp-scan`; the difference is that
   Airlock enforces it inline, on the definitions the model actually receives, and reacts by
   quarantining the changed tool.
5. **Evidence, not claims.** Hash chained tamper evident audit log, live Claude Code runs through
   the proxy, an HTTP smoke test and reputation attestations anchored on the Stellar testnet (see
   the README, "Proofs"). Benchmark detection and false positive rates are the next step.
   Injection patterns in English, Spanish and Portuguese; most open tools are English first.

## Where Airlock is weaker (say it before a judge does)

- **Heuristics, not trained classifiers.** Regex and structural rules are exact for
  deterministic channels (Unicode tag smuggling, zero width, bidi, HTML comments, markdown image
  exfil, OAST domains, secrets) but weaker than PromptGuard 2 or Lakera on paraphrased natural
  language injection.
- **Request side only, for now.** A dangerous `tool_use` emitted in a model response is seen
  by Airlock on the next request, after the client may have executed it. Claude Code
  permission prompts are the current backstop; streaming response inspection is the next step.
- **Small, self authored corpus.** Numbers are honest but not a third party benchmark
  (AgentDojo, InjecAgent, BIPIA would be the external yardsticks).
- **Anthropic Messages API only.** OpenAI and Gemini shapes are not parsed yet.
- **Single user, local.** No central policy management, dashboards or fleet reporting.

## If a judge asks

**"How is this different from Snyk Agent Scan?"** Agent Scan answers "is what I installed
safe?" before or between sessions, and sends tool descriptions to Snyk's API for analysis.
Airlock answers "is this request safe?" on every model call, locally, and covers the
`tool_result` channel where indirect prompt injection actually arrives. They compose: scan at
install time, Airlock at runtime. Airlock borrows the tool pinning idea and moves it inline.

**"How is this different from Lakera / Prompt Shields / LLM Guard?"** Those are detectors you
call; Airlock is where you enforce. They need the developer to extract and label the right text
for each call; Airlock gets origin for free from the protocol and applies graduated actions. A
trained classifier can be plugged in as one more detector behind the same interface
(`airlock/detectors/__init__.py`); the policy and the audit trail stay the same. LLM Guard is
archived and has no notion of message origin.

**"Regex is trivially bypassed."** For hidden channels and exfil URLs, structural rules are
the right tool and are exact. For natural language injection, yes, which is why we publish the
miss rate and the false positive rate instead of a single headline number, and why the detector
layer is pluggable.

## Sources

- Snyk Agent Scan repository: https://github.com/snyk/agent-scan
- Invariant, "Introducing MCP-Scan" (tool pinning via hashing): https://invariantlabs.ai/blog/introducing-mcp-scan
- MCP-Scan docs (proxy mode): https://explorer.invariantlabs.ai/docs/mcp-scan
- Snyk Labs on the Invariant Labs acquisition: https://labs.snyk.io/resources/snyk-labs-invariant-labs
- Invariant Gateway repository: https://github.com/invariantlabs-ai/invariant-gateway
- Lasso MCP Gateway repository: https://github.com/lasso-security/mcp-gateway
- Lasso MCP Gateway launch (April 2025): https://vmblog.com/news/lasso-releases-first-open-source-security-gateway-for-mcp/
- Lasso claude-hooks (secondary aggregator): https://gittrend.io/repo/lasso-security/claude-hooks
- Docker MCP Gateway blog: https://www.docker.com/blog/docker-mcp-gateway-secure-infrastructure-for-agentic-ai/
- Docker MCP Gateway repository: https://github.com/docker/mcp-gateway
- Cloudflare AI Security for Apps docs: https://developers.cloudflare.com/waf/detections/firewall-for-ai/
- Check Point acquires Lakera: https://www.csoonline.com/article/4058653/check-point-acquires-lakera-to-build-a-unified-ai-security-stack.html
- Lakera pricing and alternatives (secondary): https://appsecsanta.com/lakera-alternatives
- Microsoft Prompt Shields and Spotlighting: https://learn.microsoft.com/en-my/Azure/foundry-classic/openai/concepts/content-filter-prompt-shields
- LlamaFirewall paper: https://arxiv.org/html/2505.03574v1
- LlamaFirewall license note: https://deeplearning.ai/the-batch/meta-releases-llamafirewall-an-open-source-defense-against-ai-hijacking/
- LLM Guard repository (archived): https://github.com/protectai/llm-guard
- Rebuff status (secondary): https://appsecsanta.com/rebuff
- NeMo Guardrails rail types: https://docs.nvidia.com/nemo/guardrails/0.19.0/user-guides/guardrails-process.html
- SentinelOne acquires Prompt Security: https://darkreading.com/endpoint-security/sentinelone-acquires-ai-startup-prompt-security
- September 2025 M&A roundup (Aim, Pangea, CalypsoAI, Lakera): https://www.securityweek.com/cybersecurity-ma-roundup-40-deals-announced-in-september-2025/
- CrowdStrike, SentinelOne, Check Point AI security deals: https://www.infosecurity-magazine.com/news-features/cybersecurity-ma-crowdstrike
- Zenity inline runtime for Microsoft Foundry: https://zenity.io/company-overview/newsroom/company-news/zenity-announces-availability-of-inline-agent-runtime-security-for-agents-built-on-microsoft
- HiddenLayer agent runtime funding (secondary): https://www.kucoin.com/blog/hiddenlayer-100m-ai-agent-runtime-security
- MCP PoisonGuard listing: https://glama.ai/mcp/servers/skmahe1077/mcp-poisonguard
- mcp-watch guide: https://mcpcat.io/guides/detecting-tool-poisoning-attacks-mcp-watch/
