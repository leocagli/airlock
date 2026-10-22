"""Turns Findings into Actions.

The key idea: the same words mean different things depending on who wrote
them. A user asking "how do I stop 'ignore previous instructions' attacks?"
is fine. A web page that says it to the agent is an attack. So the action
depends on (category, source, severity), not on the match alone.
"""

from __future__ import annotations

from dataclasses import dataclass

from .types import Action, Category, Finding, Severity, Source


@dataclass(frozen=True)
class Policy:
    # Content written by third parties (tool results).
    untrusted_block_at: Severity = Severity.CRITICAL
    untrusted_redact_at: Severity = Severity.HIGH
    untrusted_warn_at: Severity = Severity.MEDIUM
    # Tool definitions: poisoned tools are removed from the request instead of
    # rewritten, so the agent keeps working without them.
    quarantine_poisoned_tools: bool = True
    tool_definition_quarantine_at: Severity = Severity.HIGH
    # Tool calls the model already emitted (visible again in the history).
    tool_use_block_at: Severity = Severity.CRITICAL
    tool_use_warn_at: Severity = Severity.HIGH
    # User / system / assistant text: never blocked for talking about attacks.
    trusted_warn_at: Severity = Severity.MEDIUM
    trusted_strip_hidden_at: Severity = Severity.HIGH
    # Secrets are masked wherever they appear.
    redact_secrets: bool = True
    # Tool trust. Empty means every tool definition is third-party content. A harness
    # such as Claude Code ships its own tools (Bash, Edit, ...) next to MCP tools named
    # "mcp__<server>__<tool>"; with ("mcp__",) only MCP tools are untrusted and the
    # harness's native tools are judged like its system prompt (at most WARN).
    untrusted_tool_prefixes: tuple[str, ...] = ()
    # Agent harnesses resend the whole history every turn, so a BLOCK caused by an old
    # tool result would block every later turn. With False, critical findings in a tool
    # result are neutralized (REDACT of the offending span or whole result) instead.
    block_untrusted_critical: bool = True

    def tool_is_untrusted(self, name: str | None) -> bool:
        if not self.untrusted_tool_prefixes:
            return True
        return bool(name) and name.startswith(self.untrusted_tool_prefixes)


DEFAULT_POLICY = Policy()
# Policy for agent harnesses that prefix third-party tools (Claude Code: mcp__server__tool).
HARNESS_POLICY = Policy(untrusted_tool_prefixes=("mcp__",), block_untrusted_critical=False)


def action_for(finding: Finding, policy: Policy = DEFAULT_POLICY) -> Action:
    sev = finding.severity
    src = finding.source

    if src is Source.TOOL_DEFINITION and not policy.tool_is_untrusted(finding.tool_name):
        # The harness's own tools are as trusted as its system prompt: never quarantined.
        return Action.WARN if sev >= policy.trusted_warn_at else Action.ALLOW

    if finding.category is Category.SECRET:
        return Action.REDACT if policy.redact_secrets else Action.WARN
    if finding.category is Category.PII:
        return Action.WARN

    if src is Source.TOOL_DEFINITION:
        if sev >= policy.tool_definition_quarantine_at:
            return Action.REDACT if policy.quarantine_poisoned_tools else Action.BLOCK
        return Action.WARN if sev >= policy.untrusted_warn_at else Action.ALLOW

    if src is Source.TOOL_RESULT:
        if sev >= policy.untrusted_block_at:
            return Action.BLOCK if policy.block_untrusted_critical else Action.REDACT
        if sev >= policy.untrusted_redact_at:
            return Action.REDACT
        return Action.WARN if sev >= policy.untrusted_warn_at else Action.ALLOW

    if src is Source.TOOL_USE:
        if sev >= policy.tool_use_block_at:
            return Action.BLOCK
        return Action.WARN if sev >= policy.tool_use_warn_at else Action.ALLOW

    # SYSTEM / USER / ASSISTANT
    if finding.category is Category.HIDDEN_CONTENT and sev >= policy.trusted_strip_hidden_at:
        return Action.REDACT
    return Action.WARN if sev >= policy.trusted_warn_at else Action.ALLOW


def decide(findings: list[Finding], policy: Policy = DEFAULT_POLICY) -> tuple[Action, list[Action]]:
    per_finding = [action_for(f, policy) for f in findings]
    return max(per_finding, default=Action.ALLOW), per_finding
