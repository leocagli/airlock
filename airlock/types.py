"""Core data model shared by every Airlock module.

A request body (Anthropic Messages API shape) is split into Segments, each
tagged with where it came from. Detectors turn Segments into Findings. The
policy turns Findings into an Action. Paths are tuples of dict keys / list
indexes so sanitizers can rewrite the exact string they point at.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Any

Path = tuple[str | int, ...]


class Source(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    # Arguments of a tool call the model emitted (seen again in the history).
    TOOL_USE = "tool_use"
    # Content returned by a tool: web pages, files, emails, MCP output.
    TOOL_RESULT = "tool_result"
    # tools[].name / description / input_schema: supplied by MCP servers.
    TOOL_DEFINITION = "tool_definition"


# Content that a third party can write. Instructions here are never legitimate.
UNTRUSTED_SOURCES = frozenset({Source.TOOL_RESULT, Source.TOOL_DEFINITION})


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Action(IntEnum):
    """Ordered so that max() picks the strictest action."""

    ALLOW = 0
    WARN = 1
    REDACT = 2
    BLOCK = 3


class Category(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    HIDDEN_CONTENT = "hidden_content"
    EXFILTRATION = "exfiltration"
    EXCESSIVE_AGENCY = "excessive_agency"
    TOOL_POISONING = "tool_poisoning"
    RUG_PULL = "rug_pull"
    SECRET = "secret"  # category name, not a credential  # nosec B105  # pragma: allowlist secret
    PII = "pii"
    REPUTATION = "reputation"


# OWASP Top 10 for LLM Applications (2025) mapping used in reports.
OWASP = {
    Category.PROMPT_INJECTION: "LLM01",
    Category.HIDDEN_CONTENT: "LLM01",
    Category.EXFILTRATION: "LLM02",
    Category.SECRET: "LLM02",  # pragma: allowlist secret
    Category.PII: "LLM02",
    Category.EXCESSIVE_AGENCY: "LLM06",
    Category.TOOL_POISONING: "LLM03",
    Category.RUG_PULL: "LLM03",
    Category.REPUTATION: "LLM03",
}


@dataclass(frozen=True)
class Segment:
    source: Source
    text: str
    path: Path
    tool_name: str | None = None


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: Category
    severity: Severity
    source: Source
    path: Path
    start: int
    end: int
    evidence: str
    message: str
    tool_name: str | None = None

    @property
    def owasp(self) -> str:
        return OWASP[self.category]

    def to_record(self) -> dict[str, Any]:
        """Audit-safe shape: no raw evidence (it may contain the secret)."""
        return {
            "rule_id": self.rule_id,
            "category": self.category.value,
            "owasp": self.owasp,
            "severity": self.severity.name,
            "source": self.source.value,
            "path": list(self.path),
            "tool_name": self.tool_name,
        }


def clip(text: str, limit: int = 80) -> str:
    """Short single-line evidence snippet for humans."""
    one_line = " ".join(text.split())
    return one_line if len(one_line) <= limit else one_line[: limit - 3] + "..."


def get_at(obj: Any, path: Path) -> Any:
    for key in path:
        obj = obj[key]
    return obj


def set_at(obj: Any, path: Path, value: Any) -> None:
    if not path:
        raise ValueError("empty path")
    parent = get_at(obj, path[:-1])
    parent[path[-1]] = value
