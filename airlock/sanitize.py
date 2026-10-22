"""Rewrite a request body so flagged content never reaches the model.

Text findings are replaced in place (span by span, from the end backwards so
offsets stay valid). Findings on tools[k] quarantine the whole tool.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from .types import Category, Finding, get_at

# Unicode tag block, bidi overrides / isolates, zero-width characters.
INVISIBLE_RE = re.compile(
    "[\U000e0000-\U000e007f\u202a-\u202e\u2066-\u2069\u200b\u200c\u200d\u2060\ufeff]"
)
INVISIBLE_RULES = frozenset({"HID-UNICODE-TAGS", "HID-ZERO-WIDTH", "HID-BIDI"})
STRIP_ONLY_RULES = frozenset({"HID-ZERO-WIDTH", "HID-BIDI"})
_MASK_CATEGORIES = (Category.SECRET, Category.PII)


def strip_invisible(text: str) -> str:
    """Remove every invisible, tag or bidi control character."""
    return INVISIBLE_RE.sub("", text)


def _label(finding: Finding) -> str:
    if finding.category in _MASK_CATEGORIES:
        return f"[REDACTED:{finding.rule_id}]"
    return f"[removed by Airlock: {finding.rule_id}]"


def _merge(findings: list[Finding], length: int) -> list[tuple[int, int, str]]:
    """Merge overlapping spans; a secret mask wins over a removal label."""
    spans = sorted(
        (max(0, int(f.start)), min(length, int(f.end)), i) for i, f in enumerate(findings)
    )
    merged: list[list[Any]] = []
    for start, end, i in spans:
        if end <= start:
            continue
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
            if findings[i].category in _MASK_CATEGORIES:
                merged[-1][2] = findings[i]
        else:
            merged.append([start, end, findings[i]])
    return [(s, e, _label(f)) for s, e, f in merged]


def _rewrite(text: str, findings: list[Finding]) -> str:
    # Scattered zero-width / bidi chars span visible text: strip, do not label.
    labelled = [f for f in findings if f.rule_id not in STRIP_ONLY_RULES]
    out = text
    for start, end, label in reversed(_merge(labelled, len(text))):
        out = out[:start] + label + out[end:]
    if any(f.rule_id in INVISIBLE_RULES for f in findings):
        out = strip_invisible(out)
    return out


def sanitize(
    body: dict[str, Any],
    findings: list[Finding],
    errors: list[tuple[tuple, str]] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Return (sanitized deep copy, names of quarantined tools in order).

    Never raises. A finding that cannot be applied (stale path, non-string
    target, body that cannot be copied) is reported in `errors` as
    (path, reason): the engine then fails closed instead of forwarding the span.
    """
    try:
        new_body = copy.deepcopy(body)
    except Exception as exc:  # noqa: BLE001 - reported to the caller, not swallowed
        if errors is not None:
            errors.append(((), type(exc).__name__))
        return body, []
    if not isinstance(new_body, dict):
        return new_body, []

    tools = new_body.get("tools")
    quarantine: set[int] = set()
    by_path: dict[tuple, list[Finding]] = {}
    for f in findings or []:
        path = tuple(getattr(f, "path", ()) or ())
        if len(path) >= 2 and path[0] == "tools" and isinstance(path[1], int):
            if isinstance(tools, list) and 0 <= path[1] < len(tools):
                quarantine.add(path[1])
            continue
        if path:
            by_path.setdefault(path, []).append(f)

    for path, group in by_path.items():
        try:
            parent = get_at(new_body, path[:-1])
            text = parent[path[-1]]
            if not isinstance(text, str):
                raise TypeError("redaction target is not a string")
            parent[path[-1]] = _rewrite(text, group)
        except Exception as exc:  # noqa: BLE001 - reported to the caller, not swallowed
            if errors is not None:
                errors.append((path, type(exc).__name__))

    names: list[str] = []
    if quarantine and isinstance(tools, list):
        kept = []
        for k, tool in enumerate(tools):
            if k in quarantine:
                name = tool.get("name") if isinstance(tool, dict) else None
                names.append(name if isinstance(name, str) else f"tools[{k}]")
            else:
                kept.append(tool)
        new_body["tools"] = kept
        choice = new_body.get("tool_choice")
        if (
            isinstance(choice, dict)
            and choice.get("type") == "tool"
            and choice.get("name") in names
        ):
            new_body["tool_choice"] = {"type": "auto"}
    return new_body, names
