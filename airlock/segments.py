"""Split an Anthropic Messages API body into origin-tagged Segments.

Every Segment path can be followed with types.get_at / set_at to the exact
string it came from, so the sanitizer can rewrite it in place. The extractor
is defensive: malformed bodies produce fewer segments, never an exception.
Parts it cannot read are reported through the optional `errors` list so the
engine can fail closed instead of forwarding text nobody inspected.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from .types import Path, Segment, Source

_ROLE_SOURCE = {"user": Source.USER, "assistant": Source.ASSISTANT}
_SCHEMA_TEXT_KEYS = ("description", "title")
_TOOL_USE_TYPES = ("tool_use", "server_tool_use", "mcp_tool_use")
_UNTRUSTED_TYPES = ("document", "search_result")
_MAX_DEPTH = 64

Errors = list[tuple[Path, str]]


class DepthLimitExceeded(ValueError):
    """Nested deeper than _MAX_DEPTH: text below that level was not inspected."""


def _report(errors: Errors, path: Path, exc: Exception) -> None:
    if isinstance(exc, DepthLimitExceeded):
        errors.append((path, f"nesting deeper than {_MAX_DEPTH} levels"))
    else:
        errors.append((path, type(exc).__name__))


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _walk_strings(obj: Any, path: Path, depth: int = 0) -> Iterator[tuple[Path, str]]:
    """Every non-empty string leaf inside nested dicts and lists."""
    if depth > _MAX_DEPTH:
        raise DepthLimitExceeded(path)
    if isinstance(obj, str):
        if obj:
            yield path, obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str):
                yield from _walk_strings(value, (*path, key), depth + 1)
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            yield from _walk_strings(value, (*path, i), depth + 1)


def _walk_schema_text(obj: Any, path: Path, depth: int = 0) -> Iterator[tuple[Path, str]]:
    """Every "description" / "title" string inside a JSON schema."""
    if depth > _MAX_DEPTH:
        raise DepthLimitExceeded(path)
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                continue
            if key in _SCHEMA_TEXT_KEYS and _text(value):
                yield (*path, key), value
            elif isinstance(value, (dict, list)):
                yield from _walk_schema_text(value, (*path, key), depth + 1)
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            yield from _walk_schema_text(value, (*path, i), depth + 1)


def _text_blocks(blocks: Any, path: Path, source: Source, tool_name: str | None) -> list[Segment]:
    out: list[Segment] = []
    if not isinstance(blocks, list):
        return out
    for k, block in enumerate(blocks):
        if isinstance(block, dict) and block.get("type") == "text" and _text(block.get("text")):
            out.append(Segment(source, block["text"], (*path, k, "text"), tool_name))
    return out


def _untrusted_block(block: dict[str, Any], path: Path, name: str | None) -> list[Segment]:
    """Documents and search results carry third-party text."""
    if block.get("type") == "document":
        src = block.get("source")
        if not isinstance(src, dict):
            return []
        if src.get("type") == "text" and _text(src.get("data")):
            return [Segment(Source.TOOL_RESULT, src["data"], (*path, "source", "data"), name)]
        if src.get("type") == "content":
            return _text_blocks(
                src.get("content"), (*path, "source", "content"), Source.TOOL_RESULT, name
            )
        return []
    return _text_blocks(block.get("content"), (*path, "content"), Source.TOOL_RESULT, name)


def _tool_result(block: dict[str, Any], path: Path, tool_ids: dict[str, str]) -> list[Segment]:
    tool_id = block.get("tool_use_id")
    name = tool_ids.get(tool_id) if isinstance(tool_id, str) else None
    content = block.get("content")
    if _text(content):
        return [Segment(Source.TOOL_RESULT, content, (*path, "content"), name)]
    out: list[Segment] = []
    if not isinstance(content, list):
        return out
    for k, inner in enumerate(content):
        if not isinstance(inner, dict):
            continue
        inner_path = (*path, "content", k)
        if inner.get("type") == "text" and _text(inner.get("text")):
            out.append(Segment(Source.TOOL_RESULT, inner["text"], (*inner_path, "text"), name))
        elif inner.get("type") in _UNTRUSTED_TYPES:
            out.extend(_untrusted_block(inner, inner_path, name))
    return out


def _block(
    block: dict[str, Any], path: Path, source: Source, tool_ids: dict[str, str]
) -> list[Segment]:
    kind = block.get("type")
    if kind == "text":
        text = _text(block.get("text"))
        return [Segment(source, text, (*path, "text"))] if text else []
    if kind in _TOOL_USE_TYPES:
        name = block.get("name") if isinstance(block.get("name"), str) else None
        if isinstance(block.get("id"), str) and name:
            tool_ids[block["id"]] = name
        return [
            Segment(Source.TOOL_USE, text, p, name)
            for p, text in _walk_strings(block.get("input"), (*path, "input"))
        ]
    if isinstance(kind, str) and kind.endswith("tool_result"):
        return _tool_result(block, path, tool_ids)
    if kind in _UNTRUSTED_TYPES:
        return _untrusted_block(block, path, None)
    return []  # images, thinking, redacted_thinking, unknown types


def _system(body: dict[str, Any], _errors: Errors) -> list[Segment]:
    system = body.get("system")
    if _text(system):
        return [Segment(Source.SYSTEM, system, ("system",))]
    return _text_blocks(system, ("system",), Source.SYSTEM, None)


def _message(message: dict[str, Any], i: int, tool_ids: dict[str, str]) -> list[Segment]:
    source = _ROLE_SOURCE.get(message.get("role"), Source.USER)
    content = message.get("content")
    if _text(content):
        return [Segment(source, content, ("messages", i, "content"))]
    out: list[Segment] = []
    if isinstance(content, list):
        for j, block in enumerate(content):
            if isinstance(block, dict):
                out.extend(_block(block, ("messages", i, "content", j), source, tool_ids))
    return out


def _messages(body: dict[str, Any], errors: Errors) -> list[Segment]:
    out: list[Segment] = []
    messages = body.get("messages")
    if not isinstance(messages, list):
        return out
    tool_ids: dict[str, str] = {}
    for i, message in enumerate(messages):
        if not isinstance(message, dict):
            continue
        # One malformed message must not hide the others from the detectors,
        # and is reported so the engine can fail closed on it.
        try:
            out.extend(_message(message, i, tool_ids))
        except Exception as exc:  # noqa: BLE001 - reported to the caller, not swallowed
            _report(errors, ("messages", i), exc)
    return out


def _tools(body: dict[str, Any], _errors: Errors) -> list[Segment]:
    out: list[Segment] = []
    tools = body.get("tools")
    if not isinstance(tools, list):
        return out
    for k, tool in enumerate(tools):
        if not isinstance(tool, dict):
            continue
        name = tool.get("name") if isinstance(tool.get("name"), str) else None
        for key in ("name", "description"):
            text = _text(tool.get(key))
            if text:
                out.append(Segment(Source.TOOL_DEFINITION, text, ("tools", k, key), name))
        for p, text in _walk_schema_text(tool.get("input_schema"), ("tools", k, "input_schema")):
            out.append(Segment(Source.TOOL_DEFINITION, text, p, name))
    return out


def extract_segments(body: dict[str, Any], errors: Errors | None = None) -> list[Segment]:
    """All inspectable strings of a request body, tagged by origin.

    Never raises. A part that cannot be read (wrong types, nesting deeper than
    _MAX_DEPTH) yields no segments and, when `errors` is given, appends
    (path, reason) to it so the caller can block instead of trusting the gap.
    """
    if not isinstance(body, dict):
        return []
    sink: Errors = [] if errors is None else errors
    out: list[Segment] = []
    for key, part in (("system", _system), ("messages", _messages), ("tools", _tools)):
        try:
            out.extend(part(body, sink))
        except Exception as exc:  # noqa: BLE001 - reported to the caller, not swallowed
            _report(sink, (key,), exc)
    return out
