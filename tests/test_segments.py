import pytest

from airlock.segments import extract_segments
from airlock.types import Source, get_at


def _body():
    return {
        "system": [{"type": "text", "text": "You are a coding agent."}],
        "messages": [
            {"role": "user", "content": "Summarize the page"},
            {
                "role": "assistant",
                "content": [
                    {"type": "thinking", "thinking": "secret thoughts"},
                    {"type": "text", "text": "Fetching it"},
                    {
                        "type": "tool_use",
                        "id": "tu_1",
                        "name": "web_fetch",
                        "input": {
                            "url": "https://example.com",
                            "opts": {"headers": ["a", ""]},
                            "n": 3,
                        },
                    },
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "tu_1",
                        "content": [
                            {"type": "text", "text": "page body"},
                            {"type": "image", "source": {"type": "base64", "data": "AAAA"}},
                        ],
                    },
                    {"type": "tool_result", "tool_use_id": "unknown", "content": "orphan result"},
                    {
                        "type": "document",
                        "source": {"type": "text", "media_type": "text/plain", "data": "doc text"},
                    },
                    {
                        "type": "search_result",
                        "source": "https://x.test",
                        "title": "t",
                        "content": [{"type": "text", "text": "search snippet"}],
                    },
                    {"type": "text", "text": "thanks"},
                ],
            },
        ],
        "tools": [
            {
                "name": "web_fetch",
                "description": "Fetch a URL",
                "input_schema": {
                    "type": "object",
                    "title": "Fetch input",
                    "properties": {
                        "url": {"type": "string", "description": "The URL"},
                        "items": {"type": "array", "items": [{"description": "nested"}]},
                    },
                },
            }
        ],
    }


def test_every_path_resolves_to_its_text():
    body = _body()
    segments = extract_segments(body)
    assert segments
    for seg in segments:
        assert get_at(body, seg.path) == seg.text


def test_sources_and_paths():
    segs = {s.path: s for s in extract_segments(_body())}
    assert segs[("system", 0, "text")].source is Source.SYSTEM
    assert segs[("messages", 0, "content")].source is Source.USER
    assert segs[("messages", 1, "content", 1, "text")].source is Source.ASSISTANT
    url = segs[("messages", 1, "content", 2, "input", "url")]
    assert url.source is Source.TOOL_USE and url.tool_name == "web_fetch"
    assert segs[("messages", 1, "content", 2, "input", "opts", "headers", 0)].text == "a"
    res = segs[("messages", 2, "content", 0, "content", 0, "text")]
    assert res.source is Source.TOOL_RESULT and res.tool_name == "web_fetch"
    orphan = segs[("messages", 2, "content", 1, "content")]
    assert orphan.source is Source.TOOL_RESULT and orphan.tool_name is None
    assert segs[("messages", 2, "content", 2, "source", "data")].source is Source.TOOL_RESULT
    assert segs[("messages", 2, "content", 3, "content", 0, "text")].source is Source.TOOL_RESULT
    assert segs[("messages", 2, "content", 4, "text")].source is Source.USER


def test_tool_definitions():
    segs = {s.path: s for s in extract_segments(_body())}
    for path in [
        ("tools", 0, "name"),
        ("tools", 0, "description"),
        ("tools", 0, "input_schema", "title"),
        ("tools", 0, "input_schema", "properties", "url", "description"),
        ("tools", 0, "input_schema", "properties", "items", "items", 0, "description"),
    ]:
        assert segs[path].source is Source.TOOL_DEFINITION
        assert segs[path].tool_name == "web_fetch"


def test_skips_empty_images_and_thinking():
    texts = [s.text for s in extract_segments(_body())]
    assert "" not in texts
    assert "secret thoughts" not in texts
    assert "AAAA" not in texts


def test_plain_string_system():
    segs = extract_segments({"system": "be nice", "messages": []})
    assert [(s.source, s.path) for s in segs] == [(Source.SYSTEM, ("system",))]


def test_property_named_description_is_still_walked():
    body = {"tools": [{"name": "t", "input_schema": {"properties": {
        "description": {"type": "string", "description": "inner"}}}}]}
    texts = {s.text for s in extract_segments(body)}
    assert "inner" in texts


@pytest.mark.parametrize(
    "body",
    [
        None,
        [],
        "x",
        42,
        {},
        {"messages": None},
        {"messages": "hi"},
        {"messages": [None, 1, "x"]},
        {
            "messages": [
                {
                    "role": "user",
                    "content": [None, 3, {"type": "text"}, {"type": "text", "text": 5}],
                }
            ]
        },
        {
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "tool_result", "content": [None, {"type": "text"}]}],
                }
            ]
        },
        {"messages": [{"role": "assistant", "content": [{"type": "tool_use", "input": None}]}]},
        {"tools": "nope"},
        {"tools": [None, {"name": 3, "input_schema": [1, {"title": ""}]}]},
        {"system": [None, {"type": "text", "text": None}]},
        {"messages": [{"role": "user", "content": [{"type": "document", "source": "bad"}]}]},
    ],
)
def test_malformed_bodies_never_raise(body):
    assert isinstance(extract_segments(body), list)


def test_deeply_nested_input_does_not_blow_up():
    deep = cur = {}
    for _ in range(500):
        cur["k"] = {}
        cur = cur["k"]
    cur["leaf"] = "deep"
    body = {
        "messages": [
            {"role": "assistant", "content": [{"type": "tool_use", "name": "x", "input": deep}]}
        ]
    }
    assert isinstance(extract_segments(body), list)
