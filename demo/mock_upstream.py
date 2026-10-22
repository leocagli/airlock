"""A fake Anthropic API that echoes what it received.

It shows the audience exactly what reached the "model" after Airlock.
In-process:  create_mock_app()  (the demo uses it via httpx.ASGITransport)
Standalone:  python -m demo.mock_upstream  (listens on 127.0.0.1:8788), then
             AIRLOCK_UPSTREAM=http://127.0.0.1:8788 python -m airlock serve
"""

from __future__ import annotations

import json
import os
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse


def _echo_text(body: dict[str, Any]) -> str:
    tools = [t.get("name") for t in body.get("tools") or [] if isinstance(t, dict)]
    return (
        f"[mock model] I received {len(body.get('messages') or [])} message(s) and "
        f"tools {tools}. Full request as I saw it:\n"
        + json.dumps(body, indent=2, ensure_ascii=False)
    )


def _message(body: dict[str, Any], text: str) -> dict[str, Any]:
    return {
        "id": f"msg_mock_{len(text):06d}",
        "type": "message",
        "role": "assistant",
        "model": body.get("model", "mock"),
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 0, "output_tokens": 0},
    }


def _sse(msg: dict[str, Any]) -> list[bytes]:
    def ev(name: str, data: dict[str, Any]) -> bytes:
        return f"event: {name}\ndata: {json.dumps(data)}\n\n".encode()

    text = msg["content"][0]["text"]
    return [
        ev("message_start", {"type": "message_start",
                             "message": {**msg, "content": [], "stop_reason": None}}),
        ev("content_block_start", {"type": "content_block_start", "index": 0,
                                   "content_block": {"type": "text", "text": ""}}),
        ev("content_block_delta", {"type": "content_block_delta", "index": 0,
                                   "delta": {"type": "text_delta", "text": text}}),
        ev("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ev("message_delta", {"type": "message_delta",
                             "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                             "usage": {"output_tokens": 0}}),
        ev("message_stop", {"type": "message_stop"}),
    ]


def create_mock_app() -> FastAPI:
    app = FastAPI(title="mock-anthropic")
    app.state.received = []  # every body that reached the "model", in order

    @app.post("/v1/messages")
    async def messages(request: Request) -> Response:
        body = await request.json()
        app.state.received.append(body)
        msg = _message(body, _echo_text(body))
        if body.get("stream") is True:
            async def gen():
                for chunk in _sse(msg):
                    yield chunk
            return StreamingResponse(gen(), media_type="text/event-stream")
        return JSONResponse(msg)

    @app.post("/v1/messages/count_tokens")
    async def count_tokens(request: Request) -> dict[str, int]:
        return {"input_tokens": len(await request.body()) // 4}

    @app.get("/v1/models")
    async def models() -> dict[str, Any]:
        return {"data": [{"id": "claude-sonnet-5-5", "type": "model"}], "has_more": False}

    return app


app = create_mock_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("MOCK_PORT", "8788")))
