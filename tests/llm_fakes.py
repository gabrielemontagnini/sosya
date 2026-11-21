"""Helpers for LLM adapter tests: recorded responses served by an httpx mock transport."""

import json
from pathlib import Path
from typing import Any

import httpx

FIXTURES = Path(__file__).parent / "fixtures" / "llm"
FAKE_KEY = "sk-test-0123456789abcdef-secret"


def fixture(name: str) -> Any:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


class Server:
    """Serve queued responses per path and record every request it receives."""

    def __init__(self) -> None:
        self.queue: dict[str, list[httpx.Response | Exception]] = {}
        self.requests: list[httpx.Request] = []

    def on(self, path: str, *responses: httpx.Response | Any) -> "Server":
        items = self.queue.setdefault(path, [])
        for response in responses:
            if isinstance(response, httpx.Response | Exception):
                items.append(response)
            else:
                items.append(httpx.Response(200, json=response))
        return self

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        pending = self.queue.get(request.url.path) or []
        if not pending:
            return httpx.Response(
                404, json={"error": {"type": "not_found", "message": "no fixture"}}
            )
        item = pending.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def bodies(self, path: str) -> list[dict[str, Any]]:
        return [json.loads(r.content) for r in self.requests if r.url.path == path]


def no_sleep(seconds: float) -> None:
    del seconds
