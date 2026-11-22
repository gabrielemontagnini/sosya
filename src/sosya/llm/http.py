"""A small JSON-over-HTTP client with retries on temporary errors."""

import json
import random
import time
from collections.abc import Callable, Mapping
from typing import Any

import httpx

from sosya.llm.base import LLMError

RETRY_STATUS = frozenset({408, 409, 429, 500, 502, 503, 504, 529})
ATTEMPTS = 4
MAX_WAIT = 30.0
TIMEOUT = httpx.Timeout(300.0, connect=10.0)
LOCAL_TIMEOUT = httpx.Timeout(1800.0, connect=10.0)
"""For a server on this machine: a model on CPU can need many minutes for one answer, and a
timeout would only send the same long request again."""


def _error_text(response: httpx.Response) -> str:
    """The server's error type and message, if the body has them; else the reason phrase."""
    try:
        body = response.json()
    except ValueError:
        return response.reason_phrase or "error"
    error = body.get("error") if isinstance(body, dict) else None
    if isinstance(error, dict):
        kind = error.get("type") or error.get("code") or ""
        message = str(error.get("message") or "")[:300]
        return f"{kind}: {message}" if kind else message
    if isinstance(error, str):
        return error[:300]
    return response.reason_phrase or "error"


def _retry_after(response: httpx.Response) -> float | None:
    value = response.headers.get("retry-after")
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None


class Http:
    def __init__(
        self,
        name: str,
        base_url: str,
        headers: Mapping[str, str],
        *,
        secrets: tuple[str, ...] = (),
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        attempts: int = ATTEMPTS,
        timeout: httpx.Timeout = TIMEOUT,
    ) -> None:
        self.name = name
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers=dict(headers),
            timeout=timeout,
            transport=transport,
        )
        self._secrets = tuple(s for s in secrets if s)
        self._sleep = sleep
        self._attempts = attempts
        self.elapsed = 0.0

    def _scrub(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, "***")
        return text

    def _wait(self, attempt: int, hint: float | None) -> None:
        delay = hint if hint is not None else min(MAX_WAIT, 2.0**attempt) + random.uniform(0, 1)
        self._sleep(min(delay, MAX_WAIT))

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        """Send a request and return the JSON body. Retries temporary failures."""
        problem = ""
        for attempt in range(self._attempts):
            started = time.monotonic()
            try:
                response = self._client.request(method, path, json=body, params=params)
            except httpx.TransportError as exc:
                self.elapsed += time.monotonic() - started
                problem = f"{self.name}: cannot reach the API ({type(exc).__name__})"
                if attempt + 1 < self._attempts:
                    self._wait(attempt, None)
                continue
            self.elapsed += time.monotonic() - started
            if response.status_code < 400:
                try:
                    return response.json()
                except ValueError:
                    raise LLMError(f"{self.name}: the API answered with invalid JSON") from None
            text = self._scrub(_error_text(response))
            problem = f"{self.name} API returned {response.status_code}: {text}"
            if response.status_code not in RETRY_STATUS:
                raise LLMError(problem, response.status_code)
            if response.headers.get("x-should-retry") == "false":
                raise LLMError(problem, response.status_code)
            if attempt + 1 < self._attempts:
                self._wait(attempt, _retry_after(response))
        raise LLMError(self._scrub(problem) + f" (after {self._attempts} attempts)")


def dumps(value: Any) -> str:
    """Stable JSON: the same schema always gives the same bytes, so prompt caching holds."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
