"""The interface every LLM adapter implements: complete a conversation into JSON for a schema.

Adapters talk plain HTTP (httpx), not vendor SDKs. They never log or print keys, and their
errors carry only the HTTP status and the server's own error type and message.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

EFFORTS = ("low", "medium", "high", "xhigh", "max")
"""`none` turns reasoning off; only OpenAI-compatible servers accept it (local models)."""
Role = Literal["user", "assistant"]


@dataclass(frozen=True)
class Message:
    role: Role
    content: str


@dataclass(frozen=True)
class Completion:
    data: Any
    """The parsed JSON object."""
    stop_reason: str
    elapsed: float
    """Seconds spent in HTTP calls, retries included."""
    usage: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    """Safe to show: for example a server that probably truncated the prompt."""


class LLMError(RuntimeError):
    """A call that failed. The message is safe to show: it never contains a key."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class ConfigError(LLMError):
    """No provider, no model, or a choice the user has to make (several models)."""


class RefusalError(LLMError):
    """The model declined the request."""

    def __init__(self, message: str, category: str | None = None) -> None:
        super().__init__(message)
        self.category = category


Recorder = Callable[[str, Any], None]
"""Receives (request path, response body) of every successful call: used to record fixtures."""


class LLM(Protocol):
    provider: str
    line: str
    """The model family, safe to put in reports (never the model id itself)."""

    @property
    def model(self) -> str: ...

    def complete_json(
        self,
        *,
        system: str,
        messages: Sequence[Message],
        schema: dict[str, Any],
        schema_name: str,
        max_tokens: int = ...,
        effort: str | None = ...,
    ) -> Completion: ...
