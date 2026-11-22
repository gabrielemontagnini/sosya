"""OpenAI-compatible Chat Completions over plain HTTP: OpenAI, Ollama, LM Studio, vLLM, OpenRouter.

Structured output uses `response_format` `json_schema` with `strict: true`. A server that
rejects it gets the schema in the system prompt instead, and the JSON is read from the text.

The effort goes out as `reasoning_effort` (`xhigh` and `max` become `high`). A server that
rejects the field gets requests without it.

Some servers (Ollama) cut a prompt longer than their context window without an error. When the
reported `prompt_tokens` is far below an estimate of what was sent, the completion carries a
warning.
"""

import ipaddress
import json
import re
import time
from collections.abc import Callable, Sequence
from typing import Any
from urllib.parse import urlparse

import httpx

from sosya.llm.base import Completion, ConfigError, LLMError, Message, Recorder, RefusalError
from sosya.llm.http import LOCAL_TIMEOUT, TIMEOUT, Http, dumps

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MAX_TOKENS = 16000
MAX_TOKENS_CAP = 64000
_FORMAT_WORDS = ("response_format", "json_schema", "schema", "structured")
REASONING_EFFORT = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "xhigh": "high",
    "max": "high",
}
CHARS_PER_TOKEN = 4
"""A rough estimate, on the low side for JSON and for text that is not English."""
TRUNCATION_RATIO = 0.5
TRUNCATION_MIN_TOKENS = 1000
_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)

TEXT_MODE_INSTRUCTION = (
    "\n\nReply with one JSON object that matches this JSON Schema, and nothing else: no prose, "
    "no code fences.\nJSON Schema:\n"
)


def is_local(base_url: str) -> bool:
    """True for a server on this machine (loopback, or the Docker host from a container)."""
    host = urlparse(base_url).hostname or ""
    if host in ("localhost", "host.docker.internal"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def truncation_warning(sent_chars: int, prompt_tokens: int | None) -> str | None:
    """A warning when the server read far fewer prompt tokens than were sent."""
    estimate = sent_chars // CHARS_PER_TOKEN
    if prompt_tokens is None or estimate < TRUNCATION_MIN_TOKENS:
        return None
    if prompt_tokens >= estimate * TRUNCATION_RATIO:
        return None
    return (
        f"the server read {prompt_tokens} prompt tokens of about {estimate} sent: it probably "
        "truncated the prompt. Raise its context size (for Ollama: OLLAMA_CONTEXT_LENGTH or "
        "num_ctx)"
    )


def extract_json(text: str) -> Any:
    """The JSON object in a reply: the whole text, a fenced block, or the first {...} span."""
    text = text.strip()
    candidates = [text, *(m.strip() for m in _FENCE.findall(text))]
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        candidates.append(text[start : end + 1])
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except ValueError:
            continue
    raise ValueError("no JSON object in the reply")


class OpenAICompatibleLLM:
    provider = "openai-compatible"
    line = "custom"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        effort: str | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        recorder: Recorder | None = None,
    ) -> None:
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.effort = effort
        headers = {"authorization": f"Bearer {api_key}"} if api_key else {}
        self._http = Http(
            "OpenAI-compatible",
            self.base_url,
            headers,
            secrets=(api_key,) if api_key else (),
            transport=transport,
            sleep=sleep,
            timeout=LOCAL_TIMEOUT if is_local(self.base_url) else TIMEOUT,
        )
        self._model = model
        self._recorder = recorder
        self.text_mode = False
        self.reasoning = True
        """False once the server rejected `reasoning_effort`."""
        host = urlparse(self.base_url).hostname or ""
        self._tokens_field = "max_completion_tokens" if host == "api.openai.com" else "max_tokens"

    def _call(self, method: str, path: str, body: Any = None) -> Any:
        reply = self._http.request(method, path, body=body)
        if self._recorder:
            self._recorder(path, reply)
        return reply

    @property
    def model(self) -> str:
        if self._model is None:
            listing = self._call("GET", "/models")
            ids = sorted(
                str(item["id"])
                for item in (listing.get("data") or [])
                if isinstance(item, dict) and "id" in item
            )
            if not ids:
                raise ConfigError(f"the endpoint {self.base_url} lists no models")
            if len(ids) > 1:
                raise ConfigError(
                    f"the endpoint {self.base_url} lists {len(ids)} models; choose one with "
                    "--model or SOSYA_MODEL:\n  " + "\n  ".join(ids)
                )
            self._model = ids[0]
        return self._model

    def _body(
        self,
        system: str,
        messages: Sequence[Message],
        schema: dict[str, Any],
        schema_name: str,
        tokens: int,
        effort: str | None,
    ) -> dict[str, Any]:
        chat = [{"role": m.role, "content": m.content} for m in messages]
        body: dict[str, Any] = {"model": self.model, self._tokens_field: tokens}
        if effort and self.reasoning:
            body["reasoning_effort"] = REASONING_EFFORT[effort]
        if self.text_mode:
            body["messages"] = [
                {"role": "system", "content": system + TEXT_MODE_INSTRUCTION + dumps(schema)},
                *chat,
            ]
        else:
            body["messages"] = [{"role": "system", "content": system}, *chat]
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": schema_name, "schema": schema, "strict": True},
            }
        return body

    def complete_json(
        self,
        *,
        system: str,
        messages: Sequence[Message],
        schema: dict[str, Any],
        schema_name: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        effort: str | None = None,
    ) -> Completion:
        chosen_effort = effort or self.effort
        start = self._http.elapsed
        tokens = max_tokens
        while True:
            body = self._body(system, messages, schema, schema_name, tokens, chosen_effort)
            try:
                reply = self._call("POST", "/chat/completions", body)
            except LLMError as exc:
                lowered = str(exc).lower()
                if (
                    "reasoning_effort" in body
                    and exc.status in (400, 422)
                    and "reasoning" in lowered
                ):
                    self.reasoning = False
                    continue
                if (
                    not self.text_mode
                    and exc.status in (400, 422)
                    and any(word in lowered for word in _FORMAT_WORDS)
                ):
                    self.text_mode = True
                    continue
                raise
            choices = reply.get("choices") or []
            if not choices:
                raise LLMError("the endpoint returned no choices")
            choice = choices[0]
            message = choice.get("message") or {}
            if message.get("refusal"):
                raise RefusalError(f"the model declined to plan this range: {message['refusal']}")
            finish = str(choice.get("finish_reason") or "")
            if finish == "length":
                if tokens >= MAX_TOKENS_CAP:
                    raise LLMError(f"the answer did not fit in {tokens} output tokens")
                tokens = min(tokens * 2, MAX_TOKENS_CAP)
                continue
            try:
                data = extract_json(str(message.get("content") or ""))
            except ValueError:
                raise LLMError(f"the {schema_name} answer is not valid JSON") from None
            usage = {k: v for k, v in (reply.get("usage") or {}).items() if isinstance(v, int)}
            sent = sum(len(m["content"]) for m in body["messages"])
            warning = truncation_warning(sent, usage.get("prompt_tokens"))
            return Completion(
                data=data,
                stop_reason=finish,
                elapsed=self._http.elapsed - start,
                usage=usage,
                warnings=[warning] if warning else [],
            )
