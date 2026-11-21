"""OpenAI-compatible Chat Completions over plain HTTP: OpenAI, Ollama, LM Studio, vLLM, OpenRouter.

Structured output uses `response_format` `json_schema` with `strict: true`. A server that
rejects it gets the schema in the system prompt instead, and the JSON is read from the text.
"""

import json
import re
import time
from collections.abc import Callable, Sequence
from typing import Any
from urllib.parse import urlparse

import httpx

from sosya.llm.base import Completion, ConfigError, LLMError, Message, Recorder, RefusalError
from sosya.llm.http import Http, dumps

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MAX_TOKENS = 16000
MAX_TOKENS_CAP = 64000
_FORMAT_WORDS = ("response_format", "json_schema", "schema", "structured")
_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)

TEXT_MODE_INSTRUCTION = (
    "\n\nReply with one JSON object that matches this JSON Schema, and nothing else: no prose, "
    "no code fences.\nJSON Schema:\n"
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
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        recorder: Recorder | None = None,
    ) -> None:
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        headers = {"authorization": f"Bearer {api_key}"} if api_key else {}
        self._http = Http(
            "OpenAI-compatible",
            self.base_url,
            headers,
            secrets=(api_key,) if api_key else (),
            transport=transport,
            sleep=sleep,
        )
        self._model = model
        self._recorder = recorder
        self.text_mode = False
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
    ) -> dict[str, Any]:
        chat = [{"role": m.role, "content": m.content} for m in messages]
        body: dict[str, Any] = {"model": self.model, self._tokens_field: tokens}
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
        del effort  # not portable across OpenAI-compatible servers
        start = self._http.elapsed
        tokens = max_tokens
        while True:
            body = self._body(system, messages, schema, schema_name, tokens)
            try:
                reply = self._call("POST", "/chat/completions", body)
            except LLMError as exc:
                lowered = str(exc).lower()
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
            usage = reply.get("usage") or {}
            return Completion(
                data=data,
                stop_reason=finish,
                elapsed=self._http.elapsed - start,
                usage={k: v for k, v in usage.items() if isinstance(v, int)},
            )
