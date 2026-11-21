"""Anthropic Messages API over plain HTTP, with JSON-schema structured output.

Structured output uses `output_config.format` (`json_schema`). The request never sets
`temperature`, `top_p`, `top_k`, `thinking` or an assistant prefill: current models reject them.
"""

import json
import time
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from sosya.llm import cache
from sosya.llm.base import Completion, ConfigError, LLMError, Message, Recorder, RefusalError
from sosya.llm.http import Http

DEFAULT_BASE_URL = "https://api.anthropic.com"
API_VERSION = "2023-06-01"
LINE = "sonnet"
"""The model line picked automatically when no model is given."""
DEFAULT_MAX_TOKENS = 16000
MAX_TOKENS_CAP = 64000


def _created(item: dict[str, Any]) -> datetime:
    try:
        return datetime.fromisoformat(str(item.get("created_at", "")).replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=None)


def newest_of_line(models: list[dict[str, Any]], line: str = LINE) -> str | None:
    """The most recent model whose id belongs to `line`, by `created_at`."""
    candidates = [m for m in models if line in str(m.get("id", "")).lower()]
    if not candidates:
        return None
    aware = [m for m in candidates if _created(m).tzinfo is not None]
    pool = aware or candidates
    return str(max(pool, key=lambda m: (_created(m), str(m["id"])))["id"])


class AnthropicLLM:
    provider = "anthropic"
    line = LINE

    def __init__(
        self,
        api_key: str,
        *,
        model: str | None = None,
        effort: str | None = None,
        base_url: str | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        cache_path: Path | None = None,
        recorder: Recorder | None = None,
    ) -> None:
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.effort = effort
        self._http = Http(
            "Anthropic",
            self.base_url,
            {"x-api-key": api_key, "anthropic-version": API_VERSION},
            secrets=(api_key,),
            transport=transport,
            sleep=sleep,
        )
        self._model = model
        self._cache_path = cache_path
        self._recorder = recorder
        if model is None:
            self.line = LINE
        else:
            self.line = LINE if LINE in model.lower() else "custom"

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        body = self._http.request("GET", path, params=params)
        if self._recorder:
            self._recorder(path, body)
        return body

    def list_models(self) -> list[dict[str, Any]]:
        models: list[dict[str, Any]] = []
        params: dict[str, Any] = {"limit": 1000}
        while True:
            page = self._get("/v1/models", params)
            data = page.get("data") or []
            models.extend(item for item in data if isinstance(item, dict) and "id" in item)
            if not page.get("has_more") or not data:
                return models
            params = {"limit": 1000, "after_id": page.get("last_id") or data[-1]["id"]}

    @property
    def model(self) -> str:
        if self._model is None:
            key = f"{self.provider} {self.base_url}"
            chosen = cache.get(key, path=self._cache_path)
            if chosen is None:
                chosen = newest_of_line(self.list_models())
                if chosen is None:
                    raise ConfigError(
                        f"no {LINE} model is listed for this API key: choose one with --model "
                        "or SOSYA_MODEL"
                    )
                cache.put(key, chosen, path=self._cache_path)
            self._model = chosen
        return self._model

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
        output_config: dict[str, Any] = {"format": {"type": "json_schema", "schema": schema}}
        chosen_effort = effort or self.effort
        if chosen_effort:
            output_config["effort"] = chosen_effort
        start = self._http.elapsed
        tokens = max_tokens
        while True:
            body = {
                "model": self.model,
                "max_tokens": tokens,
                "system": system,
                "messages": [{"role": m.role, "content": m.content} for m in messages],
                "output_config": output_config,
            }
            reply = self._http.request("POST", "/v1/messages", body=body)
            if self._recorder:
                self._recorder("/v1/messages", reply)
            stop = str(reply.get("stop_reason") or "")
            if stop == "refusal":
                details = reply.get("stop_details") or {}
                category = details.get("category") if isinstance(details, dict) else None
                raise RefusalError(
                    "the model declined to plan this range"
                    + (f" (category: {category})" if category else ""),
                    category,
                )
            if stop == "max_tokens":
                if tokens >= MAX_TOKENS_CAP:
                    raise LLMError(f"the answer did not fit in {tokens} output tokens")
                tokens = min(tokens * 2, MAX_TOKENS_CAP)
                continue
            text = "".join(
                block.get("text", "")
                for block in reply.get("content") or []
                if isinstance(block, dict) and block.get("type") == "text"
            )
            try:
                data = json.loads(text)
            except ValueError:
                raise LLMError(f"the {schema_name} answer is not valid JSON") from None
            usage = reply.get("usage") or {}
            return Completion(
                data=data,
                stop_reason=stop,
                elapsed=self._http.elapsed - start,
                usage={k: v for k, v in usage.items() if isinstance(v, int)},
            )
