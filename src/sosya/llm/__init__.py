"""LLM adapters: Anthropic and OpenAI-compatible, chosen from the environment.

Provider: `ANTHROPIC_API_KEY` selects Anthropic; `OPENAI_API_KEY` or `OPENAI_BASE_URL` selects
the OpenAI-compatible adapter. `SOSYA_PROVIDER` (`anthropic` or `openai`) decides when both are
set. Model: `--model`, else `SOSYA_MODEL`, else automatic. Effort: `--effort`, else
`SOSYA_EFFORT`, else the default.
"""

import os
from collections.abc import Mapping

import httpx

from sosya.llm.anthropic import AnthropicLLM
from sosya.llm.base import (
    EFFORTS,
    LLM,
    Completion,
    ConfigError,
    LLMError,
    Message,
    Recorder,
    RefusalError,
)
from sosya.llm.openai import OpenAICompatibleLLM

DEFAULT_EFFORT: str | None = "medium"
"""Chosen from the Gate 2 measurements (2026-11-21): low, medium and high all gave 10/10 valid
plans; medium matched low's latency (about 5.4 s median, 6.3 s p90 for queries and plan) and
high had a worse tail (7.7 s p90)."""


def select(
    model: str | None = None,
    effort: str | None = None,
    *,
    env: Mapping[str, str] | None = None,
    transport: httpx.BaseTransport | None = None,
    recorder: Recorder | None = None,
) -> LLM:
    env = os.environ if env is None else env
    model = model or env.get("SOSYA_MODEL") or None
    effort = effort or env.get("SOSYA_EFFORT") or DEFAULT_EFFORT
    if effort is not None and effort not in EFFORTS:
        raise ConfigError(f"unknown effort {effort!r}: use one of {', '.join(EFFORTS)}")
    anthropic_key = env.get("ANTHROPIC_API_KEY") or None
    openai_key = env.get("OPENAI_API_KEY") or None
    openai_url = env.get("OPENAI_BASE_URL") or None
    wanted = (env.get("SOSYA_PROVIDER") or "").strip().lower()
    if wanted not in ("", "anthropic", "openai"):
        raise ConfigError(f"unknown SOSYA_PROVIDER {wanted!r}: use anthropic or openai")
    use_openai = wanted == "openai" or (not anthropic_key and (openai_key or openai_url))
    if wanted == "anthropic" or (not use_openai and anthropic_key):
        if not anthropic_key:
            raise ConfigError("SOSYA_PROVIDER is anthropic but ANTHROPIC_API_KEY is not set")
        if effort == "none":
            raise ConfigError("effort none is for OpenAI-compatible servers: use low or more")
        return AnthropicLLM(
            anthropic_key,
            model=model,
            effort=effort,
            base_url=env.get("ANTHROPIC_BASE_URL") or None,
            transport=transport,
            recorder=recorder,
        )
    if use_openai:
        return OpenAICompatibleLLM(
            api_key=openai_key,
            base_url=openai_url,
            model=model,
            effort=effort,
            transport=transport,
            recorder=recorder,
        )
    raise ConfigError(
        "no LLM provider is configured: set ANTHROPIC_API_KEY, OPENAI_API_KEY or "
        "OPENAI_BASE_URL. `sosya up` runs any range.yaml without one."
    )


__all__ = [
    "DEFAULT_EFFORT",
    "EFFORTS",
    "LLM",
    "AnthropicLLM",
    "Completion",
    "ConfigError",
    "LLMError",
    "Message",
    "OpenAICompatibleLLM",
    "RefusalError",
    "select",
]
