import json
from pathlib import Path

import httpx
import pytest
from llm_fakes import FAKE_KEY, Server, fixture, no_sleep
from pydantic import BaseModel

from sosya import llm
from sosya.llm import cache
from sosya.llm.anthropic import AnthropicLLM, newest_of_line
from sosya.llm.base import ConfigError, LLMError, Message, RefusalError
from sosya.llm.openai import OpenAICompatibleLLM, extract_json
from sosya.llm.schema import strict_schema

SCHEMA = {
    "type": "object",
    "properties": {"queries": {"type": "array", "items": {"type": "string"}}},
}
ASK = [Message("user", "a struts2 lab")]


def anthropic(server: Server, tmp_path: Path, **kwargs) -> AnthropicLLM:
    return AnthropicLLM(
        FAKE_KEY,
        transport=server.transport,
        sleep=no_sleep,
        cache_path=tmp_path / "models.json",
        **kwargs,
    )


def complete(adapter) -> llm.Completion:
    return adapter.complete_json(system="plan", messages=ASK, schema=SCHEMA, schema_name="queries")


# --- Anthropic: model choice ----------------------------------------------------------------


def test_newest_of_the_line_by_creation_date() -> None:
    assert newest_of_line(fixture("anthropic-models")["data"]) == "test-sonnet-2"
    assert newest_of_line([{"id": "test-opus-1", "created_at": "2026-01-01T00:00:00Z"}]) is None


def test_model_is_listed_once_then_cached(tmp_path: Path) -> None:
    server = Server().on("/v1/models", fixture("anthropic-models"))
    assert anthropic(server, tmp_path).model == "test-sonnet-2"
    assert anthropic(Server(), tmp_path).model == "test-sonnet-2"  # from the cache, no request
    assert len(server.requests) == 1
    assert server.requests[0].headers["x-api-key"] == FAKE_KEY
    assert server.requests[0].headers["anthropic-version"]


def test_model_listing_follows_pages(tmp_path: Path) -> None:
    first = {
        "data": [{"id": "test-opus-1", "created_at": "2026-10-01T00:00:00Z"}],
        "has_more": True,
        "last_id": "test-opus-1",
    }
    second = {
        "data": [{"id": "test-sonnet-1", "created_at": "2026-02-01T00:00:00Z"}],
        "has_more": False,
    }
    server = Server().on("/v1/models", first, second)
    assert anthropic(server, tmp_path).model == "test-sonnet-1"
    assert server.requests[1].url.params["after_id"] == "test-opus-1"


def test_no_model_of_the_line(tmp_path: Path) -> None:
    server = Server().on("/v1/models", {"data": [{"id": "test-opus-1"}], "has_more": False})
    with pytest.raises(ConfigError, match="--model"):
        _ = anthropic(server, tmp_path).model


def test_explicit_model_skips_the_listing(tmp_path: Path) -> None:
    server = Server().on("/v1/messages", fixture("anthropic-message"))
    complete(anthropic(server, tmp_path, model="test-custom-1"))
    assert [r.url.path for r in server.requests] == ["/v1/messages"]


def test_expired_cache_is_ignored(tmp_path: Path) -> None:
    path = tmp_path / "models.json"
    cache.put("k", "test-sonnet-1", path=path, now=0)
    assert cache.get("k", path=path, now=cache.TTL + 1) is None
    assert cache.get("k", path=path, now=10) == "test-sonnet-1"


# --- Anthropic: messages --------------------------------------------------------------------


def test_structured_output_request_and_parse(tmp_path: Path) -> None:
    server = Server().on("/v1/messages", fixture("anthropic-message"))
    result = complete(anthropic(server, tmp_path, model="test-sonnet-2", effort="low"))
    assert result.data == {"queries": ["struts2", "redis"]}
    assert result.usage["output_tokens"] == 18
    (body,) = server.bodies("/v1/messages")
    assert body["output_config"] == {
        "format": {"type": "json_schema", "schema": SCHEMA},
        "effort": "low",
    }
    assert body["system"] == "plan"
    assert body["messages"] == [{"role": "user", "content": "a struts2 lab"}]
    for forbidden in ("temperature", "top_p", "top_k", "thinking", "tools", "tool_choice"):
        assert forbidden not in body
    assert body["messages"][-1]["role"] == "user"  # no assistant prefill


def test_effort_per_call_overrides_the_default(tmp_path: Path) -> None:
    server = Server().on("/v1/messages", fixture("anthropic-message"))
    adapter = anthropic(server, tmp_path, model="test-sonnet-2", effort="high")
    adapter.complete_json(system="s", messages=ASK, schema=SCHEMA, schema_name="q", effort="low")
    assert server.bodies("/v1/messages")[0]["output_config"]["effort"] == "low"


def test_refusal_is_a_clear_error(tmp_path: Path) -> None:
    server = Server().on("/v1/messages", fixture("anthropic-refusal"))
    with pytest.raises(RefusalError, match="declined") as info:
        complete(anthropic(server, tmp_path, model="test-sonnet-2"))
    assert info.value.category == "cyber"


def test_max_tokens_retries_with_more_tokens(tmp_path: Path) -> None:
    server = Server().on(
        "/v1/messages", fixture("anthropic-max-tokens"), fixture("anthropic-message")
    )
    result = complete(anthropic(server, tmp_path, model="test-sonnet-2"))
    assert result.data["queries"] == ["struts2", "redis"]
    first, second = server.bodies("/v1/messages")
    assert second["max_tokens"] == 2 * first["max_tokens"]


def test_invalid_json_answer(tmp_path: Path) -> None:
    reply = fixture("anthropic-message")
    reply["content"] = [{"type": "text", "text": "not json"}]
    server = Server().on("/v1/messages", reply)
    with pytest.raises(LLMError, match="not valid JSON"):
        complete(anthropic(server, tmp_path, model="test-sonnet-2"))


# --- HTTP retries and errors ----------------------------------------------------------------


def test_retries_rate_limits_overload_and_connection_errors(tmp_path: Path) -> None:
    waits: list[float] = []
    server = Server().on(
        "/v1/messages",
        httpx.Response(
            429, headers={"retry-after": "3"}, json={"error": {"type": "rate_limit_error"}}
        ),
        httpx.Response(529, json={"error": {"type": "overloaded_error", "message": "busy"}}),
        httpx.ConnectError("down"),
        fixture("anthropic-message"),
    )
    adapter = AnthropicLLM(
        FAKE_KEY,
        model="test-sonnet-2",
        transport=server.transport,
        sleep=waits.append,
        cache_path=tmp_path / "m.json",
    )
    assert complete(adapter).data["queries"]
    assert waits[0] == 3.0
    assert len(waits) == 3


def test_gives_up_after_the_last_attempt(tmp_path: Path) -> None:
    busy = httpx.Response(503, json={"error": {"type": "api_error", "message": "unavailable"}})
    server = Server().on("/v1/messages", *[busy] * 4)
    with pytest.raises(LLMError, match=r"503.*after 4 attempts"):
        complete(anthropic(server, tmp_path, model="test-sonnet-2"))


def test_client_errors_are_not_retried(tmp_path: Path) -> None:
    server = Server().on(
        "/v1/messages",
        httpx.Response(400, json={"error": {"type": "invalid_request_error", "message": "bad"}}),
    )
    with pytest.raises(LLMError, match="400: invalid_request_error: bad") as info:
        complete(anthropic(server, tmp_path, model="test-sonnet-2"))
    assert info.value.status == 400
    assert len(server.requests) == 1


def test_the_key_never_appears_in_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    echo = {"error": {"type": "authentication_error", "message": f"invalid x-api-key {FAKE_KEY}"}}
    server = Server().on("/v1/messages", httpx.Response(401, json=echo))
    with pytest.raises(LLMError) as info:
        complete(anthropic(server, tmp_path, model="test-sonnet-2"))
    assert FAKE_KEY not in str(info.value)
    assert FAKE_KEY not in repr(info.value)
    captured = capsys.readouterr()
    assert FAKE_KEY not in captured.out + captured.err


# --- OpenAI-compatible ----------------------------------------------------------------------


def openai(server: Server, **kwargs) -> OpenAICompatibleLLM:
    kwargs.setdefault("base_url", "http://localhost:11434/v1")
    return OpenAICompatibleLLM(transport=server.transport, sleep=no_sleep, **kwargs)


def test_openai_single_model_and_strict_schema() -> None:
    server = Server().on("/v1/models", fixture("openai-models-one"))
    server.on("/v1/chat/completions", fixture("openai-chat"))
    adapter = openai(server)
    assert complete(adapter).data == {"queries": ["jenkins"]}
    (body,) = server.bodies("/v1/chat/completions")
    assert body["model"] == "test-local-1"
    assert body["response_format"]["json_schema"] == {
        "name": "queries",
        "schema": SCHEMA,
        "strict": True,
    }
    assert body["messages"][0] == {"role": "system", "content": "plan"}
    assert "max_tokens" in body
    assert "authorization" not in server.requests[0].headers


def test_openai_bearer_and_token_field_for_the_official_api() -> None:
    server = Server().on("/v1/chat/completions", fixture("openai-chat"))
    adapter = openai(server, api_key=FAKE_KEY, base_url="https://api.openai.com/v1", model="test-1")
    complete(adapter)
    assert server.requests[0].headers["authorization"] == f"Bearer {FAKE_KEY}"
    assert "max_completion_tokens" in server.bodies("/v1/chat/completions")[0]


def test_openai_several_models_stop_with_the_list() -> None:
    server = Server().on("/v1/models", fixture("openai-models-many"))
    with pytest.raises(ConfigError) as info:
        _ = openai(server).model
    assert "test-local-1" in str(info.value) and "test-local-2" in str(info.value)
    assert "--model" in str(info.value)


def test_openai_no_models() -> None:
    server = Server().on("/v1/models", {"data": []})
    with pytest.raises(ConfigError, match="no models"):
        _ = openai(server).model


def test_openai_falls_back_to_json_in_text() -> None:
    rejected = httpx.Response(
        400, json={"error": {"message": "response_format json_schema is not supported"}}
    )
    server = Server().on("/v1/chat/completions", rejected, fixture("openai-chat-text"))
    adapter = openai(server, model="test-local-1")
    assert complete(adapter).data == {"queries": ["gitlab"]}
    assert adapter.text_mode
    second = server.bodies("/v1/chat/completions")[1]
    assert "response_format" not in second
    assert (
        json.dumps(SCHEMA, sort_keys=True, separators=(",", ":"))
        in second["messages"][0]["content"]
    )


def test_openai_other_400_is_not_a_fallback() -> None:
    server = Server().on(
        "/v1/chat/completions", httpx.Response(400, json={"error": {"message": "context too long"}})
    )
    with pytest.raises(LLMError, match="context too long"):
        complete(openai(server, model="test-local-1"))


def test_openai_refusal_and_length() -> None:
    server = Server().on("/v1/chat/completions", fixture("openai-refusal"))
    with pytest.raises(RefusalError):
        complete(openai(server, model="test-local-1"))
    cut = {"choices": [{"finish_reason": "length", "message": {"content": '{"q'}}]}
    server = Server().on("/v1/chat/completions", cut, fixture("openai-chat"))
    assert complete(openai(server, model="test-local-1")).data == {"queries": ["jenkins"]}


@pytest.mark.parametrize(
    "text",
    ['{"a": 1}', '```json\n{"a": 1}\n```', 'Sure! {"a": 1} Hope it helps.', '```\n{"a": 1}```'],
)
def test_extract_json(text: str) -> None:
    assert extract_json(text) == {"a": 1}


def test_extract_json_fails_cleanly() -> None:
    with pytest.raises(ValueError):
        extract_json("no json here")


# --- schema ---------------------------------------------------------------------------------


class _Inner(BaseModel):
    name: str
    pattern: str | None = None  # a property called like a keyword stays


class _Outer(BaseModel):
    title: str = ""
    items: list[_Inner]
    count: int = 3


def test_strict_schema_closes_objects_and_drops_constraints() -> None:
    from pydantic import Field

    class Limited(BaseModel):
        word: str = Field(min_length=2, max_length=5, pattern="^[a-z]+$")
        many: list[str] = Field(min_length=1, max_length=8)

    schema = strict_schema(Limited)
    text = json.dumps(schema)
    for dropped in ("minLength", "maxLength", "minItems", "maxItems", '"pattern"', "default"):
        assert dropped not in text
    assert schema["additionalProperties"] is False
    assert schema["required"] == ["word", "many"]

    nested = strict_schema(_Outer)
    inner = nested["$defs"]["_Inner"]
    assert inner["additionalProperties"] is False
    assert inner["required"] == ["name", "pattern"]
    assert "pattern" in inner["properties"]
    assert "title" in nested["properties"]
    assert nested["required"] == ["title", "items", "count"]


# --- provider selection ---------------------------------------------------------------------


def test_select_provider_from_the_environment() -> None:
    assert isinstance(llm.select(env={"ANTHROPIC_API_KEY": FAKE_KEY}), AnthropicLLM)
    assert isinstance(llm.select(env={"OPENAI_BASE_URL": "http://x/v1"}), OpenAICompatibleLLM)
    both = {"ANTHROPIC_API_KEY": FAKE_KEY, "OPENAI_API_KEY": FAKE_KEY}
    assert isinstance(llm.select(env=both), AnthropicLLM)
    assert isinstance(llm.select(env={**both, "SOSYA_PROVIDER": "openai"}), OpenAICompatibleLLM)


def test_select_model_and_effort() -> None:
    env = {"ANTHROPIC_API_KEY": FAKE_KEY, "SOSYA_MODEL": "test-sonnet-9", "SOSYA_EFFORT": "low"}
    chosen = llm.select(env=env)
    assert chosen.model == "test-sonnet-9"
    assert llm.select("test-other-1", env=env).model == "test-other-1"
    with pytest.raises(ConfigError, match="effort"):
        llm.select(effort="turbo", env=env)


def test_select_without_any_provider() -> None:
    with pytest.raises(ConfigError, match="ANTHROPIC_API_KEY"):
        llm.select(env={})
