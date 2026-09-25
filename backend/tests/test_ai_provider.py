"""Provider adapter tests.

The provider response is untrusted input, so the adapter must parse it
defensively: never trust the shape, never leak the API key, and translate
transport/status problems into the narrow exception types the service maps to
client-safe messages.
"""

import json

import httpx
import pytest

from app.ai import provider as provider_module
from app.ai.provider import (
    OpenAIProvider,
    ProviderConfigurationError,
    ProviderRateLimited,
    ProviderResponseError,
    ProviderTimeout,
    ProviderUnavailable,
    get_provider,
)

KEY = "unit-test-key"
MODEL = "test-model"


@pytest.fixture
def provider_factory(monkeypatch):
    """Build providers whose HTTP layer is replaced by a mock transport."""

    def factory(handler):
        transport = httpx.MockTransport(handler)
        real_client = httpx.Client

        def client(**kwargs):
            kwargs["transport"] = transport
            return real_client(**kwargs)

        monkeypatch.setattr(provider_module.httpx, "Client", client)
        return OpenAIProvider(api_key=KEY, timeout_seconds=5)

    return factory


def completion(content=None, tool_calls=None):
    message = {"content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    return {
        "choices": [{"message": message}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 7},
    }


def call(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=completion(content="hello"))


def test_parses_plain_answer(provider_factory):
    provider = provider_factory(call)
    response = provider.complete(messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=100)
    assert response.content == "hello"
    assert response.tool_calls == ()
    assert response.prompt_tokens == 11
    assert response.completion_tokens == 7


def test_parses_tool_calls(provider_factory):
    def handler(request):
        return httpx.Response(
            200,
            json=completion(
                tool_calls=[
                    {
                        "id": "call_abc",
                        "type": "function",
                        "function": {"name": "search_my_events", "arguments": '{"limit": 5}'},
                    }
                ]
            ),
        )

    provider = provider_factory(handler)
    response = provider.complete(messages=[], tools=[{}], model=MODEL, max_output_tokens=100)
    assert len(response.tool_calls) == 1
    assert response.tool_calls[0].name == "search_my_events"
    assert response.tool_calls[0].arguments == {"limit": 5}
    assert response.tool_calls[0].id == "call_abc"


def test_sends_bearer_key_and_declared_tools(provider_factory):
    captured = {}

    def handler(request):
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=completion(content="ok"))

    provider = provider_factory(handler)
    provider.complete(
        messages=[{"role": "user", "content": "hi"}],
        tools=[{"type": "function", "function": {"name": "t", "parameters": {}}}],
        model=MODEL,
        max_output_tokens=100,
    )
    assert captured["auth"] == f"Bearer {KEY}"
    assert captured["body"]["model"] == MODEL
    assert captured["body"]["max_tokens"] == 100
    assert captured["body"]["tools"][0]["function"]["name"] == "t"
    assert captured["body"]["tool_choice"] == "auto"


def test_omits_tool_fields_when_no_tools(provider_factory):
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=completion(content="ok"))

    provider = provider_factory(handler)
    provider.complete(messages=[], tools=[], model=MODEL, max_output_tokens=100)
    assert "tools" not in captured["body"]
    assert "tool_choice" not in captured["body"]


@pytest.mark.parametrize(
    "payload",
    [
        {"choices": []},
        {"choices": [{"message": {"content": {"nested": "object"}}}]},
        {"choices": [{"message": {"tool_calls": [{"id": "x", "function": {"name": "t", "arguments": "not json"}}]}}]},
        {"choices": [{"message": {"tool_calls": [{"id": "x", "function": {"name": "t", "arguments": "[1,2]"}}]}}]},
        {"choices": [{"message": {"tool_calls": [{"function": {"name": "t", "arguments": "{}"}}]}}]},
        {"choices": [{"message": {"tool_calls": [{"id": "x", "function": {"arguments": "{}"}}]}}]},
        {"choices": [{"message": {"tool_calls": [{"id": "x", "function": {"name": "t", "arguments": "{" * 20000}}]}}]},
    ],
)
def test_rejects_malformed_responses(provider_factory, payload):
    provider = provider_factory(lambda request: httpx.Response(200, json=payload))
    with pytest.raises(ProviderResponseError):
        provider.complete(messages=[], tools=[], model=MODEL, max_output_tokens=100)


def test_maps_rate_limited_status(provider_factory):
    provider = provider_factory(lambda request: httpx.Response(429, json={"error": "slow down"}))
    with pytest.raises(ProviderRateLimited):
        provider.complete(messages=[], tools=[], model=MODEL, max_output_tokens=100)


@pytest.mark.parametrize("status", [400, 401, 403, 404, 500, 503])
def test_maps_error_status_without_leaking_body(provider_factory, status):
    provider = provider_factory(
        lambda request: httpx.Response(status, text="sk-secret-internal-detail")
    )
    with pytest.raises(ProviderUnavailable) as excinfo:
        provider.complete(messages=[], tools=[], model=MODEL, max_output_tokens=100)
    assert "sk-secret" not in str(excinfo.value)


def test_maps_transport_error(provider_factory):
    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    provider = provider_factory(handler)
    with pytest.raises(ProviderUnavailable):
        provider.complete(messages=[], tools=[], model=MODEL, max_output_tokens=100)


def test_maps_timeout(provider_factory):
    def handler(request):
        raise httpx.ReadTimeout("too slow", request=request)

    provider = provider_factory(handler)
    with pytest.raises(ProviderTimeout):
        provider.complete(messages=[], tools=[], model=MODEL, max_output_tokens=100)


def test_get_provider_supports_openai_and_rejects_unknown():
    assert isinstance(get_provider("openai", KEY, 5), OpenAIProvider)
    assert isinstance(get_provider("OpenAI", KEY, 5), OpenAIProvider)
    with pytest.raises(ProviderConfigurationError):
        get_provider("unknown-provider", KEY, 5)
