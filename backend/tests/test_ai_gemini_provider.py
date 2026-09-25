"""Gemini provider adapter tests.

The Gemini response is untrusted input, so the adapter must parse it
defensively, translate the internal message/tool format without weakening it,
never leak the API key, and turn transport/status problems into the narrow
exception types the service maps to client-safe messages. No live Gemini call
is ever made: the HTTP layer is replaced by a mock transport.
"""

import json
from types import SimpleNamespace

import httpx
import pytest
from pydantic import SecretStr

from app.ai import gemini as gemini_module
from app.ai.gemini import GeminiProvider
from app.ai.provider import (
    OpenAIProvider,
    ProviderAuthenticationError,
    ProviderConfigurationError,
    ProviderRateLimited,
    ProviderResponseError,
    ProviderTimeout,
    ProviderToolCall,
    ProviderUnavailable,
    build_provider,
    get_provider,
)

KEY = "unit-test-gemini-key"
MODEL = "test-gemini-model"


@pytest.fixture
def provider_factory(monkeypatch):
    """Build Gemini providers whose HTTP layer is a mock transport."""

    def factory(handler):
        transport = httpx.MockTransport(handler)
        real_client = httpx.Client

        def client(**kwargs):
            kwargs["transport"] = transport
            return real_client(**kwargs)

        monkeypatch.setattr(gemini_module.httpx, "Client", client)
        return GeminiProvider(api_key=KEY, timeout_seconds=5)

    return factory


def ok(content=None, function_calls=None, finish_reason=None):
    """Build a Gemini candidate body.

    ``function_calls`` entries are either a raw ``functionCall`` object or a
    ``(functionCall, thought_signature)`` pair.
    """
    parts = []
    if content is not None:
        parts.append({"text": content})
    for entry in function_calls or []:
        call, signature = entry if isinstance(entry, tuple) else (entry, None)
        part = {"functionCall": call}
        if signature is not None:
            part["thoughtSignature"] = signature
        parts.append(part)
    candidate = {"content": {"parts": parts}}
    if finish_reason:
        candidate["finishReason"] = finish_reason
    return {
        "candidates": [candidate],
        "usageMetadata": {"promptTokenCount": 13, "candidatesTokenCount": 5},
    }


def echo_history(messages, call, result='{"ok": true}'):
    """Emulate the service echoing a tool call and its result into history."""
    return [
        *messages,
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {"name": call.name, "arguments": json.dumps(call.arguments)},
                    "thought_signature": call.thought_signature,
                }
            ],
        },
        {"role": "tool", "tool_call_id": call.id, "content": result},
    ]


def answer(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=ok(content="hello"))


def settings_stub(**overrides):
    base = {
        "AI_PROVIDER": "gemini",
        "AI_REQUEST_TIMEOUT_SECONDS": 20,
        "AI_API_KEY": SecretStr("openai-key"),
        "AI_MODEL": "gpt-4o-mini",
        "GEMINI_API_KEY": SecretStr(KEY),
        "GEMINI_MODEL": MODEL,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_parses_plain_answer(provider_factory):
    provider = provider_factory(answer)
    response = provider.complete(
        messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=100
    )
    assert response.content == "hello"
    assert response.tool_calls == ()
    assert response.prompt_tokens == 13
    assert response.completion_tokens == 5


def test_sends_key_in_header_and_model_in_path(provider_factory):
    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        captured["key_header"] = request.headers.get("x-goog-api-key")
        captured["auth_header"] = request.headers.get("authorization")
        return httpx.Response(200, json=ok(content="ok"))

    provider = provider_factory(handler)
    provider.complete(
        messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=100
    )
    assert captured["url"] == f"{GeminiProvider.api_root}/models/{MODEL}:generateContent"
    assert captured["key_header"] == KEY
    assert captured["auth_header"] is None
    assert KEY not in captured["url"]


def test_translates_system_and_user_messages(provider_factory):
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=ok(content="ok"))

    provider = provider_factory(handler)
    provider.complete(
        messages=[
            {"role": "system", "content": "trusted rules"},
            {"role": "user", "content": "question"},
        ],
        tools=[],
        model=MODEL,
        max_output_tokens=64,
    )
    body = captured["body"]
    assert body["systemInstruction"]["parts"] == [{"text": "trusted rules"}]
    assert body["contents"] == [{"role": "user", "parts": [{"text": "question"}]}]
    assert body["generationConfig"]["maxOutputTokens"] == 64


def test_merges_every_system_message_into_system_instruction(provider_factory):
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=ok(content="ok"))

    provider = provider_factory(handler)
    provider.complete(
        messages=[
            {"role": "system", "content": "rules"},
            {"role": "user", "content": "question"},
            {"role": "system", "content": "budget exhausted"},
        ],
        tools=[],
        model=MODEL,
        max_output_tokens=64,
    )
    assert captured["body"]["systemInstruction"]["parts"] == [
        {"text": "rules"},
        {"text": "budget exhausted"},
    ]


def test_translates_tool_calls_and_results_into_function_parts(provider_factory):
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=ok(content="done"))

    provider = provider_factory(handler)
    provider.complete(
        messages=[
            {"role": "system", "content": "rules"},
            {"role": "user", "content": "question"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "gemini_call_0",
                        "type": "function",
                        "function": {"name": "search_my_events", "arguments": '{"limit": 5}'},
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "gemini_call_0",
                "content": '{"ok": true, "events": []}',
            },
        ],
        tools=[],
        model=MODEL,
        max_output_tokens=64,
    )
    contents = captured["body"]["contents"]
    assert contents[1] == {
        "role": "model",
        "parts": [{"functionCall": {"name": "search_my_events", "args": {"limit": 5}}}],
    }
    assert contents[2] == {
        "role": "user",
        "parts": [
            {"functionResponse": {"name": "search_my_events", "response": {"ok": True, "events": []}}}
        ],
    }


def test_groups_consecutive_tool_results_into_one_content(provider_factory):
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=ok(content="done"))

    provider = provider_factory(handler)
    provider.complete(
        messages=[
            {"role": "user", "content": "question"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {"id": "a", "function": {"name": "search_my_events", "arguments": "{}"}},
                    {"id": "b", "function": {"name": "search_my_alerts", "arguments": "{}"}},
                ],
            },
            {"role": "tool", "tool_call_id": "a", "content": '{"ok": true}'},
            {"role": "tool", "tool_call_id": "b", "content": '{"ok": false}'},
        ],
        tools=[],
        model=MODEL,
        max_output_tokens=64,
    )
    contents = captured["body"]["contents"]
    assert len(contents) == 3
    assert [part["functionResponse"]["name"] for part in contents[2]["parts"]] == [
        "search_my_events",
        "search_my_alerts",
    ]


def test_translates_tools_and_drops_unsupported_schema_keywords(provider_factory):
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=ok(content="ok"))

    provider = provider_factory(handler)
    provider.complete(
        messages=[{"role": "user", "content": "hi"}],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "search_my_events",
                    "description": "Search events.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "limit": {"type": "integer", "maximum": 20, "exclusiveMaximum": 99},
                            "severity": {"type": "string", "enum": ["LOW", "HIGH"]},
                            "nested": {
                                "type": "object",
                                "properties": {"deep": {"type": "string"}},
                                "additionalProperties": False,
                            },
                        },
                        "required": ["limit"],
                        "additionalProperties": False,
                    },
                },
            }
        ],
        model=MODEL,
        max_output_tokens=64,
    )
    declaration = captured["body"]["tools"][0]["functionDeclarations"][0]
    assert declaration["name"] == "search_my_events"
    assert declaration["description"] == "Search events."
    parameters = declaration["parameters"]
    assert "additionalProperties" not in parameters
    assert parameters["required"] == ["limit"]
    assert parameters["properties"]["limit"] == {"type": "integer", "maximum": 20}
    assert parameters["properties"]["severity"] == {"type": "string", "enum": ["LOW", "HIGH"]}
    assert parameters["properties"]["nested"] == {
        "type": "object",
        "properties": {"deep": {"type": "string"}},
    }
    assert captured["body"]["toolConfig"] == {"functionCallingConfig": {"mode": "AUTO"}}


def test_omits_tool_fields_when_no_tools(provider_factory):
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=ok(content="ok"))

    provider = provider_factory(handler)
    provider.complete(
        messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
    )
    assert "tools" not in captured["body"]
    assert "toolConfig" not in captured["body"]


def test_parses_function_calls_with_stable_synthetic_ids(provider_factory):
    def handler(request):
        return httpx.Response(
            200,
            json=ok(
                function_calls=[
                    {"name": "search_my_events", "args": {"limit": 5}},
                    {"name": "search_my_alerts", "args": {}},
                ]
            ),
        )

    provider = provider_factory(handler)
    response = provider.complete(
        messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
    )
    assert [call.id for call in response.tool_calls] == ["gemini_call_0", "gemini_call_1"]
    assert [call.name for call in response.tool_calls] == ["search_my_events", "search_my_alerts"]
    assert response.tool_calls[0].arguments == {"limit": 5}


def test_rejects_model_names_that_are_not_safe_path_segments(provider_factory):
    provider = provider_factory(answer)
    for model in ("../other-model", "models/../../x", "bad name", "", "a" * 100, "gemini;rm -rf /"):
        with pytest.raises(ProviderConfigurationError):
            provider.complete(
                messages=[{"role": "user", "content": "hi"}],
                tools=[],
                model=model,
                max_output_tokens=64,
            )


def test_accepts_models_prefixed_model_name(provider_factory):
    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        return httpx.Response(200, json=ok(content="ok"))

    provider = provider_factory(handler)
    provider.complete(
        messages=[{"role": "user", "content": "hi"}],
        tools=[],
        model=f"models/{MODEL}",
        max_output_tokens=64,
    )
    assert captured["url"] == f"{GeminiProvider.api_root}/models/{MODEL}:generateContent"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"candidates": []},
        {"candidates": "nope"},
        {"candidates": [{}]},
        {"candidates": [{"content": {}}]},
        {"candidates": [{"content": {"parts": "nope"}}]},
        {"candidates": [{"content": {"parts": [{"functionCall": {"args": {}}}]}}]},
        {"candidates": [{"content": {"parts": [{"functionCall": {"name": "t", "args": "bad"}}]}}]},
        {"candidates": [{"content": {"parts": [{"functionCall": {"name": "t", "args": {"k": "v" * 30000}}}]}}]},
    ],
)
def test_rejects_malformed_responses(provider_factory, payload):
    provider = provider_factory(lambda request: httpx.Response(200, json=payload))
    with pytest.raises(ProviderResponseError):
        provider.complete(
            messages=[{"role": "user", "content": "hi"}],
            tools=[],
            model=MODEL,
            max_output_tokens=64,
        )


def test_rejects_blocked_finish_reasons(provider_factory):
    for reason in ("SAFETY", "PROHIBITED_CONTENT", "RECITATION", "MALFORMED_FUNCTION_CALL"):
        provider = provider_factory(
            lambda request, reason=reason: httpx.Response(200, json=ok(content="x", finish_reason=reason))
        )
        with pytest.raises(ProviderResponseError):
            provider.complete(
                messages=[{"role": "user", "content": "hi"}],
                tools=[],
                model=MODEL,
                max_output_tokens=64,
            )


def test_rejects_prompt_blocked_responses(provider_factory):
    provider = provider_factory(
        lambda request: httpx.Response(
            200, json={"promptFeedback": {"blockReason": "SAFETY"}, "candidates": []}
        )
    )
    with pytest.raises(ProviderResponseError):
        provider.complete(
            messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
        )


def test_rejects_too_many_function_calls_in_one_response(provider_factory):
    provider = provider_factory(
        lambda request: httpx.Response(
            200,
            json=ok(function_calls=[{"name": "search_my_events", "args": {}} for _ in range(25)]),
        )
    )
    with pytest.raises(ProviderResponseError):
        provider.complete(
            messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
        )


def test_maps_rate_limited_status(provider_factory):
    provider = provider_factory(lambda request: httpx.Response(429, json={"error": {"message": "quota"}}))
    with pytest.raises(ProviderRateLimited):
        provider.complete(
            messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
        )


@pytest.mark.parametrize("status", [401, 403])
def test_maps_unauthorized_status_to_authentication_error(provider_factory, status):
    provider = provider_factory(lambda request: httpx.Response(status, text="denied"))
    with pytest.raises(ProviderAuthenticationError):
        provider.complete(
            messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
        )


def test_maps_invalid_api_key_message_to_authentication_error(provider_factory):
    provider = provider_factory(
        lambda request: httpx.Response(
            400,
            json={"error": {"code": 400, "status": "INVALID_ARGUMENT", "message": "API key not valid"}},
        )
    )
    with pytest.raises(ProviderAuthenticationError):
        provider.complete(
            messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
        )


def test_maps_unknown_model_to_configuration_error(provider_factory):
    provider = provider_factory(lambda request: httpx.Response(404, json={"error": {"message": "not found"}}))
    with pytest.raises(ProviderConfigurationError):
        provider.complete(
            messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
        )


@pytest.mark.parametrize("status", [400, 500, 503])
def test_maps_other_errors_without_leaking_body(provider_factory, status):
    provider = provider_factory(
        lambda request: httpx.Response(status, text=f"internal detail containing {KEY}")
    )
    with pytest.raises(ProviderUnavailable) as excinfo:
        provider.complete(
            messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
        )
    assert KEY not in str(excinfo.value)


def test_does_not_follow_redirects(provider_factory):
    provider = provider_factory(lambda request: httpx.Response(307, headers={"location": "https://evil.example"}))
    with pytest.raises(ProviderUnavailable):
        provider.complete(
            messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
        )


def test_maps_transport_error(provider_factory):
    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    provider = provider_factory(handler)
    with pytest.raises(ProviderUnavailable):
        provider.complete(
            messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
        )


def test_maps_timeout(provider_factory):
    def handler(request):
        raise httpx.ReadTimeout("too slow", request=request)

    provider = provider_factory(handler)
    with pytest.raises(ProviderTimeout):
        provider.complete(
            messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
        )


def test_rejects_response_that_is_not_json(provider_factory):
    provider = provider_factory(lambda request: httpx.Response(200, text="not json"))
    with pytest.raises(ProviderResponseError):
        provider.complete(
            messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
        )


def test_rejects_request_without_any_user_content(provider_factory):
    provider = provider_factory(answer)
    with pytest.raises(ProviderResponseError):
        provider.complete(
            messages=[{"role": "system", "content": "rules"}], tools=[], model=MODEL, max_output_tokens=64
        )


def test_get_provider_supports_both_providers():
    assert isinstance(get_provider("openai", KEY, 5), OpenAIProvider)
    assert isinstance(get_provider("gemini", KEY, 5), GeminiProvider)
    assert isinstance(get_provider("Gemini", KEY, 5), GeminiProvider)
    for unknown in ("", "  ", "unknown-provider", "openai-compatible", "gemini-proxy"):
        with pytest.raises(ProviderConfigurationError):
            get_provider(unknown, KEY, 5)


def test_build_provider_uses_gemini_key_and_model():
    provider, model = build_provider(settings_stub())
    assert isinstance(provider, GeminiProvider)
    assert model == MODEL


def test_build_provider_uses_openai_key_and_model():
    provider, model = build_provider(settings_stub(AI_PROVIDER="openai"))
    assert isinstance(provider, OpenAIProvider)
    assert model == "gpt-4o-mini"


def test_build_provider_keeps_provider_model_settings_separate():
    with pytest.raises(ProviderConfigurationError):
        build_provider(settings_stub(GEMINI_MODEL="  "))
    with pytest.raises(ProviderConfigurationError):
        build_provider(settings_stub(AI_PROVIDER="openai", AI_MODEL=""))


@pytest.mark.parametrize(
    "overrides",
    [
        {"GEMINI_API_KEY": SecretStr("")},
        {"GEMINI_MODEL": ""},
        {"AI_PROVIDER": "mystery"},
        {"AI_PROVIDER": ""},
    ],
)
def test_build_provider_rejects_incomplete_or_unknown_configuration(overrides):
    with pytest.raises(ProviderConfigurationError):
        build_provider(settings_stub(**overrides))


def test_build_provider_rejects_openai_without_its_own_key():
    with pytest.raises(ProviderConfigurationError):
        build_provider(settings_stub(AI_PROVIDER="openai", AI_API_KEY=SecretStr("  ")))


# --- Gemini 3 thought signatures --------------------------------------------
# Gemini 3 strictly validates thought signatures on the current turn: the first
# functionCall part of every step must carry the signature it was returned with,
# or the request fails with a 400. Parts must be returned exactly as received.


def test_preserves_thought_signature_from_function_call(provider_factory):
    provider = provider_factory(
        lambda request: httpx.Response(
            200,
            json=ok(function_calls=[({"name": "search_my_events", "args": {"limit": 5}}, "sig-alpha")]),
        )
    )
    response = provider.complete(
        messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
    )
    assert response.tool_calls[0].thought_signature == "sig-alpha"


def test_next_request_returns_the_thought_signature(provider_factory):
    """The signature must travel back on the exact part that produced it."""
    captured = []
    responses = [
        httpx.Response(
            200,
            json=ok(function_calls=[({"name": "search_my_events", "args": {"limit": 5}}, "sig-alpha")]),
        ),
        httpx.Response(200, json=ok(content="done")),
    ]

    def handler(request):
        captured.append(json.loads(request.content))
        return responses[len(captured) - 1]

    provider = provider_factory(handler)
    first = provider.complete(
        messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
    )
    call = first.tool_calls[0]

    provider.complete(
        messages=echo_history([{"role": "user", "content": "hi"}], call),
        tools=[],
        model=MODEL,
        max_output_tokens=64,
    )

    model_part = captured[1]["contents"][1]["parts"][0]
    assert model_part["functionCall"] == {"name": "search_my_events", "args": {"limit": 5}}
    assert model_part["thoughtSignature"] == "sig-alpha"


def test_signature_is_sent_back_unchanged_and_unmerged(provider_factory):
    """Signature must ride on its own part, never merged with another part."""
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=ok(content="done"))

    provider = provider_factory(handler)
    provider.complete(
        messages=[
            {"role": "user", "content": "hi"},
            {
                "role": "assistant",
                "content": "Checking now.",
                "tool_calls": [
                    {
                        "id": "gemini_call_0",
                        "function": {"name": "search_my_events", "arguments": "{}"},
                        "thought_signature": "sig-alpha",
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "gemini_call_0", "content": '{"ok": true}'},
        ],
        tools=[],
        model=MODEL,
        max_output_tokens=64,
    )
    parts = captured["body"]["contents"][1]["parts"]
    assert parts == [
        {"text": "Checking now."},
        {
            "functionCall": {"name": "search_my_events", "args": {}},
            "thoughtSignature": "sig-alpha",
        },
    ]


def test_multiple_sequential_tool_calls_preserve_all_signatures(provider_factory):
    """Sequential steps each carry a signature; every one must be returned."""
    captured = []
    responses = [
        httpx.Response(
            200, json=ok(function_calls=[({"name": "search_my_events", "args": {}}, "sig-one")])
        ),
        httpx.Response(
            200, json=ok(function_calls=[({"name": "search_my_alerts", "args": {}}, "sig-two")])
        ),
        httpx.Response(200, json=ok(content="done")),
    ]

    def handler(request):
        captured.append(json.loads(request.content))
        return responses[len(captured) - 1]

    provider = provider_factory(handler)
    history = [{"role": "user", "content": "hi"}]

    first = provider.complete(messages=history, tools=[], model=MODEL, max_output_tokens=64)
    history = echo_history(history, first.tool_calls[0])
    second = provider.complete(messages=history, tools=[], model=MODEL, max_output_tokens=64)
    history = echo_history(history, second.tool_calls[0])
    provider.complete(messages=history, tools=[], model=MODEL, max_output_tokens=64)

    final_contents = captured[-1]["contents"]
    signatures = [
        part["thoughtSignature"]
        for content in final_contents
        for part in content["parts"]
        if "thoughtSignature" in part
    ]
    assert signatures == ["sig-one", "sig-two"]


def test_parallel_function_calls_are_not_interleaved_with_results(provider_factory):
    """Parallel calls must all precede all results, else the API returns 400."""
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=ok(content="done"))

    provider = provider_factory(handler)
    provider.complete(
        messages=[
            {"role": "user", "content": "hi"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "gemini_call_0",
                        "function": {"name": "search_my_events", "arguments": "{}"},
                        "thought_signature": "sig-first",
                    },
                    {"id": "gemini_call_1", "function": {"name": "search_my_alerts", "arguments": "{}"}},
                ],
            },
            {"role": "tool", "tool_call_id": "gemini_call_0", "content": '{"ok": true}'},
            {"role": "tool", "tool_call_id": "gemini_call_1", "content": '{"ok": false}'},
        ],
        tools=[],
        model=MODEL,
        max_output_tokens=64,
    )
    contents = captured["body"]["contents"]
    assert len(contents) == 3
    assert [next(iter(p)) for p in contents[1]["parts"]] == ["functionCall", "functionCall"]
    assert contents[1]["parts"][0]["thoughtSignature"] == "sig-first"
    assert "thoughtSignature" not in contents[1]["parts"][1]
    assert [next(iter(p)) for p in contents[2]["parts"]] == ["functionResponse", "functionResponse"]


def test_absent_signature_is_tolerated_and_omitted(provider_factory):
    """No signature means no key is emitted; we never invent one."""
    provider = provider_factory(
        lambda request: httpx.Response(200, json=ok(function_calls=[{"name": "search_my_events", "args": {}}]))
    )
    response = provider.complete(
        messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
    )
    assert response.tool_calls[0].thought_signature is None


def test_missing_signature_key_is_not_invented_on_replay(provider_factory):
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=ok(content="done"))

    provider = provider_factory(handler)
    provider.complete(
        messages=echo_history(
            [{"role": "user", "content": "hi"}],
            ProviderToolCall(id="gemini_call_0", name="search_my_events", arguments={}),
        ),
        tools=[],
        model=MODEL,
        max_output_tokens=64,
    )
    assert "thoughtSignature" not in captured["body"]["contents"][1]["parts"][0]


def test_missing_signature_400_is_mapped_to_a_safe_error(provider_factory):
    """A Gemini 'missing a thought_signature' 400 must not leak or be misread."""
    upstream = (
        "Function call FC1 in the 1. content block is missing a thought_signature."
    )
    provider = provider_factory(
        lambda request: httpx.Response(
            400, json={"error": {"code": 400, "status": "INVALID_ARGUMENT", "message": upstream}}
        )
    )
    with pytest.raises(ProviderUnavailable) as excinfo:
        provider.complete(
            messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
        )
    assert "thought_signature" not in str(excinfo.value)
    assert "FC1" not in str(excinfo.value)


@pytest.mark.parametrize(
    "signature",
    ["", 123, {"sig": 1}, ["a"], "x" * 9000, True, 1.5],
)
def test_rejects_malformed_thought_signatures(provider_factory, signature):
    part = {"functionCall": {"name": "search_my_events", "args": {}}, "thoughtSignature": signature}
    provider = provider_factory(
        lambda request: httpx.Response(200, json={"candidates": [{"content": {"parts": [part]}}]})
    )
    with pytest.raises(ProviderResponseError):
        provider.complete(
            messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
        )


def test_null_signature_is_treated_as_absent(provider_factory):
    """An explicit null is equivalent to no signature; nothing is invented."""
    provider = provider_factory(
        lambda request: httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "functionCall": {"name": "search_my_events", "args": {}},
                                    "thoughtSignature": None,
                                }
                            ]
                        }
                    }
                ]
            },
        )
    )
    response = provider.complete(
        messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
    )
    assert response.tool_calls[0].thought_signature is None


def test_signature_survives_a_full_multi_turn_loop(provider_factory):
    """Two steps in one turn: both signatures must be present in the last request."""
    captured = []
    responses = [
        httpx.Response(
            200, json=ok(function_calls=[({"name": "search_my_events", "args": {}}, "sig-step-1")])
        ),
        httpx.Response(
            200, json=ok(function_calls=[({"name": "search_my_alerts", "args": {}}, "sig-step-2")])
        ),
        httpx.Response(200, json=ok(content="final answer")),
    ]

    def handler(request):
        captured.append(json.loads(request.content))
        return responses[len(captured) - 1]

    provider = provider_factory(handler)
    history = [{"role": "user", "content": "hi"}]
    for _ in range(3):
        response = provider.complete(messages=history, tools=[], model=MODEL, max_output_tokens=64)
        if not response.tool_calls:
            break
        history = echo_history(history, response.tool_calls[0])

    assert len(captured) == 3
    last = captured[-1]["contents"]
    assert [
        (content["role"], [next(iter(p)) for p in content["parts"]]) for content in last
    ] == [
        ("user", ["text"]),
        ("model", ["functionCall"]),
        ("user", ["functionResponse"]),
        ("model", ["functionCall"]),
        ("user", ["functionResponse"]),
    ]
    assert last[1]["parts"][0]["thoughtSignature"] == "sig-step-1"
    assert last[3]["parts"][0]["thoughtSignature"] == "sig-step-2"


# --- Gemini 3 sampling parameters -------------------------------------------


def test_request_contains_no_sampling_parameters(provider_factory):
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=ok(content="ok"))

    provider = provider_factory(handler)
    provider.complete(
        messages=[{"role": "user", "content": "hi"}], tools=[], model=MODEL, max_output_tokens=64
    )
    config = captured["body"]["generationConfig"]
    assert "temperature" not in config
    assert "topP" not in config
    assert "topK" not in config
    assert "frequencyPenalty" not in config
    assert "presencePenalty" not in config
    assert config == {"maxOutputTokens": 64}


def test_temperature_is_absent_from_every_gemini_request(provider_factory):
    captured = []
    responses = [
        httpx.Response(
            200, json=ok(function_calls=[({"name": "search_my_events", "args": {}}, "sig-1")])
        ),
        httpx.Response(200, json=ok(content="done")),
    ]

    def handler(request):
        captured.append(json.loads(request.content))
        return responses[len(captured) - 1]

    provider = provider_factory(handler)
    history = [{"role": "user", "content": "hi"}]
    first = provider.complete(messages=history, tools=[], model=MODEL, max_output_tokens=64)
    history = echo_history(history, first.tool_calls[0])
    provider.complete(messages=history, tools=[], model=MODEL, max_output_tokens=64)

    assert len(captured) == 2
    for body in captured:
        assert "temperature" not in json.dumps(body)


def test_openai_request_is_unchanged_and_never_carries_a_signature(monkeypatch):
    """OpenAI payloads must not gain Gemini-only fields."""
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {"name": "search_my_events", "arguments": "{}"},
                                }
                            ],
                        }
                    }
                ]
            },
        )

    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    def client(**kwargs):
        kwargs["transport"] = transport
        return real_client(**kwargs)

    monkeypatch.setattr(gemini_module.httpx, "Client", client)

    response = OpenAIProvider(api_key=KEY, timeout_seconds=5).complete(
        messages=[{"role": "user", "content": "hi"}],
        tools=[{"type": "function", "function": {"name": "t", "parameters": {}}}],
        model="test-openai-model",
        max_output_tokens=64,
    )

    assert response.tool_calls[0].thought_signature is None
    assert "temperature" in captured["body"]
    assert "thought_signature" not in json.dumps(captured["body"])
