"""Google Gemini adapter for the Security Assistant provider abstraction.

Speaks the official Gemini Developer API over REST using the same ``AIProvider``
contract as the OpenAI adapter. The API key and model come only from trusted
backend configuration, the request timeout is bounded, redirects are not
followed, and every failure is translated into the shared provider error types
so the service layer can return safe, generic messages.

The adapter converts between the internal OpenAI-shaped message/tool format and
Gemini's ``systemInstruction`` / ``contents`` / ``functionDeclarations`` format.
It never changes the tool definitions themselves: authorization, argument
validation and result limits are always enforced server-side.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from app.ai.provider import (
    ProviderAuthenticationError,
    ProviderConfigurationError,
    ProviderRateLimited,
    ProviderResponse,
    ProviderResponseError,
    ProviderTimeout,
    ProviderToolCall,
    ProviderUnavailable,
)

API_ROOT = "https://generativelanguage.googleapis.com/v1beta"

MODEL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_TOOL_CALLS_PER_RESPONSE = 20
MAX_ARGUMENT_CHARS = 20000
MAX_ARGUMENT_KEYS = 64
MAX_THOUGHT_SIGNATURE_CHARS = 8192
UNKNOWN_TOOL_NAME = "unknown_tool"

BLOCKED_FINISH_REASONS = frozenset(
    {
        "SAFETY",
        "PROHIBITED_CONTENT",
        "BLOCKLIST",
        "SPII",
        "IMAGE_SAFETY",
        "RECITATION",
        "MALFORMED_FUNCTION_CALL",
        "UNEXPECTED_TOOL_CALL",
    }
)

SUPPORTED_SCHEMA_KEYS = frozenset(
    {
        "type",
        "format",
        "description",
        "nullable",
        "enum",
        "items",
        "properties",
        "required",
        "anyOf",
        "minimum",
        "maximum",
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
    }
)
NUMERIC_SCHEMA_KEYS = frozenset(
    {"minimum", "maximum", "minItems", "maxItems", "minLength", "maxLength"}
)


class GeminiProvider:
    """``AIProvider`` implementation backed by Gemini ``generateContent``."""

    api_root = API_ROOT

    def __init__(self, api_key: str, timeout_seconds: float) -> None:
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds

    def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        model: str,
        max_output_tokens: int,
    ) -> ProviderResponse:
        model_name = _validate_model(model)
        system_parts, contents = _to_gemini_contents(messages)
        if not contents:
            raise ProviderResponseError

        payload: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {"maxOutputTokens": int(max_output_tokens)},
        }
        if system_parts:
            payload["systemInstruction"] = {"parts": system_parts}
        declarations = _function_declarations(tools)
        if declarations:
            payload["tools"] = [{"functionDeclarations": declarations}]
            payload["toolConfig"] = {"functionCallingConfig": {"mode": "AUTO"}}

        headers = {
            "x-goog-api-key": self._api_key,
            "Content-Type": "application/json",
        }
        url = f"{self.api_root}/models/{model_name}:generateContent"

        try:
            with httpx.Client(timeout=self._timeout_seconds, follow_redirects=False) as client:
                response = client.post(url, headers=headers, json=payload)
        except httpx.TimeoutException as exc:
            raise ProviderTimeout from exc
        except httpx.RequestError as exc:
            raise ProviderUnavailable from exc

        if response.status_code == 429:
            raise ProviderRateLimited
        if 300 <= response.status_code < 400:
            raise ProviderUnavailable
        if response.status_code >= 400:
            _raise_for_error_status(response)

        try:
            body = response.json()
        except ValueError as exc:
            raise ProviderResponseError from exc
        return _parse_response(body)


def _validate_model(model: str) -> str:
    name = (model or "").strip()
    if name.startswith("models/"):
        name = name[len("models/") :]
    if not MODEL_NAME_PATTERN.match(name):
        raise ProviderConfigurationError
    return name


def _as_text(content: Any) -> str:
    return content if isinstance(content, str) else ""


def _parse_arguments(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        parsed = raw
    elif isinstance(raw, str) and raw:
        try:
            decoded = json.loads(raw)
        except ValueError:
            return {}
        if not isinstance(decoded, dict):
            return {}
        parsed = decoded
    else:
        return {}
    if len(parsed) > MAX_ARGUMENT_KEYS:
        return {}
    return parsed


def _function_response_payload(content: Any) -> dict[str, Any]:
    text = _as_text(content)
    if text:
        try:
            decoded = json.loads(text)
        except ValueError:
            return {"result": text[:2000]}
        if isinstance(decoded, dict):
            return decoded
    return {"result": text[:2000]}


def _to_gemini_contents(
    messages: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Translate internal messages into Gemini system parts and contents."""
    system_parts: list[dict[str, Any]] = []
    contents: list[dict[str, Any]] = []
    call_names: dict[str, str] = {}

    for message in messages:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        content = message.get("content")

        if role == "system":
            text = _as_text(content)
            if text:
                system_parts.append({"text": text})
            continue

        if role == "user":
            text = _as_text(content)
            if text:
                contents.append({"role": "user", "parts": [{"text": text}]})
            continue

        if role == "assistant":
            parts: list[dict[str, Any]] = []
            text = _as_text(content)
            if text:
                parts.append({"text": text})
            raw_calls = message.get("tool_calls")
            for raw_call in raw_calls if isinstance(raw_calls, list) else []:
                if not isinstance(raw_call, dict):
                    continue
                function = raw_call.get("function")
                if not isinstance(function, dict):
                    continue
                name = function.get("name")
                if not isinstance(name, str) or not name:
                    continue
                call_id = raw_call.get("id")
                if isinstance(call_id, str) and call_id:
                    call_names[call_id] = name
                part: dict[str, Any] = {
                    "functionCall": {"name": name, "args": _parse_arguments(function.get("arguments"))}
                }
                signature = raw_call.get("thought_signature")
                if isinstance(signature, str) and signature:
                    part["thoughtSignature"] = signature
                parts.append(part)
            if parts:
                contents.append({"role": "model", "parts": parts})
            continue

        if role == "tool":
            call_id = message.get("tool_call_id")
            name = call_names.get(call_id, UNKNOWN_TOOL_NAME) if isinstance(call_id, str) else UNKNOWN_TOOL_NAME
            part = {
                "functionResponse": {
                    "name": name,
                    "response": _function_response_payload(content),
                }
            }
            if (
                contents
                and contents[-1]["role"] == "user"
                and all("functionResponse" in existing for existing in contents[-1]["parts"])
            ):
                contents[-1]["parts"].append(part)
            else:
                contents.append({"role": "user", "parts": [part]})
            continue

    return system_parts, contents


def _sanitize_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Reduce a JSON/OpenAPI schema to the subset Gemini accepts.

    Unsupported keywords such as ``additionalProperties`` are dropped. The tools
    re-validate every argument server-side, so this only affects model-side
    guidance, never authorization or validation.
    """
    clean: dict[str, Any] = {}
    for key in SUPPORTED_SCHEMA_KEYS:
        if key not in schema:
            continue
        value = schema[key]
        if key == "properties":
            if isinstance(value, dict):
                clean[key] = {
                    str(name): _sanitize_schema(sub)
                    for name, sub in value.items()
                    if isinstance(sub, dict)
                }
        elif key in ("items", "anyOf"):
            if key == "items" and isinstance(value, dict):
                clean[key] = _sanitize_schema(value)
            elif isinstance(value, list):
                clean[key] = [_sanitize_schema(item) for item in value if isinstance(item, dict)]
        elif key in ("required", "enum"):
            if isinstance(value, list):
                clean[key] = [item for item in value if isinstance(item, (str, int, float, bool))]
        elif key in NUMERIC_SCHEMA_KEYS:
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                clean[key] = value
        elif key == "nullable":
            if isinstance(value, bool):
                clean[key] = value
        elif isinstance(value, str):
            clean[key] = value
    clean.setdefault("type", "string")
    return clean


def _function_declarations(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    declarations: list[dict[str, Any]] = []
    for tool in tools if isinstance(tools, list) else []:
        if not isinstance(tool, dict):
            continue
        function = tool.get("function")
        if not isinstance(function, dict):
            continue
        name = function.get("name")
        if not isinstance(name, str) or not name or len(name) > 100:
            continue
        declaration: dict[str, Any] = {"name": name}
        description = function.get("description")
        if isinstance(description, str) and description:
            declaration["description"] = description
        parameters = function.get("parameters")
        if isinstance(parameters, dict):
            declaration["parameters"] = _sanitize_schema(parameters)
        declarations.append(declaration)
    return declarations


def _error_message(body: Any) -> str:
    if not isinstance(body, dict):
        return ""
    error = body.get("error")
    if isinstance(error, dict):
        message = error.get("message")
        if isinstance(message, str):
            return message
    return ""


def _raise_for_error_status(response: httpx.Response) -> None:
    if response.status_code in (401, 403):
        raise ProviderAuthenticationError
    if response.status_code == 404:
        raise ProviderConfigurationError
    try:
        body = response.json()
    except ValueError:
        body = None
    message = _error_message(body).lower()
    if "api key" in message or "api_key_invalid" in message or "unauthenticated" in message:
        raise ProviderAuthenticationError
    raise ProviderUnavailable


def _parse_thought_signature(part: dict[str, Any]) -> str | None:
    """Extract an opaque Gemini thought signature from a response part.

    Gemini 3 requires these to be returned unchanged on the exact part that
    produced them; for function calls a missing signature is a hard ``400``.
    The value is treated as opaque, bounded, and never logged or persisted.
    """
    signature = part.get("thoughtSignature")
    if signature is None:
        signature = part.get("thought_signature")
    if signature is None:
        return None
    if not isinstance(signature, str) or not signature:
        raise ProviderResponseError
    if len(signature) > MAX_THOUGHT_SIGNATURE_CHARS:
        raise ProviderResponseError
    return signature


def _parse_function_call(
    function_call: dict[str, Any], index: int, signature: str | None
) -> ProviderToolCall:
    name = function_call.get("name")
    if not isinstance(name, str) or not name or len(name) > 100:
        raise ProviderResponseError
    arguments = function_call.get("args")
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict) or len(arguments) > MAX_ARGUMENT_KEYS:
        raise ProviderResponseError
    try:
        if len(json.dumps(arguments, default=str)) > MAX_ARGUMENT_CHARS:
            raise ProviderResponseError
    except (TypeError, ValueError) as exc:
        raise ProviderResponseError from exc
    return ProviderToolCall(
        id=f"gemini_call_{index}",
        name=name,
        arguments=arguments,
        thought_signature=signature,
    )


def _parse_response(body: Any) -> ProviderResponse:
    if not isinstance(body, dict):
        raise ProviderResponseError

    feedback = body.get("promptFeedback")
    if isinstance(feedback, dict) and feedback.get("blockReason"):
        raise ProviderResponseError

    candidates = body.get("candidates")
    if not isinstance(candidates, list) or not candidates or not isinstance(candidates[0], dict):
        raise ProviderResponseError
    candidate = candidates[0]

    finish_reason = candidate.get("finishReason")
    if isinstance(finish_reason, str) and finish_reason.upper() in BLOCKED_FINISH_REASONS:
        raise ProviderResponseError

    content = candidate.get("content")
    parts = content.get("parts") if isinstance(content, dict) else None
    if not isinstance(parts, list):
        raise ProviderResponseError

    text_chunks: list[str] = []
    tool_calls: list[ProviderToolCall] = []
    for part in parts:
        if not isinstance(part, dict):
            continue
        function_call = part.get("functionCall")
        if isinstance(function_call, dict):
            tool_calls.append(
                _parse_function_call(
                    function_call, len(tool_calls), _parse_thought_signature(part)
                )
            )
            continue
        text = part.get("text")
        if isinstance(text, str):
            text_chunks.append(text)

    if len(tool_calls) > MAX_TOOL_CALLS_PER_RESPONSE:
        raise ProviderResponseError

    usage = body.get("usageMetadata")
    prompt_tokens = usage.get("promptTokenCount") if isinstance(usage, dict) else None
    completion_tokens = usage.get("candidatesTokenCount") if isinstance(usage, dict) else None
    if not isinstance(prompt_tokens, int):
        prompt_tokens = None
    if not isinstance(completion_tokens, int):
        completion_tokens = None

    return ProviderResponse(
        content="".join(text_chunks),
        tool_calls=tuple(tool_calls),
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
    )
