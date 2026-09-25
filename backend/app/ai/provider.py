from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

import httpx


class ProviderError(Exception):
    pass


class ProviderConfigurationError(ProviderError):
    pass


class ProviderTimeout(ProviderError):
    pass


class ProviderRateLimited(ProviderError):
    pass


class ProviderUnavailable(ProviderError):
    pass


class ProviderResponseError(ProviderError):
    pass


@dataclass(frozen=True)
class ProviderToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ProviderResponse:
    content: str
    tool_calls: tuple[ProviderToolCall, ...]
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


class AIProvider(Protocol):
    def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        model: str,
        max_output_tokens: int,
    ) -> ProviderResponse:
        ...


class OpenAIProvider:
    endpoint = "https://api.openai.com/v1/chat/completions"

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
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": max_output_tokens,
        }
        if tools:
            payload["tool_choice"] = "auto"
            payload["tools"] = tools

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        try:
            with httpx.Client(timeout=self._timeout_seconds, follow_redirects=False) as client:
                response = client.post(self.endpoint, headers=headers, json=payload)
        except httpx.TimeoutException as exc:
            raise ProviderTimeout from exc
        except httpx.RequestError as exc:
            raise ProviderUnavailable from exc

        if response.status_code == 429:
            raise ProviderRateLimited
        if response.status_code >= 400:
            raise ProviderUnavailable

        try:
            body = response.json()
            choices = body["choices"]
            message = choices[0]["message"]
            content = message.get("content") or ""
            raw_tool_calls = message.get("tool_calls") or []
            usage = body.get("usage") or {}
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ProviderResponseError from exc

        if not isinstance(content, str):
            raise ProviderResponseError
        if not isinstance(raw_tool_calls, list):
            raise ProviderResponseError

        tool_calls: list[ProviderToolCall] = []
        for raw_call in raw_tool_calls:
            try:
                call_id = raw_call["id"]
                function = raw_call["function"]
                name = function["name"]
                raw_arguments = function["arguments"]
            except (KeyError, TypeError) as exc:
                raise ProviderResponseError from exc
            if not isinstance(call_id, str) or not call_id or len(call_id) > 128:
                raise ProviderResponseError
            if not isinstance(name, str) or not name or len(name) > 100:
                raise ProviderResponseError
            if not isinstance(raw_arguments, str) or len(raw_arguments) > 20000:
                raise ProviderResponseError
            try:
                arguments = json.loads(raw_arguments)
            except (TypeError, ValueError) as exc:
                raise ProviderResponseError from exc
            if not isinstance(arguments, dict):
                raise ProviderResponseError
            tool_calls.append(ProviderToolCall(id=call_id, name=name, arguments=arguments))

        prompt_tokens = usage.get("prompt_tokens") if isinstance(usage, dict) else None
        completion_tokens = usage.get("completion_tokens") if isinstance(usage, dict) else None
        if not isinstance(prompt_tokens, int):
            prompt_tokens = None
        if not isinstance(completion_tokens, int):
            completion_tokens = None

        return ProviderResponse(
            content=content,
            tool_calls=tuple(tool_calls),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )


def get_provider(provider_name: str, api_key: str, timeout_seconds: float) -> AIProvider:
    if provider_name.lower() == "openai":
        return OpenAIProvider(api_key=api_key, timeout_seconds=timeout_seconds)
    raise ProviderConfigurationError
