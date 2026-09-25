"""Security Assistant orchestration.

Binds an authenticated user to a read-only, user-scoped tool registry, runs a
bounded tool-calling loop against the configured provider, and records every
request in the audit log. The service never accepts a user identifier from the
request and never returns data belonging to another user.
"""

from __future__ import annotations

import logging
import time
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app.ai.prompts import (
    TRUSTED_SYSTEM_INSTRUCTIONS,
    build_tool_limit_message,
    build_untrusted_tool_content,
    build_user_message,
)
from app.ai.provider import (
    ProviderConfigurationError,
    ProviderRateLimited,
    ProviderResponseError,
    ProviderTimeout,
    ProviderUnavailable,
    get_provider,
)
from app.ai.schemas import AIChatRequest, AIChatResponse, AISource
from app.ai.tools import TOOL_DEFINITIONS, TOOL_NAMES, ToolRegistry
from app.auth.ratelimit import is_rate_limited
from app.config import get_settings
from app.models.audit import AuditAction
from app.models.user import User
from app.services.audit import write_audit

logger = logging.getLogger(__name__)

MAX_SOURCES = 20


class AssistantError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def run_chat(
    db: Session, user: User, payload: AIChatRequest, ip_address: str | None
) -> AIChatResponse:
    settings = get_settings()
    conversation_id = payload.conversation_id or uuid4()
    started = time.monotonic()
    base_audit: dict[str, Any] = {
        "input_chars": len(payload.message),
        "provider": settings.AI_PROVIDER[:40],
        "latency_ms": _latency_ms(started),
    }

    if not settings.AI_ENABLED:
        _audit(db, user, ip_address, conversation_id, "disabled", base_audit)
        raise AssistantError(503, "The Security Assistant is not enabled.")

    if is_rate_limited(f"ai:{user.id}", limit=settings.AI_RATE_LIMIT):
        _audit(db, user, ip_address, conversation_id, "rate_limited", base_audit)
        raise AssistantError(429, "Too many assistant requests. Please try again shortly.")

    api_key = settings.AI_API_KEY.get_secret_value().strip()
    if not api_key:
        _audit(db, user, ip_address, conversation_id, "not_configured", base_audit)
        raise AssistantError(503, "The Security Assistant is not configured.")

    try:
        provider = get_provider(
            settings.AI_PROVIDER, api_key, float(settings.AI_REQUEST_TIMEOUT_SECONDS)
        )
    except ProviderConfigurationError:
        _audit(db, user, ip_address, conversation_id, "not_configured", base_audit)
        raise AssistantError(503, "The Security Assistant is not configured.") from None

    registry = ToolRegistry(
        db=db, user_id=user.id, max_context_records=settings.AI_MAX_CONTEXT_RECORDS
    )
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": TRUSTED_SYSTEM_INSTRUCTIONS},
        build_user_message(payload.message),
    ]
    sources: list[dict[str, Any]] = []
    tool_names: set[str] = set()
    tool_calls_used = 0

    while True:
        remaining_calls = max(0, settings.AI_MAX_TOOL_CALLS - tool_calls_used)
        definitions = TOOL_DEFINITIONS if remaining_calls > 0 else []

        try:
            response = provider.complete(
                messages=messages,
                tools=definitions,
                model=settings.AI_MODEL,
                max_output_tokens=settings.AI_MAX_OUTPUT_TOKENS,
            )
        except ProviderTimeout:
            _audit(db, user, ip_address, conversation_id, "provider_timeout", base_audit)
            raise AssistantError(504, "The Security Assistant timed out. Please try again.") from None
        except ProviderRateLimited:
            _audit(db, user, ip_address, conversation_id, "provider_rate_limited", base_audit)
            raise AssistantError(503, "The Security Assistant is busy. Please try again later.") from None
        except (ProviderResponseError, ProviderUnavailable):
            _audit(db, user, ip_address, conversation_id, "provider_error", base_audit)
            raise AssistantError(502, "The Security Assistant is temporarily unavailable.") from None

        if not response.tool_calls:
            answer = (response.content or "").strip()
            if not answer:
                _audit(
                    db,
                    user,
                    ip_address,
                    conversation_id,
                    "empty_response",
                    {
                        **base_audit,
                        "tools": sorted(tool_names),
                        "tool_calls": tool_calls_used,
                    },
                )
                raise AssistantError(502, "The Security Assistant returned an empty response.")
            _audit(
                db,
                user,
                ip_address,
                conversation_id,
                "success",
                {
                    **base_audit,
                    "output_chars": len(answer),
                    "tools": sorted(tool_names),
                    "tool_calls": tool_calls_used,
                    "sources": len(sources),
                    "model": settings.AI_MODEL[:60],
                    "prompt_tokens": response.prompt_tokens,
                    "completion_tokens": response.completion_tokens,
                },
            )
            return AIChatResponse(
                message=answer,
                conversation_id=conversation_id,
                sources=_dedupe_sources(sources),
            )

        if not definitions:
            _audit(
                db,
                user,
                ip_address,
                conversation_id,
                "tool_budget_exhausted",
                {
                    **base_audit,
                    "tools": sorted(tool_names),
                    "tool_calls": tool_calls_used,
                },
            )
            raise AssistantError(502, "The Security Assistant exceeded its tool budget.")

        assistant_tool_calls: list[dict[str, Any]] = []
        tool_messages: list[dict[str, Any]] = []

        for index, call in enumerate(response.tool_calls):
            call_id = call.id or f"call_{index}"
            name = call.name if call.name else "unknown"

            if remaining_calls <= 0:
                result: dict[str, Any] = _limit_result()
            else:
                tool_calls_used += 1
                remaining_calls -= 1
                if name not in TOOL_NAMES:
                    tool_names.add("unknown")
                    result = _unknown_tool_result()
                else:
                    tool_names.add(name)
                    result = registry.execute(name, call.arguments)

            for source in result.get("sources", []):
                if isinstance(source, dict) and isinstance(source.get("id"), int):
                    sources.append(source)

            content = build_untrusted_tool_content(name, result)
            if len(content) > settings.AI_MAX_TOOL_RESULT_CHARS:
                content = build_untrusted_tool_content(
                    name,
                    {
                        **_oversized_result(),
                        "sources": result.get("sources", []),
                    },
                )

            assistant_tool_calls.append(
                {
                    "id": call_id,
                    "type": "function",
                    "function": {"name": name, "arguments": "{}"},
                }
            )
            tool_messages.append(
                {"role": "tool", "tool_call_id": call_id, "content": content}
            )

        messages.append(
            {"role": "assistant", "content": None, "tool_calls": assistant_tool_calls}
        )
        if remaining_calls <= 0:
            messages.append(build_tool_limit_message())
        messages.extend(tool_messages)


def _limit_result() -> dict[str, Any]:
    return {
        "ok": False,
        "error": {
            "code": "limit_reached",
            "message": "The tool-call budget is exhausted. Answer with what you already have.",
        },
    }


def _unknown_tool_result() -> dict[str, Any]:
    return {
        "ok": False,
        "error": {
            "code": "unknown_tool",
            "message": "That tool is not approved. Use one of the approved read-only tools.",
        },
    }


def _oversized_result() -> dict[str, Any]:
    return {
        "ok": False,
        "error": {
            "code": "result_too_large",
            "message": "The result was too large to include. Narrow the filters and retry once.",
        },
    }


def _dedupe_sources(sources: list[dict[str, Any]]) -> list[AISource]:
    seen: set[tuple[str, int]] = set()
    unique: list[AISource] = []
    for source in sources:
        try:
            parsed = AISource(type=source["type"], id=source["id"])
        except Exception:  # noqa: BLE001 — never emit a malformed source.
            continue
        key = (parsed.type, parsed.id)
        if key in seen:
            continue
        seen.add(key)
        unique.append(parsed)
        if len(unique) >= MAX_SOURCES:
            break
    return unique


def _latency_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _audit(
    db: Session,
    user: User,
    ip_address: str | None,
    conversation_id: Any,
    outcome: str,
    details: dict[str, Any],
) -> None:
    audit_details: dict[str, Any] = {
        **details,
        "outcome": outcome,
        "conversation_id": str(conversation_id),
        "latency_ms": details.get("latency_ms", 0),
    }
    if "provider" in details and details["provider"]:
        audit_details["provider"] = details["provider"]
    try:
        write_audit(
            db,
            user=user,
            action=AuditAction.AI_QUERY,
            resource_type="ai_assistant",
            ip_address=ip_address,
            details=audit_details,
        )
    except Exception:  # noqa: BLE001 — never fail a request because auditing failed.
        logger.warning("Security Assistant audit write failed")
