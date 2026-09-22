"""Detection rule schemas."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

RULE_CATEGORIES = ("authentication", "ssh", "web", "system", "general")
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


class RuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    category: str
    severity: str
    enabled: bool
    threshold: int
    time_window: int
    rule_definition: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class RuleListResponse(BaseModel):
    total: int
    items: list[RuleOut]


class RuleUpdate(BaseModel):
    """Toggle a detection rule on or off."""

    enabled: bool


class RuleReloadResponse(BaseModel):
    loaded: int
    updated: int
    skipped: int


class RuleDefinitionCreate(BaseModel):
    """Declarative match expression for a new rule (mirrors the engine's fields)."""

    event_type: str | list[str]
    key: Literal["source_ip", "username"] = "source_ip"
    status: str | None = None
    reason: str | None = None
    signature: str | None = None

    @field_validator("event_type")
    @classmethod
    def _event_type_not_empty(cls, value: str | list[str]) -> str | list[str]:
        if isinstance(value, str):
            value = value.strip()
            if not value:
                raise ValueError("event_type is required")
            return value
        cleaned = [t.strip() for t in value if t and t.strip()]
        if not cleaned:
            raise ValueError("event_type is required")
        return cleaned

    @field_validator("status", "reason", "signature", mode="before")
    @classmethod
    def _blank_to_none(cls, value):
        if isinstance(value, str):
            value = value.strip()
            return value if value else None
        return value


class RuleCreate(BaseModel):
    """Payload for authoring a new detection rule."""

    name: str = Field(min_length=3, max_length=120, pattern=r"^[A-Za-z0-9 _\-\.\(\)\/]+$")
    description: str | None = Field(default=None, max_length=2000)
    category: Literal["authentication", "ssh", "web", "system", "general"] = "general"
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    enabled: bool = True
    threshold: int = Field(default=5, ge=1, le=100_000)
    time_window: int = Field(default=300, ge=1, le=604_800)
    rule_definition: RuleDefinitionCreate