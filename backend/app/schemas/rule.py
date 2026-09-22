"""Detection rule schemas."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


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