"""Audit log schemas."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int | None
    username: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    ip_address: str | None
    timestamp: datetime
    details: dict[str, Any] = Field(default_factory=dict)


class AuditLogListResponse(BaseModel):
    total: int
    items: list[AuditLogOut]