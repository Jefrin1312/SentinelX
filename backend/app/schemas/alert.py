"""Alert schemas and related-event output."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.alert import AlertStatus, Severity


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_id: int | None
    rule_id: int | None
    alert_type: str
    severity: str
    source_ip: str | None
    description: str
    status: str
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None
    rule_name: str | None = None


class AlertListResponse(BaseModel):
    total: int
    items: list[AlertOut]


class AlertStatusRequest(BaseModel):
    """Request to transition an alert to a new status."""

    status: str = Field(pattern=f"^({'|'.join(AlertStatus.ALL)})$")
    note: str | None = Field(default=None, max_length=2000)


class RelatedEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    event_type: str
    source_ip: str | None
    username: str | None
    status: str
    severity: str
    source: str
    message: str