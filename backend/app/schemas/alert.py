"""Alert schemas and related-event output."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.alert import AlertStatus, Severity
from app.schemas.investigation import InvestigationOut


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
    metadata: dict = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _expose_metadata(cls, value):
        """Read the ``metadata`` JSON column (mapped as ``metadata_json``)."""
        if hasattr(value, "metadata_json"):
            return {
                **{attr.key: getattr(value, attr.key) for attr in value.__mapper__.column_attrs},
                "metadata": value.metadata_json or {},
            }
        return value


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


class AlertDetailOut(AlertOut):
    """Alert plus the related event and open investigation for a detail view."""

    event: RelatedEventOut | None = None
    investigation: InvestigationOut | None = None