"""Event and log ingestion schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EventCreate(BaseModel):
    """A normalised security event submitted by an external collector."""

    timestamp: datetime | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    event_type: str = Field(min_length=1, max_length=80)
    status: str = "UNKNOWN"
    severity: str = "LOW"
    source: str = "MANUAL"
    message: str = Field(min_length=1)
    metadata: dict = Field(default_factory=dict)


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    source_ip: str | None
    destination_ip: str | None
    username: str | None
    event_type: str
    status: str
    severity: str
    source: str
    message: str
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


class EventListResponse(BaseModel):
    total: int
    items: list[EventOut]


class LogIngestBatch(BaseModel):
    """Raw log lines submitted for parsing and normalisation."""

    lines: list[str] = Field(min_length=1, max_length=2000)
    source: str = "MANUAL"


class LogIngestResponse(BaseModel):
    """Aggregated result of ingesting a batch of log lines."""

    total_lines: int
    parsed: int
    unknown: int
    events_created: int
    alerts_created: int
    event_ids: list[int] = Field(default_factory=list)