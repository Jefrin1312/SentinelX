"""Dashboard aggregation schemas."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.alert import AlertOut
from app.schemas.event import EventOut


class SeverityCounts(BaseModel):
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0


class StatusCounts(BaseModel):
    open: int = 0
    investigating: int = 0
    resolved: int = 0


class IpCount(BaseModel):
    source_ip: str
    count: int


class TypeCount(BaseModel):
    event_type: str
    count: int


class DashboardSummary(BaseModel):
    total_events: int
    total_alerts: int
    events_last_24h: int
    alerts_last_24h: int
    severity: SeverityCounts
    status: StatusCounts
    top_source_ips: list[IpCount] = Field(default_factory=list)
    top_event_types: list[TypeCount] = Field(default_factory=list)
    recent_events: list[EventOut] = Field(default_factory=list)
    recent_alerts: list[AlertOut] = Field(default_factory=list)


class TimelinePoint(BaseModel):
    bucket: datetime
    events: int = 0
    alerts: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0