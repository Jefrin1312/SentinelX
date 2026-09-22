"""Report aggregation schemas."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.dashboard import IpCount, TypeCount


class DailyEventPoint(BaseModel):
    day: str
    events: int = 0


class DailyAlertPoint(BaseModel):
    day: str
    alerts: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class AlertTypeReport(BaseModel):
    alert_type: str
    count: int


class SeverityReport(BaseModel):
    severity: str
    count: int


class StatusReport(BaseModel):
    status: str
    count: int


class ReportSummary(BaseModel):
    range_start: datetime
    range_end: datetime
    days: int
    total_events: int
    total_alerts: int
    avg_resolution_minutes: int | None = None
    by_day_events: list[DailyEventPoint] = Field(default_factory=list)
    by_day_alerts: list[DailyAlertPoint] = Field(default_factory=list)
    top_alert_types: list[AlertTypeReport] = Field(default_factory=list)
    by_severity: list[SeverityReport] = Field(default_factory=list)
    by_status: list[StatusReport] = Field(default_factory=list)
    top_source_ips: list[IpCount] = Field(default_factory=list)
    top_event_types: list[TypeCount] = Field(default_factory=list)