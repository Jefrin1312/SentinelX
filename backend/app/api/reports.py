"""Reporting and trend endpoints.

Every value is an aggregate computed live from the database over the requested
window — the SOC gets the same fidelity as the dashboard, sliced by day and
summarised by severity, status, alert type, and source.
"""

from datetime import date, datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Date, func
from sqlalchemy.orm import Session

from app.auth.dependencies import require_analyst
from app.database import get_db
from app.models.alert import Alert, AlertStatus, Severity
from app.models.event import Event
from app.models.user import User
from app.schemas.dashboard import IpCount, TypeCount
from app.schemas.report import (
    DailyAlertPoint,
    DailyEventPoint,
    AlertTypeReport,
    ReportSummary,
    SeverityReport,
    StatusReport,
)

router = APIRouter(prefix="/reports", tags=["reports"])

DbSession = Annotated[Session, Depends(get_db)]


def _utc_day_bucket(column):
    """Group a tz-aware column by UTC day, returning a :class:`date`."""
    return func.date_trunc("day", column.op("AT TIME ZONE")("UTC")).cast(Date)


@router.get("/summary", response_model=ReportSummary, summary="Reports summary for a date range")
def report_summary(
    db: DbSession,
    _user: Annotated[User, Depends(require_analyst)],
    days: int = Query(default=7, ge=1, le=90),
    topn: int = Query(default=10, ge=1, le=25),
) -> ReportSummary:
    """Ingest/alert totals, daily trends, and breakdowns over the last ``days``."""
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)

    total_events = (
        db.query(func.count(Event.id)).filter(Event.timestamp >= since).scalar()
    )
    total_alerts = (
        db.query(func.count(Alert.id)).filter(Alert.created_at >= since).scalar()
    )
    if total_events is None:
        total_events = 0
    if total_alerts is None:
        total_alerts = 0

    # Daily zero-filled series for events and (severity-split) alerts.
    event_day_rows = (
        db.query(_utc_day_bucket(Event.timestamp).label("day"), func.count(Event.id))
        .filter(Event.timestamp >= since)
        .group_by("day")
        .all()
    )
    alert_day_rows = (
        db.query(
            _utc_day_bucket(Alert.created_at).label("day"),
            Alert.severity,
            func.count(Alert.id),
        )
        .filter(Alert.created_at >= since)
        .group_by("day", Alert.severity)
        .all()
    )

    events_by_day = {d: n for d, n in event_day_rows}
    alerts_by_day: dict[date, dict[str, int]] = {}
    for day, severity, count in alert_day_rows:
        entry = alerts_by_day.setdefault(
            day, {"critical": 0, "high": 0, "medium": 0, "low": 0}
        )
        entry[severity.lower()] += count

    day_events: list[DailyEventPoint] = []
    day_alerts: list[DailyAlertPoint] = []
    current = now.date() - timedelta(days=days - 1)
    while current <= now.date():
        day_events.append(DailyEventPoint(day=current.isoformat(), events=events_by_day.get(current, 0)))
        sev = alerts_by_day.get(current, {})
        day_alerts.append(
            DailyAlertPoint(
                day=current.isoformat(),
                alerts=sum(sev.values()),
                critical=sev.get("critical", 0),
                high=sev.get("high", 0),
                medium=sev.get("medium", 0),
                low=sev.get("low", 0),
            )
        )
        current += timedelta(days=1)

    # Breakdowns.
    alert_type_rows = (
        db.query(Alert.alert_type, func.count(Alert.id).label("cnt"))
        .filter(Alert.created_at >= since)
        .group_by(Alert.alert_type)
        .order_by(func.count(Alert.id).desc())
        .limit(topn)
        .all()
    )
    severity_rows = (
        db.query(Alert.severity, func.count(Alert.id).label("cnt"))
        .filter(Alert.created_at >= since)
        .group_by(Alert.severity)
        .all()
    )
    status_rows = (
        db.query(Alert.status, func.count(Alert.id).label("cnt"))
        .filter(Alert.created_at >= since)
        .group_by(Alert.status)
        .all()
    )
    ip_rows = (
        db.query(Event.source_ip, func.count(Event.id).label("cnt"))
        .filter(Event.source_ip.isnot(None), Event.timestamp >= since)
        .group_by(Event.source_ip)
        .order_by(func.count(Event.id).desc())
        .limit(topn)
        .all()
    )
    event_type_rows = (
        db.query(Event.event_type, func.count(Event.id).label("cnt"))
        .filter(Event.timestamp >= since)
        .group_by(Event.event_type)
        .order_by(func.count(Event.id).desc())
        .limit(topn)
        .all()
    )

    avg_resolution = (
        db.query(
            func.avg(
                func.extract("epoch", func.age(Alert.resolved_at, Alert.created_at)) / 60.0
            )
        )
        .filter(
            Alert.created_at >= since,
            Alert.status == AlertStatus.RESOLVED,
            Alert.resolved_at.isnot(None),
        )
        .scalar()
    )

    severity_order = {s: i for i, s in enumerate(Severity.ALL)}
    status_order = {s: i for i, s in enumerate(AlertStatus.ALL)}
    severity_counts = {sev: 0 for sev in Severity.ALL}
    status_counts = {st: 0 for st in AlertStatus.ALL}
    for sev, count in severity_rows:
        severity_counts[sev] = count
    for st, count in status_rows:
        status_counts[st] = count

    return ReportSummary(
        range_start=since,
        range_end=now,
        days=days,
        total_events=total_events,
        total_alerts=total_alerts,
        avg_resolution_minutes=(
            int(round(avg_resolution)) if avg_resolution is not None else None
        ),
        by_day_events=day_events,
        by_day_alerts=day_alerts,
        top_alert_types=[
            AlertTypeReport(alert_type=name, count=count) for name, count in alert_type_rows
        ],
        by_severity=[
            SeverityReport(severity=name, count=severity_counts[name])
            for name in sorted(severity_counts, key=severity_order.get)
        ],
        by_status=[
            StatusReport(status=name, count=status_counts[name])
            for name in sorted(status_counts, key=status_order.get)
        ],
        top_source_ips=[IpCount(source_ip=ip, count=cnt) for ip, cnt in ip_rows],
        top_event_types=[TypeCount(event_type=t, count=cnt) for t, cnt in event_type_rows],
    )