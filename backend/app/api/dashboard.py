"""Security dashboard endpoints.

All values are computed from real database aggregates at request time — no
statistics are hardcoded. Analysts and admins can view the dashboard but the
data itself is always read straight from PostgreSQL.
"""

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth.dependencies import require_analyst
from app.database import get_db
from app.models.alert import Alert, Severity
from app.models.event import Event
from app.models.user import User
from app.schemas.alert import AlertOut
from app.schemas.dashboard import (
    DashboardSummary,
    IpCount,
    SeverityCounts,
    StatusCounts,
    TimelinePoint,
    TypeCount,
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

DbSession = Annotated[Session, Depends(get_db)]

HOURS_WINDOW = 24


def _alert_out(alert: Alert) -> AlertOut:
    obj = AlertOut.model_validate(alert)
    obj.rule_name = alert.rule.name if alert.rule else None
    return obj


@router.get("/summary", response_model=DashboardSummary, summary="Dashboard statistics")
def dashboard_summary(
    db: DbSession, _user: Annotated[User, Depends(require_analyst)]
) -> DashboardSummary:
    """Aggregate live statistics for the SOC dashboard."""
    now = datetime.now(timezone.utc)
    since_24h = now - timedelta(hours=HOURS_WINDOW)

    total_events = db.query(func.count(Event.id)).scalar()
    total_alerts = db.query(func.count(Alert.id)).scalar()
    events_recent = db.query(func.count(Event.id)).filter(Event.timestamp >= since_24h).scalar()
    alerts_recent = db.query(func.count(Alert.id)).filter(Alert.created_at >= since_24h).scalar()

    severity_counts = {
        s: db.query(func.count(Alert.id)).filter(Alert.severity == s).scalar()
        for s in Severity.ALL
    }
    severity = SeverityCounts(
        low=severity_counts.get(Severity.LOW, 0),
        medium=severity_counts.get(Severity.MEDIUM, 0),
        high=severity_counts.get(Severity.HIGH, 0),
        critical=severity_counts.get(Severity.CRITICAL, 0),
    )

    status_counts = {
        "open": db.query(func.count(Alert.id)).filter(Alert.status == "OPEN").scalar(),
        "investigating": db.query(func.count(Alert.id)).filter(Alert.status == "INVESTIGATING").scalar(),
        "resolved": db.query(func.count(Alert.id)).filter(Alert.status == "RESOLVED").scalar(),
    }
    status = StatusCounts(**status_counts)

    ip_rows = (
        db.query(Event.source_ip, func.count(Event.id).label("cnt"))
        .filter(Event.source_ip.isnot(None))
        .group_by(Event.source_ip)
        .order_by(func.count(Event.id).desc())
        .limit(8)
        .all()
    )
    top_source_ips = [IpCount(source_ip=ip, count=cnt) for ip, cnt in ip_rows]

    type_rows = (
        db.query(Event.event_type, func.count(Event.id).label("cnt"))
        .group_by(Event.event_type)
        .order_by(func.count(Event.id).desc())
        .limit(8)
        .all()
    )
    top_event_types = [TypeCount(event_type=t, count=cnt) for t, cnt in type_rows]

    recent_events = (
        db.query(Event).order_by(Event.timestamp.desc()).limit(50).all()
    )
    recent_alerts = (
        db.query(Alert).order_by(Alert.created_at.desc()).limit(20).all()
    )

    return DashboardSummary(
        total_events=total_events,
        total_alerts=total_alerts,
        events_last_24h=events_recent,
        alerts_last_24h=alerts_recent,
        severity=severity,
        status=status,
        top_source_ips=top_source_ips,
        top_event_types=top_event_types,
        recent_events=recent_events,
        recent_alerts=[_alert_out(a) for a in recent_alerts],
    )


@router.get("/timeline", response_model=list[TimelinePoint], summary="Attack timeline")
def dashboard_timeline(
    db: DbSession,
    _user: Annotated[User, Depends(require_analyst)],
    hours: int = Query(default=HOURS_WINDOW, ge=1, le=168),
) -> list[TimelinePoint]:
    """Hourly event and alert counts (with severity breakdown) over the window."""
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)

    # date_trunc is applied in UTC on both the DB values and the bucket keys
    # below, so the keys always align regardless of the server time zone.
    utc_bucket = lambda column: func.date_trunc(
        "hour", column.op("AT TIME ZONE")("UTC")
    )

    event_rows = (
        db.query(utc_bucket(Event.timestamp).label("bucket"), func.count(Event.id))
        .filter(Event.timestamp >= since)
        .group_by("bucket")
        .all()
    )
    alert_rows = (
        db.query(utc_bucket(Alert.created_at).label("bucket"), Alert.severity, func.count(Alert.id))
        .filter(Alert.created_at >= since)
        .group_by("bucket", Alert.severity)
        .all()
    )

    events_by_bucket = {bucket.replace(tzinfo=None): count for bucket, count in event_rows}
    alerts_by_bucket: dict[str, dict[str, int]] = {}
    for bucket, severity, count in alert_rows:
        key = bucket.replace(tzinfo=None)
        entry = alerts_by_bucket.setdefault(key, {"critical": 0, "high": 0, "medium": 0, "low": 0})
        entry[severity.lower()] += count

    buckets: list[TimelinePoint] = []
    current = since.replace(minute=0, second=0, microsecond=0, tzinfo=None)
    while current <= now.replace(tzinfo=None):
        point = TimelinePoint(bucket=current.replace(tzinfo=timezone.utc))
        point.events = events_by_bucket.get(current, 0)
        severities = alerts_by_bucket.get(current, {})
        point.critical = severities.get("critical", 0)
        point.high = severities.get("high", 0)
        point.medium = severities.get("medium", 0)
        point.low = severities.get("low", 0)
        point.alerts = point.critical + point.high + point.medium + point.low
        buckets.append(point)
        current += timedelta(hours=1)

    return buckets