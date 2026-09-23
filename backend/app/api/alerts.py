"""Alert query and triage endpoints.

Alerts are produced by the detection engine; this router exposes them for the
SOC workflow: searchable list, detail with the related event, and status
transitions that drive triage. Every status change is recorded in the audit
log.
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.auth.dependencies import require_analyst
from app.database import get_db
from app.models.alert import Alert, AlertStatus
from app.models.audit import AuditAction
from app.models.investigation import Investigation
from app.models.user import User
from app.schemas.alert import AlertDetailOut, AlertListResponse, AlertOut, AlertStatusRequest, RelatedEventOut
from app.schemas.investigation import InvestigationOut
from app.services.audit import write_audit
from app.services.export import csv_response

router = APIRouter(prefix="/alerts", tags=["alerts"])

DbSession = Annotated[Session, Depends(get_db)]

EXPORT_MAX_ROWS = 50_000


def _to_out(alert: Alert) -> AlertOut:
    out = AlertOut.model_validate(alert)
    out.rule_name = alert.rule.name if alert.rule else None
    return out


def _to_investigation_out(investigation: Investigation | None) -> InvestigationOut | None:
    if investigation is None:
        return None
    out = InvestigationOut.model_validate(investigation)
    out.assignee_username = investigation.assignee.username if investigation.assignee else None
    return out


@router.get("", response_model=AlertListResponse, summary="List alerts")
def list_alerts(
    db: DbSession,
    _user: Annotated[User, Depends(require_analyst)],
    status_filter: str | None = Query(default=None, alias="status", max_length=20),
    severity: str | None = Query(default=None, max_length=20),
    alert_type: str | None = Query(default=None, max_length=80),
    source_ip: str | None = Query(default=None, max_length=45),
    search: str | None = Query(default=None, max_length=200),
    from_time: datetime | None = Query(default=None),
    to_time: datetime | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> AlertListResponse:
    """Searchable, filterable, paginated alert list ordered newest first."""
    query = db.query(Alert).filter(Alert.user_id == _user.id)
    if status_filter:
        query = query.filter(Alert.status == status_filter)
    if severity:
        query = query.filter(Alert.severity == severity)
    if alert_type:
        query = query.filter(Alert.alert_type == alert_type)
    if source_ip:
        query = query.filter(Alert.source_ip == source_ip)
    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(
                Alert.alert_type.ilike(pattern),
                Alert.description.ilike(pattern),
                Alert.source_ip.ilike(pattern),
            )
        )
    if from_time:
        query = query.filter(Alert.created_at >= from_time)
    if to_time:
        query = query.filter(Alert.created_at <= to_time)

    total = query.count()
    items = (
        query.order_by(Alert.created_at.desc(), Alert.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return AlertListResponse(total=total, items=[_to_out(a) for a in items])


@router.get("/export", summary="Export alerts as CSV")
def export_alerts(
    db: DbSession,
    _user: Annotated[User, Depends(require_analyst)],
    status_filter: str | None = Query(default=None, alias="status", max_length=20),
    severity: str | None = Query(default=None, max_length=20),
    alert_type: str | None = Query(default=None, max_length=80),
    source_ip: str | None = Query(default=None, max_length=45),
    search: str | None = Query(default=None, max_length=200),
    from_time: datetime | None = Query(default=None),
    to_time: datetime | None = Query(default=None),
) -> Response:
    """CSV export honouring the same filters as the alert list, newest first."""
    query = db.query(Alert).filter(Alert.user_id == _user.id)
    if status_filter:
        query = query.filter(Alert.status == status_filter)
    if severity:
        query = query.filter(Alert.severity == severity)
    if alert_type:
        query = query.filter(Alert.alert_type == alert_type)
    if source_ip:
        query = query.filter(Alert.source_ip == source_ip)
    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(
                Alert.alert_type.ilike(pattern),
                Alert.description.ilike(pattern),
                Alert.source_ip.ilike(pattern),
            )
        )
    if from_time:
        query = query.filter(Alert.created_at >= from_time)
    if to_time:
        query = query.filter(Alert.created_at <= to_time)

    rows = []
    for alert in query.order_by(Alert.created_at.desc(), Alert.id.desc()).limit(EXPORT_MAX_ROWS):
        rows.append(
            [
                alert.id,
                alert.alert_type,
                alert.severity,
                alert.status,
                alert.source_ip or "",
                alert.rule.name if alert.rule else "",
                alert.created_at.isoformat(),
                alert.updated_at.isoformat(),
                alert.resolved_at.isoformat() if alert.resolved_at else "",
                alert.description or "",
            ]
        )
    return csv_response(
        "alerts.csv",
        ["id", "alert_type", "severity", "status", "source_ip", "rule", "created_at", "updated_at", "resolved_at", "description"],
        rows,
    )


@router.get("/{alert_id}", response_model=AlertDetailOut, summary="Get alert detail")
def get_alert(
    alert_id: int,
    db: DbSession,
    _user: Annotated[User, Depends(require_analyst)],
) -> AlertDetailOut:
    """Full alert detail including the related event and its investigation."""
    alert = (
        db.query(Alert)
        .filter(
            Alert.id == alert_id,
            Alert.user_id == _user.id,
        )
        .first()
    )
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found.")

    investigation = (
        db.query(Investigation).filter(Investigation.alert_id == alert_id).first()
    )
    out = AlertDetailOut.model_validate(alert)
    out.rule_name = alert.rule.name if alert.rule else None
    out.event = RelatedEventOut.model_validate(alert.event) if alert.event else None
    out.investigation = _to_investigation_out(investigation)
    return out


@router.patch(
    "/{alert_id}/status",
    response_model=AlertOut,
    summary="Transition alert status",
)
def update_alert_status(
    alert_id: int,
    payload: AlertStatusRequest,
    db: DbSession,
    user: Annotated[User, Depends(require_analyst)],
) -> AlertOut:
    """Move an alert through the OPEN / INVESTIGATING / RESOLVED lifecycle."""
    alert = (
        db.query(Alert)
        .filter(
            Alert.id == alert_id,
            Alert.user_id == user.id,
        )
        .first()
    )
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found.")

    previous_status = alert.status
    alert.status = payload.status
    alert.resolved_at = datetime.now() if payload.status == AlertStatus.RESOLVED else None
    db.commit()
    db.refresh(alert)

    write_audit(
        db,
        user=user,
        action=AuditAction.ALERT_STATUS_CHANGED,
        resource_type="alert",
        resource_id=alert.id,
        details={"from": previous_status, "status": payload.status, "note": payload.note},
    )
    return _to_out(alert)
