"""Investigation workflow endpoints — the SOC triage loop.

Opening an investigation automatically promotes its alert to INVESTIGATING,
and resolving the investigation resolves the linked alert. Every step is
recorded in the audit log.
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.auth.dependencies import require_analyst
from app.database import get_db
from app.models.alert import Alert, AlertStatus
from app.models.audit import AuditAction
from app.models.investigation import Investigation, InvestigationNote, InvestigationStatus
from app.models.user import User
from app.schemas.alert import AlertOut
from app.schemas.investigation import (
    InvestigationCreate,
    InvestigationDetailOut,
    InvestigationListResponse,
    InvestigationNoteCreate,
    InvestigationNoteOut,
    InvestigationOut,
    InvestigationUpdate,
)
from app.services.audit import write_audit

router = APIRouter(prefix="/investigations", tags=["investigations"])

DbSession = Annotated[Session, Depends(get_db)]


def _to_out(investigation: Investigation) -> InvestigationOut:
    out = InvestigationOut.model_validate(investigation)
    out.assignee_username = investigation.assignee.username if investigation.assignee else None
    return out


def _to_note_out(note: InvestigationNote) -> InvestigationNoteOut:
    out = InvestigationNoteOut.model_validate(note)
    out.author_username = note.author.username if note.author else None
    return out


def _to_detail_out(investigation: Investigation) -> InvestigationDetailOut:
    out = InvestigationDetailOut(
        **_to_out(investigation).model_dump(), alert={}, notes=[]
    )
    if investigation.alert:
        alert_out = AlertOut.model_validate(investigation.alert)
        alert_out.rule_name = investigation.alert.rule.name if investigation.alert.rule else None
        out.alert = alert_out.model_dump()
    out.notes = [_to_note_out(note) for note in (investigation.notes or [])]
    return out


@router.post(
    "", response_model=InvestigationOut, status_code=201, summary="Open an investigation"
)
def create_investigation(
    payload: InvestigationCreate,
    db: DbSession,
    user: Annotated[User, Depends(require_analyst)],
) -> InvestigationOut:
    """Open a new investigation on an alert (promotes the alert to INVESTIGATING)."""
    alert = (
        db.query(Alert)
        .filter(
            Alert.id == payload.alert_id,
            Alert.user_id == user.id,
        )
        .first()
    )
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found.")
    existing = (
        db.query(Investigation).filter(Investigation.alert_id == payload.alert_id).first()
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An investigation already exists for this alert.",
        )

    investigation = Investigation(
        alert_id=alert.id,
        assigned_to=None,
        status=InvestigationStatus.OPEN,
        summary=payload.summary,
    )
    db.add(investigation)

    alert_changed = False
    if alert.status == AlertStatus.OPEN:
        alert.status = AlertStatus.INVESTIGATING
        alert_changed = True

    db.commit()
    db.refresh(investigation)

    write_audit(
        db,
        user=user,
        action=AuditAction.INVESTIGATION_CREATED,
        resource_type="investigation",
        resource_id=investigation.id,
        details={"alert_id": alert.id},
    )
    if alert_changed:
        write_audit(
            db,
            user=user,
            action=AuditAction.ALERT_STATUS_CHANGED,
            resource_type="alert",
            resource_id=alert.id,
            details={"from": AlertStatus.OPEN, "status": AlertStatus.INVESTIGATING},
        )
    return _to_out(investigation)


@router.get("", response_model=InvestigationListResponse, summary="List investigations")
def list_investigations(
    db: DbSession,
    _user: Annotated[User, Depends(require_analyst)],
    status_filter: str | None = Query(default=None, alias="status", max_length=20),
    alert_id: int | None = Query(default=None),
    assigned_to: int | None = Query(default=None),
    search: str | None = Query(default=None, max_length=200),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> InvestigationListResponse:
    """Searchable, filterable, paginated investigation list, newest first."""
    query = db.query(Investigation)
    if status_filter:
        query = query.filter(Investigation.status == status_filter)
    if alert_id:
        query = query.filter(Investigation.alert_id == alert_id)
    if assigned_to is not None:
        query = query.filter(Investigation.assigned_to == assigned_to)
    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(Investigation.summary.ilike(pattern), Investigation.id.cast(str).like(pattern))
        )

    total = query.count()
    items = (
        query.order_by(Investigation.updated_at.desc(), Investigation.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return InvestigationListResponse(total=total, items=[_to_out(i) for i in items])


@router.get("/{investigation_id}", response_model=InvestigationDetailOut, summary="Get investigation")
def get_investigation(
    investigation_id: int,
    db: DbSession,
    _user: Annotated[User, Depends(require_analyst)],
) -> InvestigationDetailOut:
    """Full investigation detail including the alert headline and note thread."""
    investigation = (
        db.query(Investigation).filter(Investigation.id == investigation_id).first()
    )
    if investigation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found."
        )
    return _to_detail_out(investigation)


@router.patch("/{investigation_id}", response_model=InvestigationOut, summary="Update investigation")
def update_investigation(
    investigation_id: int,
    payload: InvestigationUpdate,
    db: DbSession,
    user: Annotated[User, Depends(require_analyst)],
) -> InvestigationOut:
    """Change an investigation's status, summary, or assignee.

    Resolving an investigation also resolves the linked open alert; reopening
    it reopens that alert too.
    """
    investigation = (
        db.query(Investigation).filter(Investigation.id == investigation_id).first()
    )
    if investigation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found."
        )

    if payload.assigned_to is not None:
        assignee = db.query(User).filter(User.id == payload.assigned_to).first()
        if assignee is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Assignee not found."
            )
        investigation.assigned_to = payload.assigned_to

    if payload.summary is not None:
        investigation.summary = payload.summary

    alert_effective = None
    if payload.status is not None and payload.status != investigation.status:
        investigation.status = payload.status
        investigation.resolved_at = (
            datetime.now() if payload.status == InvestigationStatus.RESOLVED else None
        )
        alert = investigation.alert
        if alert is not None and payload.status == InvestigationStatus.RESOLVED:
            if alert.status != AlertStatus.RESOLVED:
                alert.status = AlertStatus.RESOLVED
                alert.resolved_at = datetime.now()
                alert_effective = alert
        elif alert is not None and payload.status == InvestigationStatus.OPEN:
            if alert.status == AlertStatus.RESOLVED:
                alert.status = AlertStatus.INVESTIGATING
                alert.resolved_at = None
                alert_effective = alert

    db.commit()
    db.refresh(investigation)

    write_audit(
        db,
        user=user,
        action=AuditAction.INVESTIGATION_UPDATED,
        resource_type="investigation",
        resource_id=investigation.id,
        details={"status": payload.status, "assigned_to": payload.assigned_to},
    )
    if alert_effective is not None:
        write_audit(
            db,
            user=user,
            action=AuditAction.ALERT_STATUS_CHANGED,
            resource_type="alert",
            resource_id=alert_effective.id,
            details={
                "from": alert_effective.status,
                "status": AlertStatus.RESOLVED if alert_effective.status == AlertStatus.RESOLVED else AlertStatus.INVESTIGATING,
            },
        )
    return _to_out(investigation)


@router.post(
    "/{investigation_id}/notes",
    response_model=InvestigationNoteOut,
    status_code=201,
    summary="Add an investigation note",
)
def add_investigation_note(
    investigation_id: int,
    payload: InvestigationNoteCreate,
    db: DbSession,
    user: Annotated[User, Depends(require_analyst)],
) -> InvestigationNoteOut:
    """Append a note to the investigation thread."""
    investigation = (
        db.query(Investigation).filter(Investigation.id == investigation_id).first()
    )
    if investigation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found."
        )

    note = InvestigationNote(
        investigation_id=investigation.id,
        user_id=user.id,
        note=payload.note,
    )
    db.add(note)
    db.commit()
    db.refresh(note)

    write_audit(
        db,
        user=user,
        action=AuditAction.NOTE_ADDED,
        resource_type="investigation",
        resource_id=investigation.id,
        details={"note_transcript": payload.note[:200]},
    )
    return _to_note_out(note)