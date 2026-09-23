"""Log ingestion and event query endpoints.

Ingest accepts raw log text (manual, file upload, or bundled sample files)
and pushes each line through the collector pipeline. Required backend
enforcement: only authenticated analysts/admins may ingest or read events.
"""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Query, Response, UploadFile, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.auth.dependencies import require_analyst
from app.config import get_settings
from app.database import get_db
from app.logs.collector import ingest_lines
from app.models.alert import Alert
from app.models.audit import AuditAction
from app.models.event import Event
from app.models.investigation import Investigation
from app.models.user import User
from app.schemas.event import EventListResponse, EventOut, LogIngestBatch, LogIngestResponse
from app.services.audit import write_audit
from app.services.export import csv_response

router = APIRouter(prefix="/logs", tags=["logs"])

DbSession = Annotated[Session, Depends(get_db)]

EXPORT_MAX_ROWS = 50_000


def _sanitise_filename(filename: str) -> str:
    """Return a safe basename — never trust an uploaded filename."""
    return Path(filename or "upload.log").name[:120]


def _validate_bytes(raw: bytes) -> str:
    settings = get_settings()
    limit = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if len(raw) > limit:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Upload exceeds the {settings.MAX_UPLOAD_SIZE_MB} MB limit.",
        )
    return raw.decode("utf-8", errors="replace")


@router.post("/ingest", response_model=LogIngestResponse, status_code=201, summary="Ingest raw log lines")
def ingest_logs(
    payload: LogIngestBatch,
    db: DbSession,
    _user: Annotated[User, Depends(require_analyst)],
) -> LogIngestResponse:
    """Parse a batch of raw log lines, store normalised events, and count unknowns."""
    result = ingest_lines(
        db,
        payload.lines,
        user_id=_user.id,
        source=payload.source,
    )
    if result["events_created"] > 0 or result["unknown"] > 0:
        write_audit(
            db,
            user=_user,
            action=AuditAction.LOGS_INGESTED,
            resource_type="event_batch",
            resource_id=f"{result['events_created']}",
            details={"parsed": result["parsed"], "unknown": result["unknown"]},
        )
    return LogIngestResponse(**result)


@router.post("/upload", response_model=LogIngestResponse, status_code=201, summary="Upload a log file")
async def upload_logs(
    file: UploadFile = File(...),
    db: Annotated[Session, Depends(get_db)] = None,
    _user: Annotated[User, Depends(require_analyst)] = None,
) -> LogIngestResponse:
    """Upload a plain-text log file for parsing.

    The file is validated by size and encoding. The filename is **not**
    trusted: only its basename is retained and the content is treated purely
    as data — nothing is ever executed.
    """
    settings = get_settings()
    raw = await file.read()
    contents = _validate_bytes(raw)
    safe_name = _sanitise_filename(file.filename)

    lines = contents.splitlines()
    if len(lines) > settings.MAX_UPLOAD_LINES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Upload exceeds the {settings.MAX_UPLOAD_LINES} line limit.",
        )

    result = ingest_lines(
        db,
        lines,
        user_id=_user.id,
        source="FILE",
    )
    write_audit(
        db,
        user=_user,
        action=AuditAction.LOGS_INGESTED,
        resource_type="file_upload",
        resource_id=safe_name,
        details={"parsed": result["parsed"], "unknown": result["unknown"], "lines": len(lines)},
    )
    return LogIngestResponse(**result)


@router.post("/import", response_model=LogIngestResponse, status_code=201, summary="Import a bundled sample log")
def import_sample(
    sample: str = Query(...),
    db: Annotated[Session, Depends(get_db)] = None,
    _user: Annotated[User, Depends(require_analyst)] = None,
) -> LogIngestResponse:
    """Import one of the bundled sample log files for controlled demos."""
    settings = get_settings()
    candidates = [
        Path(settings.SAMPLE_LOGS_DIR),
        Path("sample_logs"),
        Path(__file__).resolve().parent.parent.parent.parent / "sample_logs",
    ]
    target: Path | None = None
    for base in candidates:
        candidate = base / f"{sample}.log"
        if candidate.is_file():
            target = candidate
            break
    if target is None or sample not in {"ssh", "apache", "nginx", "auth"}:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample '{sample}' is not available.",
        )

    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    result = ingest_lines(
        db,
        lines,
        user_id=_user.id,
        source=f"SAMPLE:{sample}",
    )
    write_audit(
        db,
        user=_user,
        action=AuditAction.LOGS_INGESTED,
        resource_type="sample_import",
        resource_id=sample,
        details={"parsed": result["parsed"], "unknown": result["unknown"]},
    )
    return LogIngestResponse(**result)


@router.get("", response_model=EventListResponse, summary="List security events")
def list_events(
    db: DbSession,
    _user: Annotated[User, Depends(require_analyst)],
    search: str | None = Query(default=None, max_length=200),
    event_type: str | None = Query(default=None, max_length=80),
    source: str | None = Query(default=None, max_length=30),
    source_ip: str | None = Query(default=None, max_length=45),
    username: str | None = Query(default=None, max_length=100),
    status: str | None = Query(default=None, max_length=30),
    severity: str | None = Query(default=None, max_length=20),
    from_time: datetime | None = Query(default=None),
    to_time: datetime | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> EventListResponse:
    """Searchable, filterable, paginated event list backed by database queries."""
    query = db.query(Event).filter(Event.user_id == _user.id)
    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(
                Event.message.ilike(pattern),
                Event.source_ip.ilike(pattern),
                Event.username.ilike(pattern),
            )
        )
    if event_type:
        query = query.filter(Event.event_type == event_type)
    if source:
        query = query.filter(Event.source == source)
    if source_ip:
        query = query.filter(Event.source_ip == source_ip)
    if username:
        query = query.filter(Event.username == username)
    if status:
        query = query.filter(Event.status == status)
    if severity:
        query = query.filter(Event.severity == severity)
    if from_time:
        query = query.filter(Event.timestamp >= from_time)
    if to_time:
        query = query.filter(Event.timestamp <= to_time)

    total = query.count()
    items = (
        query.order_by(Event.timestamp.desc(), Event.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return EventListResponse(total=total, items=[EventOut.model_validate(e) for e in items])


@router.get("/export", summary="Export events as CSV")
def export_events(
    db: DbSession,
    _user: Annotated[User, Depends(require_analyst)],
    search: str | None = Query(default=None, max_length=200),
    event_type: str | None = Query(default=None, max_length=80),
    source: str | None = Query(default=None, max_length=30),
    source_ip: str | None = Query(default=None, max_length=45),
    username: str | None = Query(default=None, max_length=100),
    status: str | None = Query(default=None, max_length=30),
    severity: str | None = Query(default=None, max_length=20),
    from_time: datetime | None = Query(default=None),
    to_time: datetime | None = Query(default=None),
) -> Response:
    """CSV export honouring the same filters as the event list, newest first."""
    query = db.query(Event).filter(Event.user_id == _user.id)
    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(
                Event.message.ilike(pattern),
                Event.source_ip.ilike(pattern),
                Event.username.ilike(pattern),
            )
        )
    if event_type:
        query = query.filter(Event.event_type == event_type)
    if source:
        query = query.filter(Event.source == source)
    if source_ip:
        query = query.filter(Event.source_ip == source_ip)
    if username:
        query = query.filter(Event.username == username)
    if status:
        query = query.filter(Event.status == status)
    if severity:
        query = query.filter(Event.severity == severity)
    if from_time:
        query = query.filter(Event.timestamp >= from_time)
    if to_time:
        query = query.filter(Event.timestamp <= to_time)

    rows = []
    for event in query.order_by(Event.timestamp.desc(), Event.id.desc()).limit(EXPORT_MAX_ROWS):
        rows.append(
            [
                event.id,
                event.timestamp.isoformat(),
                event.event_type,
                event.source_ip or "",
                event.username or "",
                event.status or "",
                event.severity or "",
                event.source or "",
                event.message or "",
            ]
        )
    return csv_response(
        "events.csv",
        ["id", "timestamp", "event_type", "source_ip", "username", "status", "severity", "source", "message"],
        rows,
    )


@router.get("/{event_id}", response_model=EventOut, summary="Get a security event")
def get_event(
    event_id: int,
    db: DbSession,
    _user: Annotated[User, Depends(require_analyst)],
) -> EventOut:
    event = (
        db.query(Event)
        .filter(
            Event.id == event_id,
            Event.user_id == _user.id,
        )
        .first()
    )
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found.")
    return EventOut.model_validate(event)


@router.delete(
    "/mine",
    summary="Clear my imported security data",
)
def clear_my_imported_data(
    db: DbSession,
    _user: Annotated[User, Depends(require_analyst)],
) -> dict:
    """Delete only the current user's imported events, alerts, and investigations."""

    alerts = (
        db.query(Alert)
        .filter(Alert.user_id == _user.id)
        .all()
    )

    events = (
        db.query(Event)
        .filter(Event.user_id == _user.id)
        .all()
    )

    alert_count = len(alerts)
    event_count = len(events)

    for alert in alerts:
        db.delete(alert)

    for event in events:
        db.delete(event)

    db.commit()

    return {
        "status": "ok",
        "events_deleted": event_count,
        "alerts_deleted": alert_count,
    }
