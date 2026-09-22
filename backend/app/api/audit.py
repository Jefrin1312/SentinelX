"""Audit log viewing endpoints (administrator only).

The audit log is written by every security-sensitive action; this router makes
the trail searchable and filterable so SOC admins can review who did what and
when.
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.auth.dependencies import require_admin
from app.database import get_db
from app.models.audit import AuditLog
from app.models.user import User
from app.schemas.audit import AuditLogListResponse, AuditLogOut

router = APIRouter(prefix="/audit-logs", tags=["audit"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=AuditLogListResponse, summary="List audit log entries (admin)")
def list_audit_logs(
    db: DbSession,
    _user: Annotated[User, Depends(require_admin)],
    action: str | None = Query(default=None, max_length=60),
    username: str | None = Query(default=None, max_length=50),
    resource_type: str | None = Query(default=None, max_length=40),
    search: str | None = Query(default=None, max_length=200),
    from_time: datetime | None = Query(default=None),
    to_time: datetime | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> AuditLogListResponse:
    """Searchable, filterable, paginated audit trail, newest first."""
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)
    if username:
        query = query.filter(AuditLog.username.ilike(f"%{username}%"))
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)
    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(
                AuditLog.username.ilike(pattern),
                AuditLog.action.ilike(pattern),
                AuditLog.resource_id.ilike(pattern),
            )
        )
    if from_time:
        query = query.filter(AuditLog.timestamp >= from_time)
    if to_time:
        query = query.filter(AuditLog.timestamp <= to_time)

    total = query.count()
    items = (
        query.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return AuditLogListResponse(
        total=total, items=[AuditLogOut.model_validate(entry) for entry in items]
    )