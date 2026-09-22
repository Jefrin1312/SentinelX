"""Administrator-only user management endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.auth.dependencies import AdminUser, CurrentUser
from app.database import get_db
from app.models.audit import AuditAction
from app.models.user import User, UserRole
from app.schemas.user import UserListResponse, UserOut, UserUpdate
from app.services.audit import write_audit

router = APIRouter(prefix="/users", tags=["users"])

DbSession = Annotated[Session, Depends(get_db)]


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


@router.get("", response_model=UserListResponse, summary="List users (admin)")
def list_users(
    db: DbSession,
    current_user: AdminUser,
    search: str | None = Query(default=None, max_length=50),
    role: str | None = Query(default=None, pattern=f"^({'|'.join(UserRole.ALL)})$"),
    active: bool | None = None,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=25, ge=1, le=100),
) -> UserListResponse:
    """Search, filter, and paginate user accounts."""
    query = db.query(User)
    if search:
        pattern = f"%{search}%"
        query = query.filter(or_(User.username.ilike(pattern), User.email.ilike(pattern)))
    if role:
        query = query.filter(User.role == role)
    if active is not None:
        query = query.filter(User.is_active == active)

    total = query.count()
    items = query.order_by(User.created_at).offset(skip).limit(limit).all()
    return UserListResponse(total=total, items=[UserOut.model_validate(u) for u in items])


@router.patch("/{user_id}", response_model=UserOut, summary="Update a user (admin)")
def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    db: DbSession,
    current_user: AdminUser,
) -> UserOut:
    """Change a user's role or active state.

    Protects against disabling or demoting the final active administrator.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    would_remove_admin_privilege = False
    if user.role == UserRole.ADMIN and user.is_active:
        admins = (
            db.query(User)
            .filter(User.role == UserRole.ADMIN, User.is_active.is_(True))
            .count()
        )
        if admins <= 1:
            if (payload.role is not None and payload.role != UserRole.ADMIN) or (
                payload.is_active is False
            ):
                would_remove_admin_privilege = True

    if would_remove_admin_privilege and user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot disable or demote the only active administrator.",
        )

    changed: list[str] = []
    if payload.role is not None and payload.role != user.role:
        user.role = payload.role
        changed.append(f"role={payload.role}")
        write_audit(
            db,
            user=current_user,
            action=AuditAction.USER_ROLE_CHANGED,
            resource_type="user",
            resource_id=user.id,
            ip_address=_client_ip(request),
            details={"target": user.username, "role": payload.role},
        )
    if payload.is_active is not None and payload.is_active != user.is_active:
        user.is_active = payload.is_active
        changed.append(f"active={payload.is_active}")
        action = AuditAction.USER_ENABLED if payload.is_active else AuditAction.USER_DISABLED
        write_audit(
            db,
            user=current_user,
            action=action,
            resource_type="user",
            resource_id=user.id,
            ip_address=_client_ip(request),
            details={"target": user.username},
        )

    db.add(user)
    db.commit()
    db.refresh(user)
    return UserOut.model_validate(user)