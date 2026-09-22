"""Authentication endpoints: register, login, logout, current user."""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentUser
from app.auth.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.config import get_settings
from app.database import get_db
from app.models.audit import AuditAction, TokenBlacklist
from app.models.user import User, UserRole
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    PasswordChange,
    ProfileUpdate,
    RegisterRequest,
    UserOut,
)
from app.services.audit import write_audit

router = APIRouter(prefix="/auth", tags=["authentication"])

DbSession = Annotated[Session, Depends(get_db)]


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


@router.post(
    "/register",
    response_model=LoginResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new analyst account",
)
def register(payload: RegisterRequest, request: Request, db: DbSession) -> LoginResponse:
    """Create a new account.

    Self registration always produces an ``ANALYST`` account — administrators
    are only created through the configured demo seed. Passwords are hashed
    with bcrypt before storage.
    """
    existing = (
        db.query(User)
        .filter((User.username == payload.username) | (User.email == payload.email))
        .first()
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with that username or email already exists.",
        )

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=UserRole.ANALYST,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    write_audit(
        db,
        user=user,
        action=AuditAction.USER_CREATED,
        resource_type="user",
        resource_id=user.id,
        ip_address=_client_ip(request),
        details={"username": user.username, "role": user.role},
    )

    token, jti = create_access_token(user_id=user.id, username=user.username, role=user.role)
    settings = get_settings()
    return LoginResponse(
        access_token=token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserOut.model_validate(user),
    )


@router.post("/login", response_model=LoginResponse, summary="Log in")
def login(payload: LoginRequest, request: Request, db: DbSession) -> LoginResponse:
    """Authenticate with username and password and receive a JWT."""
    user = db.query(User).filter(User.username == payload.username).first()
    ip = _client_ip(request)

    if user is None or not verify_password(payload.password, user.password_hash):
        write_audit(
            db,
            user=user,
            action=AuditAction.LOGIN_FAILURE,
            resource_type="user",
            resource_id=user.username if user else payload.username,
            ip_address=ip,
            details={"reason": "invalid_credentials"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    if not user.is_active:
        write_audit(
            db,
            user=user,
            action=AuditAction.LOGIN_FAILURE,
            resource_type="user",
            resource_id=user.username,
            ip_address=ip,
            details={"reason": "disabled_account"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been disabled. Contact an administrator.",
        )

    token, jti = create_access_token(user_id=user.id, username=user.username, role=user.role)

    write_audit(
        db,
        user=user,
        action=AuditAction.LOGIN_SUCCESS,
        resource_type="user",
        resource_id=user.id,
        ip_address=ip,
    )

    settings = get_settings()
    return LoginResponse(
        access_token=token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserOut.model_validate(user),
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, summary="Log out")
def logout(request: Request, db: DbSession, current_user: CurrentUser) -> None:
    """Revoke the current JWT so it can no longer be used."""
    bearer = request.headers.get("Authorization", "")
    token = bearer.removeprefix("Bearer ").strip()
    try:
        payload = decode_access_token(token)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token."
        ) from exc

    db.add(
        TokenBlacklist(
            jti=payload["jti"],
            expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
        )
    )
    write_audit(
        db,
        user=current_user,
        action=AuditAction.LOGOUT,
        resource_type="user",
        resource_id=current_user.id,
        ip_address=_client_ip(request),
    )
    db.commit()


@router.get("/me", response_model=UserOut, summary="Get the current user")
def me(current_user: CurrentUser) -> User:
    """Return the currently authenticated user."""
    return current_user


@router.patch("/me", response_model=UserOut, summary="Update own profile")
def update_profile(
    payload: ProfileUpdate,
    request: Request,
    db: DbSession,
    current_user: CurrentUser,
) -> User:
    """Change the authenticated user's own contact email."""
    taken = (
        db.query(User)
        .filter(User.email == payload.email, User.id != current_user.id)
        .first()
    )
    if taken is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with that email already exists.",
        )

    current_user.email = payload.email
    db.commit()
    db.refresh(current_user)

    write_audit(
        db,
        user=current_user,
        action=AuditAction.PROFILE_UPDATED,
        resource_type="user",
        resource_id=current_user.id,
        ip_address=_client_ip(request),
        details={"email": payload.email},
    )
    return current_user


@router.post(
    "/change-password",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Change own password",
)
def change_password(
    payload: PasswordChange,
    request: Request,
    db: DbSession,
    current_user: CurrentUser,
) -> None:
    """Verify the current password, set a new one, and revoke this session.

    The JWT used to authenticate this request is blacklisted, forcing the user
    to sign in again with the new password.
    """
    if not verify_password(payload.current_password, current_user.password_hash):
        write_audit(
            db,
            user=current_user,
            action=AuditAction.LOGIN_FAILURE,
            resource_type="user",
            resource_id=current_user.username,
            ip_address=_client_ip(request),
            details={"reason": "wrong_current_password"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect.",
        )

    current_user.password_hash = hash_password(payload.new_password)
    db.commit()

    bearer = request.headers.get("Authorization", "")
    token = bearer.removeprefix("Bearer ").strip()
    try:
        payload = decode_access_token(token)
    except Exception:
        payload = None
    if payload:
        db.add(
            TokenBlacklist(
                jti=payload["jti"],
                expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
            )
        )
        db.commit()

    write_audit(
        db,
        user=current_user,
        action=AuditAction.PASSWORD_CHANGED,
        resource_type="user",
        resource_id=current_user.id,
        ip_address=_client_ip(request),
    )