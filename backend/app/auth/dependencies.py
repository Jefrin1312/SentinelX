"""FastAPI dependencies for authentication and authorization.

These dependencies decode the JWT from the HttpOnly session cookie, verify it
was not revoked, and load the current user from the database on every
protected request. The JWT never touches JavaScript or HTTP headers.
"""

from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth.cookies import AUTH_COOKIE
from app.auth.security import decode_access_token
from app.database import get_db
from app.models.audit import TokenBlacklist
from app.models.user import User


def _read_token(request: Request) -> str | None:
    """Return the JWT from the session cookie, or None when absent."""
    return request.cookies.get(AUTH_COOKIE) or None


def _current_user(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> User:
    token = _read_token(request)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated.",
            headers={"WWW-Authenticate": "Cookie"},
        )

    try:
        payload: dict[str, Any] = decode_access_token(token)
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
            headers={"WWW-Authenticate": "Cookie"},
        ) from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
            headers={"WWW-Authenticate": "Cookie"},
        ) from exc

    jti = payload.get("jti")
    if jti is not None:
        revoked = db.query(TokenBlacklist).filter(TokenBlacklist.jti == jti).first()
        if revoked is not None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked.",
                headers={"WWW-Authenticate": "Cookie"},
            )

    user = db.query(User).filter(User.id == int(payload.get("sub", 0))).first()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not active or no longer exists.",
            headers={"WWW-Authenticate": "Cookie"},
        )
    return user


def get_current_user(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Dependency alias used by routes needing any authenticated user."""
    return _current_user(request, db)


def require_admin(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Dependency for administrator-only endpoints."""
    from app.auth.authorization import require_admin as ensure_admin

    return ensure_admin(_current_user(request, db))


def require_analyst(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Dependency for endpoints available to analysts and admins."""
    from app.auth.authorization import require_analyst as ensure_analyst

    return ensure_analyst(_current_user(request, db))


CurrentUser = Annotated[User, Depends(get_current_user)]
AdminUser = Annotated[User, Depends(require_admin)]