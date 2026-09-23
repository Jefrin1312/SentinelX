"""HttpOnly session cookie handling for cookie-based authentication.

The JWT is delivered inside an HttpOnly cookie so JavaScript cannot read it.
A second, non-HttpOnly cookie carries a per-session CSRF token for the
double-submit pattern: the frontend reads it and echoes it back in the
``X-CSRF-Token`` header on state-changing requests.
"""

import secrets

from fastapi import Response

from app.config import get_settings

AUTH_COOKIE = "sentinelx_token"
CSRF_COOKIE = "sentinelx_csrf"


def _shared_flags(max_age: int | None) -> dict:
    settings = get_settings()
    return {
        "path": "/",
        "samesite": "lax",
        "secure": settings.COOKIE_SECURE,
        "max_age": max_age,
    }


def new_csrf_token() -> str:
    """Return a fresh random CSRF token for a new session."""
    return secrets.token_urlsafe(32)


def issue_auth_session(response: Response, jwt_token: str) -> str:
    """Set the HttpOnly auth cookie and the readable CSRF cookie.

    Both cookies share the JWT expiry so the CSRF guard is gone exactly when
    the session expires. Returns the CSRF token.
    """
    settings = get_settings()
    max_age = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    flags = _shared_flags(max_age)

    response.set_cookie(
        AUTH_COOKIE,
        jwt_token,
        httponly=True,
        **flags,
    )

    csrf = new_csrf_token()
    response.set_cookie(
        CSRF_COOKIE,
        csrf,
        httponly=False,
        **flags,
    )
    return csrf


def clear_auth_session(response: Response) -> None:
    """Delete the auth and CSRF cookies (used on logout)."""
    settings = get_settings()
    flags = {
        "path": "/",
        "samesite": "lax",
        "secure": settings.COOKIE_SECURE,
    }
    response.delete_cookie(AUTH_COOKIE, **flags)
    response.delete_cookie(CSRF_COOKIE, **flags)