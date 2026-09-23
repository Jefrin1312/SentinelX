"""CSRF protection middleware (double-submit cookie + required header).

Authentication is cookie-based, so state-changing requests need an explicit
defense against cross-site request forgery. We use the well-established
double-submit pattern: the server sets a random ``sentinelx_csrf`` cookie that
the browser echoes back in an ``X-CSRF-Token`` header. An attacker on another
origin cannot read the cookie (and SameSite=Lax stops cross-site cookies from
being attached to form posts), so a missing or mismatched header on an
authenticated state-changing request is refused.

Safe methods (GET/HEAD/OPTIONS) are never blocked. Login and registration are
exempt because no session exists yet. Requests without an auth cookie are
passed through and rejected by the authentication dependency (401) rather than
by the CSRF check (403), which keeps the "unauthenticated ⇒ 401" contract.
"""

import hmac

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.auth.cookies import AUTH_COOKIE, CSRF_COOKIE

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_EXEMPT_PATHS = {"/api/auth/login", "/api/auth/register"}


class CSRFMiddleware(BaseHTTPMiddleware):
    """Reject authenticated state-changing requests with a bad CSRF token."""

    async def dispatch(self, request: Request, call_next):
        method = request.method
        path = request.url.path

        if method in _SAFE_METHODS or path in _EXEMPT_PATHS:
            return await call_next(request)

        if AUTH_COOKIE not in request.cookies:
            return await call_next(request)

        cookie_token = request.cookies.get(CSRF_COOKIE, "")
        header_token = request.headers.get("x-csrf-token", "")
        if not cookie_token or not header_token:
            return JSONResponse(
                status_code=403, content={"detail": "CSRF validation failed."}
            )
        if not hmac.compare_digest(cookie_token.encode("utf-8"), header_token.encode("utf-8")):
            return JSONResponse(
                status_code=403, content={"detail": "CSRF validation failed."}
            )

        return await call_next(request)