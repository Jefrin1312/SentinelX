"""Password hashing and JWT token utilities.

Passwords are hashed with bcrypt (adaptive, salted) and never stored in
plaintext. JWTs are signed with HMAC-SHA256 using a secret from the
environment and carry a unique identifier (jti) so tokens can be revoked on
logout.
"""

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import bcrypt
import jwt

from app.config import get_settings


def hash_password(password: str) -> str:
    """Hash a plaintext password with bcrypt and return the salt-embedded hash."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain: str, password_hash: str) -> bool:
    """Compare a plaintext password against a stored bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def create_access_token(*, user_id: int, username: str, role: str) -> tuple[str, int]:
    """Create a signed JWT access token.

    Returns ``(token, jti)``. ``jti`` is stored on logout to revoke the token.
    """
    settings = get_settings()
    expires_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=expires_minutes)
    jti = uuid4().hex

    payload: dict[str, Any] = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": expire,
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token, jti


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT. Raises ``jwt.PyJWTError`` on invalid tokens.

    The token must carry every claim the application issues, and ``sub`` must
    be a positive integer user id. Omitting a claim (or crafting one) is
    treated as invalid so no downstream code ever trusts incomplete tokens.
    """
    settings = get_settings()
    payload = jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["exp", "iat", "sub"]},
    )

    for claim in ("username", "role", "jti"):
        if not payload.get(claim):
            raise jwt.InvalidTokenError(f"Missing claim: {claim}")

    try:
        user_id = int(payload["sub"])
    except (TypeError, ValueError):
        raise jwt.InvalidTokenError("Invalid sub claim.") from None
    if user_id <= 0:
        raise jwt.InvalidTokenError("Invalid sub claim.")
    payload["sub"] = user_id
    return payload