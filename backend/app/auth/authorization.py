"""Role based access control helpers.

Authorization is ALWAYS enforced server side. The role stored inside the JWT
is merely a convenience hint; the authoritative source of truth is the
``users`` row loaded from the database on every request.
"""

from fastapi import HTTPException, status

from app.models.user import User, UserRole


class AuthorizationError(HTTPException):
    """Raised when the current user lacks permission for an action."""

    def __init__(self, detail: str = "You do not have permission to perform this action.") -> None:
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def require_role(user: User, allowed_roles: tuple[str, ...]) -> User:
    """Return the user when their role is in ``allowed_roles`` else raise 403."""
    if user.role not in allowed_roles:
        raise AuthorizationError()
    return user


def require_admin(user: User) -> User:
    """Admins only."""
    return require_role(user, (UserRole.ADMIN,))


def require_analyst(user: User) -> User:
    """Analysts and admins (any authenticated SOC user)."""
    if not (user.role in (UserRole.ADMIN, UserRole.ANALYST) and user.is_active):
        raise AuthorizationError()
    return user