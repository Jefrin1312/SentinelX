"""User management schemas (administrator operations)."""

from pydantic import BaseModel, ConfigDict, Field

from app.models.user import UserRole
from app.schemas.auth import UserOut


class UserRoleRequest(BaseModel):
    """Change a user's role. Only ADMIN/ANALYST are valid."""

    role: str = Field(pattern=f"^({'|'.join(UserRole.ALL)})$")


class UserActivateRequest(BaseModel):
    """Enable or disable a user account."""

    is_active: bool


class UserUpdate(BaseModel):
    """Combined administrator update for a user."""

    role: str | None = Field(default=None, pattern=f"^({'|'.join(UserRole.ALL)})$")
    is_active: bool | None = None


class UserListResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    total: int
    items: list[UserOut]