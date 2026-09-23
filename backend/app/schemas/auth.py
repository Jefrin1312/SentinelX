"""Authentication request/response schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class RegisterRequest(BaseModel):
    """Payload for creating a new account."""

    username: str = Field(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_\-\.]+$")
    email: EmailStr
    password: str = Field(min_length=10, max_length=72, description="10+ character password")


class LoginRequest(BaseModel):
    """Payload for logging in an existing account."""

    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=1, max_length=72)


class UserOut(BaseModel):
    """Public representation of a user — never includes the password hash."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: EmailStr
    role: str
    is_active: bool
    created_at: datetime


class LoginResponse(BaseModel):
    """Successful login/registration.

    Deliberately does NOT include the access token: the JWT is delivered ONLY
    via the HttpOnly session cookie so it never appears in JSON, headers, or
    client-side storage.
    """

    user: UserOut
    expires_in: int


class ProfileUpdate(BaseModel):
    """Update the authenticated user's own contact details."""

    email: EmailStr


class PasswordChange(BaseModel):
    """Change the authenticated user's own password."""

    current_password: str = Field(min_length=1, max_length=72)
    new_password: str = Field(min_length=10, max_length=72, description="10+ character password")