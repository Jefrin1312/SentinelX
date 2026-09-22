"""Investigation schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.investigation import InvestigationStatus


class InvestigationCreate(BaseModel):
    """Open a new investigation linked to an alert."""

    alert_id: int
    summary: str | None = Field(default=None, max_length=4000)


class InvestigationUpdate(BaseModel):
    """Advance an investigation to a new status or update its summary."""

    status: str | None = Field(default=None, pattern=f"^({'|'.join(InvestigationStatus.ALL)})$")
    summary: str | None = Field(default=None, max_length=4000)


class InvestigationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: int
    assigned_to: int | None
    assignee_username: str | None = None
    status: str
    summary: str | None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None


class InvestigationNoteCreate(BaseModel):
    note: str = Field(min_length=1, max_length=4000)


class InvestigationNoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    investigation_id: int
    user_id: int | None
    author_username: str | None = None
    note: str
    created_at: datetime