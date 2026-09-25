from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.config import get_settings


class AIChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    message: str = Field(min_length=1)
    conversation_id: UUID | None = None

    @field_validator("message")
    @classmethod
    def validate_message(cls, value: str) -> str:
        maximum = get_settings().AI_MAX_MESSAGE_LENGTH
        if not value:
            raise ValueError("Message must not be empty.")
        if len(value) > maximum:
            raise ValueError(f"Message must not exceed {maximum} characters.")
        return value


class AISource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["event", "alert", "investigation", "investigation_note", "detection_rule"]
    id: int = Field(ge=1)


class AIChatResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=12000)
    conversation_id: UUID
    sources: list[AISource] = Field(default_factory=list, max_length=20)
