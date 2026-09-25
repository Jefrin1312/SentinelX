"""Security Assistant endpoint.

A single authenticated, CSRF-protected, read-only entry point. The authenticated
session determines the user; the request body may only carry a message and an
optional opaque conversation id. Authorization and record ownership are enforced
in the service and tool layer, never by the client or the model.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.ai import AssistantError, run_chat
from app.ai.schemas import AIChatRequest, AIChatResponse
from app.auth.dependencies import require_analyst
from app.auth.ipaddr import client_ip
from app.database import get_db
from app.models.user import User

router = APIRouter(prefix="/ai", tags=["ai"])

DbSession = Annotated[Session, Depends(get_db)]


@router.post(
    "/chat",
    response_model=AIChatResponse,
    summary="Ask the Security Assistant about your own security data",
)
def ai_chat(
    request: Request,
    db: DbSession,
    user: Annotated[User, Depends(require_analyst)],
    payload: AIChatRequest,
) -> AIChatResponse:
    """Answer a natural-language question from the caller's own SentinelX data.

    ``conversation_id`` is an opaque client-generated id echoed back for UI
    correlation. The assistant is stateless: no server-side conversation or
    history is stored, and the same id is never used for authorization.
    """
    try:
        return run_chat(db, user, payload, client_ip(request))
    except AssistantError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
