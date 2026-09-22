"""Pydantic request/response schemas for the API."""

from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    PasswordChange,
    ProfileUpdate,
    RegisterRequest,
    TokenResponse,
    UserOut,
)
from app.schemas.user import UserActivateRequest, UserListResponse, UserRoleRequest, UserUpdate
from app.schemas.event import EventCreate, EventOut, EventListResponse, LogIngestBatch, LogIngestResponse
from app.schemas.alert import (
    AlertDetailOut,
    AlertListResponse,
    AlertOut,
    AlertStatusRequest,
    RelatedEventOut,
)
from app.schemas.investigation import (
    InvestigationCreate,
    InvestigationDetailOut,
    InvestigationListResponse,
    InvestigationNoteCreate,
    InvestigationNoteOut,
    InvestigationOut,
    InvestigationUpdate,
)
from app.schemas.rule import RuleListResponse, RuleOut, RuleReloadResponse, RuleUpdate
from app.schemas.audit import AuditLogListResponse, AuditLogOut
from app.schemas.report import (
    AlertTypeReport,
    DailyAlertPoint,
    DailyEventPoint,
    ReportSummary,
    SeverityReport,
    StatusReport,
)
from app.schemas.settings import PlatformSettings

__all__ = [
    "RegisterRequest",
    "LoginRequest",
    "LoginResponse",
    "TokenResponse",
    "UserOut",
    "ProfileUpdate",
    "PasswordChange",
    "UserUpdate",
    "UserRoleRequest",
    "UserActivateRequest",
    "UserListResponse",
    "EventCreate",
    "EventOut",
    "EventListResponse",
    "LogIngestBatch",
    "LogIngestResponse",
    "AlertOut",
    "AlertListResponse",
    "AlertStatusRequest",
    "AlertDetailOut",
    "RelatedEventOut",
    "RuleOut",
    "RuleListResponse",
    "RuleUpdate",
    "RuleReloadResponse",
    "InvestigationCreate",
    "InvestigationOut",
    "InvestigationUpdate",
    "InvestigationDetailOut",
    "InvestigationListResponse",
    "InvestigationNoteCreate",
    "InvestigationNoteOut",
    "AuditLogOut",
    "AuditLogListResponse",
    "ReportSummary",
    "DailyEventPoint",
    "DailyAlertPoint",
    "AlertTypeReport",
    "SeverityReport",
    "StatusReport",
    "PlatformSettings",
]