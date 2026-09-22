"""Platform settings endpoints (administrator only).

Reports the operational configuration that is safe to show a SOC admin —
never secrets such as database URLs or signing keys.
"""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth.dependencies import require_admin
from app.config import get_settings
from app.database import get_db
from app.models.rule import DetectionRule
from app.models.user import User
from app.schemas.settings import PlatformSettings

router = APIRouter(prefix="/settings", tags=["settings"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=PlatformSettings, summary="Platform settings (admin)")
def platform_settings(
    db: DbSession, _user: Annotated[User, Depends(require_admin)]
) -> PlatformSettings:
    """Read-only view of the platform configuration and live counts."""
    settings = get_settings()
    return PlatformSettings(
        app_name=settings.APP_NAME,
        app_env=settings.APP_ENV,
        app_version=settings.APP_VERSION,
        api_prefix=settings.API_PREFIX,
        debug=settings.DEBUG,
        jwt_expire_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        login_rate_limit=settings.LOGIN_RATE_LIMIT,
        max_upload_mb=settings.MAX_UPLOAD_SIZE_MB,
        max_upload_lines=settings.MAX_UPLOAD_LINES,
        sample_logs_dir=settings.SAMPLE_LOGS_DIR,
        rules_dir=settings.RULES_DIR,
        rule_count=db.query(func.count(DetectionRule.id)).scalar() or 0,
        user_count=db.query(func.count(User.id)).scalar() or 0,
    )