"""Health check endpoints.

The root ``/api/health`` endpoint is used by container orchestrators and the
frontend to verify the backend process is alive and can reach PostgreSQL.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db

router = APIRouter(tags=["health"])


@router.get("/health", summary="Backend health check")
def health(db: Session = Depends(get_db)) -> dict:
    """Report backend status and PostgreSQL connectivity."""
    settings = get_settings()
    database_ok = True
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        database_ok = False

    return {
        "status": "ok",
        "application": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "database": "up" if database_ok else "down",
        "version": settings.APP_VERSION,
    }