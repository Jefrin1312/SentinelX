"""Startup bootstrap: create tables and seed demo accounts.

Demo credentials are development-only and clearly documented in the README.
In production the seed must be removed or disabled via ``APP_ENV``.
"""

import logging

from sqlalchemy.orm import Session

from app.database import Base, SessionLocal, engine
from app.models.user import User, UserRole
from app.auth.security import hash_password

logger = logging.getLogger("sentinelx.bootstrap")

DEMO_ADMIN_USERNAME = "admin"
DEMO_ADMIN_PASSWORD = "Admin@12345"
DEMO_ADMIN_EMAIL = "admin@sentinelx.example.com"

DEMO_ANALYST_USERNAME = "analyst"
DEMO_ANALYST_PASSWORD = "Analyst@12345"
DEMO_ANALYST_EMAIL = "analyst@sentinelx.example.com"


def init_db() -> None:
    """Create any missing tables and seed demo users."""
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        _seed_user(
            db,
            username=DEMO_ADMIN_USERNAME,
            email=DEMO_ADMIN_EMAIL,
            password=DEMO_ADMIN_PASSWORD,
            role=UserRole.ADMIN,
        )
        _seed_user(
            db,
            username=DEMO_ANALYST_USERNAME,
            email=DEMO_ANALYST_EMAIL,
            password=DEMO_ANALYST_PASSWORD,
            role=UserRole.ANALYST,
        )


def _seed_user(db: Session, *, username: str, email: str, password: str, role: str) -> None:
    if db.query(User).filter(User.username == username).first() is not None:
        return
    db.add(
        User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            role=role,
            is_active=True,
        )
    )
    db.commit()
    logger.info("Seeded demo %s account: %s", role, username)