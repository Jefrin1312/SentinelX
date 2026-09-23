"""Startup bootstrap: create tables and seed demo accounts."""

import logging

from sqlalchemy.orm import Session

from app.auth.security import hash_password
from app.config import get_settings
from app.database import Base, SessionLocal, engine
from app.detection.loader import load_rules
from app.models.user import User, UserRole

logger = logging.getLogger("sentinelx.bootstrap")

DEMO_ADMIN_USERNAME = "admin"
DEMO_ADMIN_PASSWORD = "Admin@12345"
DEMO_ADMIN_EMAIL = "admin@sentinelx.example.com"

DEMO_ANALYST_USERNAME = "analyst"
DEMO_ANALYST_PASSWORD = "Analyst@12345"
DEMO_ANALYST_EMAIL = "analyst@sentinelx.example.com"


def init_db() -> None:
    """Create missing tables, optionally seed demo users, and load rules."""
    settings = get_settings()

    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        if settings.APP_ENV.lower() != "production":
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
        else:
            logger.info("Production mode: demo user seeding disabled.")

        load_rules(db)


def _seed_user(
    db: Session,
    *,
    username: str,
    email: str,
    password: str,
    role: str,
) -> None:
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
