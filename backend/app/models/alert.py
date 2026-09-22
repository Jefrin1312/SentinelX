"""Security alert model produced by the detection engine."""

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Severity:
    """Alert severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    ALL = (LOW, MEDIUM, HIGH, CRITICAL)
    LEVEL = {LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4}


class AlertStatus:
    """Lifecycle status of an alert."""

    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"

    ALL = (OPEN, INVESTIGATING, RESOLVED)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int | None] = mapped_column(ForeignKey("events.id", ondelete="SET NULL"))
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("detection_rules.id", ondelete="SET NULL"))
    alert_type: Mapped[str] = mapped_column(String(80), index=True)
    severity: Mapped[str] = mapped_column(String(20), default=Severity.MEDIUM, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    description: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(
        String(20), default=AlertStatus.OPEN, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    rule = relationship("DetectionRule", lazy="joined")
    event = relationship("Event", lazy="joined")
    investigations = relationship(
        "Investigation", back_populates="alert", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Alert {self.id} {self.alert_type} {self.severity}>"