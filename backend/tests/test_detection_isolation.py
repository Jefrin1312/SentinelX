"""Detection engine tenant isolation.

A rule threshold must count only the events belonging to the same user as the
event being evaluated. Counting across tenants would let one user's activity
raise an alert in another user's tenant and would leak aggregate counts into
the alert description.
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.detection.engine import detect
from app.models.alert import Alert
from app.models.event import Event
from app.models.rule import DetectionRule
from app.models.user import User, UserRole

SOURCE_IP = "198.51.100.77"


@pytest.fixture
def rule(db):
    name = f"Isolation Rule {uuid.uuid4().hex[:8]}"
    created = DetectionRule(
        name=name,
        description="Two SSH failures from one source ({count} seen).",
        category="authentication",
        severity="HIGH",
        enabled=True,
        threshold=2,
        time_window=300,
        rule_definition={"event_type": "SSH_LOGIN_FAILURE", "key": "source_ip"},
    )
    db.add(created)
    db.commit()
    db.refresh(created)
    return created


def make_user(db, tag: str) -> User:
    username = f"{tag}_{uuid.uuid4().hex[:8]}"
    user = User(
        username=username,
        email=f"{username}@example.com",
        password_hash="!",
        role=UserRole.ANALYST,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def make_failure(db, user: User, source_ip: str = SOURCE_IP) -> Event:
    now = datetime.now(timezone.utc)
    event = Event(
        user_id=user.id,
        timestamp=now,
        source_ip=source_ip,
        username="root",
        event_type="SSH_LOGIN_FAILURE",
        status="UNKNOWN",
        severity="MEDIUM",
        source="sshd",
        message="Failed password for root",
        metadata_json={},
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def test_threshold_does_not_count_another_users_events(db, rule):
    quiet = make_user(db, "quiet")
    noisy = make_user(db, "noisy")

    for _ in range(5):
        make_failure(db, noisy)

    first = make_failure(db, quiet)
    second = make_failure(db, quiet)

    detect(db, first)
    db.commit()
    assert (
        db.query(Alert).filter(Alert.user_id == quiet.id, Alert.rule_id == rule.id).count() == 0
    )

    detect(db, second)
    db.commit()
    alerts = (
        db.query(Alert)
        .filter(Alert.user_id == quiet.id, Alert.rule_id == rule.id)
        .all()
    )
    assert len(alerts) == 1


def test_alert_count_metadata_excludes_other_users_events(db, rule):
    owner = make_user(db, "owner")
    other = make_user(db, "other")

    for _ in range(7):
        make_failure(db, other)

    first = make_failure(db, owner)
    second = make_failure(db, owner)

    detect(db, first)
    detect(db, second)
    db.commit()

    alert = (
        db.query(Alert)
        .filter(Alert.user_id == owner.id, Alert.rule_id == rule.id)
        .one()
    )
    assert alert.metadata_json["count"] == 2
    assert alert.user_id == owner.id
    assert "(2 seen)" in alert.description
    assert "(9 seen)" not in alert.description


def test_no_cross_tenant_alert_is_created_for_the_quiet_user(db, rule):
    quiet = make_user(db, "quiet")
    noisy = make_user(db, "noisy")

    for _ in range(4):
        event = make_failure(db, noisy)
        detect(db, event)
    db.commit()

    assert db.query(Alert).filter(Alert.user_id == noisy.id).count() >= 1
    assert db.query(Alert).filter(Alert.user_id == quiet.id).count() == 0
