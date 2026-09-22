"""Detection engine.

Evaluates each normalised event against the enabled detection rules and
generates an alert when a rule's threshold is crossed inside its time window.
Rules are pure declarative configuration:

* ``event_type``   — one normalised event type (or a list) to match
* ``key``          — grouping field for the threshold count: ``source_ip`` or ``username``
* ``status``       — optional event status to require
* ``reason``       — optional ``metadata.reason`` value to require
* ``signature``    — optional ``metadata.suspicious_signatures`` member to require

Detection is deliberately deniable: any error is logged and swallowed so a
misbehaving rule can never block the log pipeline.
"""

import logging
from datetime import timedelta

from sqlalchemy import and_, func
from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertStatus
from app.models.event import Event
from app.models.rule import DetectionRule

logger = logging.getLogger("sentinelx.detection")

# Grouping fields the engine is allowed to count thresholds over.
KEY_FIELDS = ("source_ip", "username")


def detect(db: Session, event: Event) -> list[Alert]:
    """Run the event through all enabled rules, returning any new alerts.

    Alerts are added (but not committed) to the session so the caller controls
    the transaction boundary, e.g. the collector's batch commit.
    """
    if event.id is None:
        db.flush()
    rules = (
        db.query(DetectionRule)
        .filter(DetectionRule.enabled.is_(True))
        .order_by(DetectionRule.id)
        .all()
    )
    created: list[Alert] = []
    for rule in rules:
        try:
            alert = _evaluate_rule(db, rule, event)
        except Exception:  # noqa: BLE001 — a rule must never break ingestion.
            logger.exception("Detection rule %s failed on event %s", rule.name, event.id)
            continue
        if alert is not None:
            created.append(alert)
    return created


def _evaluate_rule(db: Session, rule: DetectionRule, event: Event) -> Alert | None:
    definition = rule.rule_definition or {}
    event_types = definition.get("event_type")
    if event_types is None:
        return None
    if isinstance(event_types, str):
        event_types = [event_types]
    if event.event_type not in event_types:
        return None

    status = definition.get("status")
    if status and event.status != status:
        return None
    metadata = event.metadata_json or {}
    reason = definition.get("reason")
    if reason and metadata.get("reason") != reason:
        return None
    signature = definition.get("signature")
    if signature and signature not in (metadata.get("suspicious_signatures") or []):
        return None

    key = definition.get("key", "source_ip")
    if key not in KEY_FIELDS:
        return None
    key_value = getattr(event, key)
    if not key_value:
        return None

    window = max(1, rule.time_window or 300)
    since = event.timestamp - timedelta(seconds=window)

    conditions = [
        Event.event_type.in_(event_types),
        Event.timestamp >= since,
        Event.timestamp <= event.timestamp,
        getattr(Event, key) == key_value,
    ]
    if status:
        conditions.append(Event.status == status)
    if reason:
        conditions.append(Event.metadata_json["reason"].as_string() == reason)
    if signature:
        conditions.append(
            Event.metadata_json["suspicious_signatures"].as_string().contains(signature)
        )

    count = db.query(func.count(Event.id)).filter(and_(*conditions)).scalar()
    threshold = max(1, rule.threshold or 1)
    if count < threshold:
        return None

    # Suppress duplicates: don't raise a second alert for the same rule and
    # grouping value while an earlier OPEN alert from this rule is still live.
    existing = (
        db.query(Alert)
        .filter(
            Alert.rule_id == rule.id,
            Alert.status == AlertStatus.OPEN,
            Alert.metadata_json["key"].as_string() == key,
            Alert.metadata_json["key_value"].as_string() == str(key_value),
        )
        .first()
    )
    if existing is not None:
        return None

    description = rule.description
    description = description.replace("{key_value}", str(key_value)).replace("{count}", str(count))

    alert = Alert(
        event_id=event.id,
        rule_id=rule.id,
        alert_type=rule.name[:80],
        severity=rule.severity.upper(),
        source_ip=event.source_ip,
        description=description,
        status=AlertStatus.OPEN,
        metadata_json={
            "key": key,
            "key_value": str(key_value),
            "count": count,
            "matched_event_types": event_types,
        },
    )
    db.add(alert)
    logger.info(
        "Alert raised: rule=%s key=%s=%s count=%s",
        rule.name,
        key,
        key_value,
        count,
    )
    return alert