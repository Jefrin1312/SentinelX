"""Event normaliser.

Validates and constrains a parsed log record so it is safe to persist:
field lengths are capped, timestamps are made timezone-aware, empty strings
become null, and metadata is open as a plain JSON dict. Malicious or
malformed content can never alter the database schema or shape.
"""

import ipaddress
from datetime import datetime, timezone

from app.logs.parser import ParsedLog

_MAX = {
    "source_ip": 45,
    "destination_ip": 45,
    "username": 100,
    "event_type": 80,
    "status": 30,
    "severity": 20,
    "source": 30,
    "message": 2000,
}


def _clean(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    if len(value) > _MAX[field]:
        value = value[: _MAX[field]]
    return value


def normalize(parsed: ParsedLog, *, fallback_timestamp: datetime | None = None) -> dict:
    """Convert a ParsedLog into a validated dict ready for the Event ORM."""
    message = (parsed.message or "").strip()
    if not message:
        raise ValueError("Cannot normalise an empty log line")

    timestamp = parsed.timestamp or fallback_timestamp or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return {
        "timestamp": timestamp.astimezone(timezone.utc),
        "source_ip": _clean(parsed.source_ip, "source_ip"),
        "destination_ip": _clean(parsed.destination_ip, "destination_ip"),
        "username": _clean(parsed.username, "username"),
        "event_type": _clean(parsed.event_type, "event_type") or "UNKNOWN",
        "status": _clean(parsed.status, "status") or "UNKNOWN",
        "severity": _clean(parsed.severity, "severity") or "LOW",
        "source": _clean(parsed.source, "source") or "UNKNOWN",
        "message": message[: _MAX["message"]],
        "metadata": dict(parsed.metadata or {}),
    }


def is_likely_ip(value: str | None) -> bool:
    """Boolean helper used by tests; harmless but demonstrates intent."""
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False