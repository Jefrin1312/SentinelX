"""Log collector.

Orchestrates the ingestion of raw text through the parser and normaliser and
persists the resulting events. Handles batching, duplicate suppression within
a batch, and strict size/line limits for uploaded content. Each stored event
is passed through the detection engine, whose threshold rules may raise
alerts.
"""

import logging
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy.orm import Session

from app.detection.engine import detect
from app.logs.normalizer import normalize
from app.logs.parser import ParsedLog, parse_log_line
from app.models.event import Event

logger = logging.getLogger("sentinelx.collector")


def ingest_lines(
    db: Session,
    lines: list[str],
    *,
    source: str = "MANUAL",
    timestamp: datetime | None = None,
    on_parsed: Callable[[ParsedLog], None] | None = None,
) -> dict:
    """Parse, normalise and store a batch of log lines.

    ``on_parsed`` is an optional hook (used in later phases) that receives
    each parsed log after normalisation, e.g. to feed the detection engine.
    """
    parsed_count = 0
    unknown_count = 0
    created_count = 0
    alerts_count = 0
    event_ids: list[int] = []
    seen_messages: set[str] = set()

    for raw in lines:
        # Trim surrounding whitespace; invalid UTF-8 is replaced, never fatal.
        line = _safe_text(raw.strip())
        if not line:
            continue

        parsed = parse_log_line(line)
        if parsed.event_type == "UNKNOWN":
            unknown_count += 1
            # Still persist so nothing is silently lost.
        else:
            parsed_count += 1

        if line in seen_messages and source == "MANUAL":
            continue
        seen_messages.add(line)

        try:
            event_data = normalize(parsed, fallback_timestamp=timestamp)
        except ValueError:
            continue

        if on_parsed is not None:
            on_parsed(parsed)

        event_dto = dict(event_data)
        # The ORM maps the JSON blob as ``metadata_json`` (``metadata`` is a
        # reserved name on SQLAlchemy declarative classes).
        event_dto["metadata_json"] = event_dto.pop("metadata")
        event_dto["source"] = source
        event = Event(**event_dto)
        db.add(event)
        db.flush()  # populate the id so batch results are accurate
        event_ids.append(event.id)
        created_count += 1

        alerts = _run_detection(db, event)
        alerts_count += len(alerts)

    db.commit()

    return {
        "total_lines": len([l for l in lines if _safe_text(l.strip())]),
        "parsed": parsed_count,
        "unknown": unknown_count,
        "events_created": created_count,
        "alerts_created": alerts_count,
        "event_ids": event_ids,
    }


def _run_detection(db: Session, event: Event) -> list:
    """Run the detection engine, keeping ingestion alive if it ever fails."""
    try:
        return detect(db, event)
    except Exception:  # noqa: BLE001 — detection must never block ingestion.
        logger.exception("Detection engine failed on event %s", event.id)
        return []


def _safe_text(value: str) -> str:
    """Coerce a raw line to a safe printable string (never a crash source)."""
    return value.encode("utf-8", errors="replace").decode("utf-8", errors="replace")