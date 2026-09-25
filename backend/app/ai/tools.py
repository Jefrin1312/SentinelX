"""Read-only, user-scoped tools for the Security Assistant.

Every tool re-applies ownership predicates on top of any identifier the model
supplies, so a forged or hallucinated record ID can never cross the tenant
boundary. Tools never accept a user identifier and never expose raw ORM rows,
raw SQL, or unbounded result sets.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError, model_validator
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertStatus, Severity
from app.models.event import Event
from app.models.investigation import Investigation, InvestigationNote, InvestigationStatus
from app.models.rule import DetectionRule

MAX_RESULT_LIMIT = 20
MAX_NOTES = 10
MAX_DASHBOARD_EVENTS = 10
MAX_DASHBOARD_ALERTS = 10
MAX_GROUP_ROWS = 10
MAX_TEXT = 600
MAX_QUERY = 200
MAX_DAYS = 90
MAX_DASHBOARD_DAYS = 30
RULE_DEFINITION_KEYS = (
    "event_type",
    "key",
    "status",
    "reason",
    "signature",
    "description",
    "value",
)
SEVERITIES = (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
EVENT_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN")


class ToolArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class TimeWindowArgs(ToolArguments):
    from_time: AwareDatetime | None = None
    to_time: AwareDatetime | None = None

    @model_validator(mode="after")
    def validate_window(self) -> "TimeWindowArgs":
        if self.from_time is not None and self.to_time is not None:
            if self.from_time > self.to_time:
                raise ValueError("from_time must be earlier than or equal to to_time.")
            if self.to_time - self.from_time > timedelta(days=MAX_DAYS):
                raise ValueError(f"Time range must not exceed {MAX_DAYS} days.")
        return self


class SearchEventsArgs(TimeWindowArgs):
    query: str | None = Field(default=None, max_length=MAX_QUERY)
    event_type: str | None = Field(default=None, max_length=80)
    source_ip: str | None = Field(default=None, max_length=45)
    username: str | None = Field(default=None, max_length=100)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"] | None = None
    limit: int = Field(default=20, ge=1, le=MAX_RESULT_LIMIT)


class GetEventArgs(ToolArguments):
    event_id: int = Field(ge=1)


class SearchAlertsArgs(TimeWindowArgs):
    query: str | None = Field(default=None, max_length=MAX_QUERY)
    alert_type: str | None = Field(default=None, max_length=80)
    status: Literal["OPEN", "INVESTIGATING", "RESOLVED"] | None = None
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    source_ip: str | None = Field(default=None, max_length=45)
    limit: int = Field(default=20, ge=1, le=MAX_RESULT_LIMIT)


class GetAlertArgs(ToolArguments):
    alert_id: int = Field(ge=1)


class GetInvestigationsArgs(TimeWindowArgs):
    alert_id: int | None = Field(default=None, ge=1)
    status: Literal["OPEN", "INVESTIGATING", "RESOLVED"] | None = None
    limit: int = Field(default=20, ge=1, le=MAX_RESULT_LIMIT)


class GetInvestigationArgs(ToolArguments):
    investigation_id: int = Field(ge=1)


class DashboardSummaryArgs(ToolArguments):
    period: Literal["today", "24h", "7d", "30d"] = "24h"


class GetDetectionRuleArgs(ToolArguments):
    rule_id: int | None = Field(default=None, ge=1)
    name: str | None = Field(default=None, max_length=120)

    @model_validator(mode="after")
    def validate_selector(self) -> "GetDetectionRuleArgs":
        if (self.rule_id is None) == (self.name is None):
            raise ValueError("Provide exactly one of rule_id or name.")
        return self


class SearchSecurityActivityArgs(ToolArguments):
    hours: int = Field(default=24, ge=1, le=24 * 30)
    source_ip: str | None = Field(default=None, max_length=45)
    username: str | None = Field(default=None, max_length=100)
    event_type: str | None = Field(default=None, max_length=80)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"] | None = None
    limit: int = Field(default=20, ge=1, le=MAX_RESULT_LIMIT)


class ToolError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _truncate(value: str | None, limit: int = MAX_TEXT) -> str | None:
    if value is None:
        return None
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _event_dict(event: Event) -> dict[str, Any]:
    return {
        "id": event.id,
        "timestamp": event.timestamp.isoformat(),
        "event_type": event.event_type,
        "severity": event.severity,
        "status": event.status,
        "source": event.source,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "username": event.username,
        "message": _truncate(event.message),
    }


def _alert_dict(alert: Alert) -> dict[str, Any]:
    return {
        "id": alert.id,
        "event_id": alert.event_id,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule.name if alert.rule is not None else None,
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "status": alert.status,
        "source_ip": alert.source_ip,
        "created_at": alert.created_at.isoformat(),
        "updated_at": alert.updated_at.isoformat(),
        "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
        "description": _truncate(alert.description),
        "event": _event_dict(alert.event) if alert.event is not None else None,
    }


def _investigation_dict(
    investigation: Investigation, *, include_notes: bool = False
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": investigation.id,
        "alert_id": investigation.alert_id,
        "status": investigation.status,
        "summary": _truncate(investigation.summary),
        "created_at": investigation.created_at.isoformat(),
        "updated_at": investigation.updated_at.isoformat(),
        "resolved_at": investigation.resolved_at.isoformat() if investigation.resolved_at else None,
        "assigned_username": investigation.assignee.username if investigation.assignee else None,
        "alert": None,
        "note_count": len(investigation.notes),
    }
    if investigation.alert is not None:
        data["alert"] = {
            "id": investigation.alert.id,
            "alert_type": investigation.alert.alert_type,
            "severity": investigation.alert.severity,
            "status": investigation.alert.status,
            "source_ip": investigation.alert.source_ip,
            "description": _truncate(investigation.alert.description),
        }
    if include_notes:
        notes = list(investigation.notes)[-MAX_NOTES:]
        data["notes"] = [
            {
                "id": note.id,
                "created_at": note.created_at.isoformat(),
                "author_username": note.author.username if note.author else None,
                "note": _truncate(note.note),
            }
            for note in notes
        ]
    return data


def _rule_dict(rule: DetectionRule) -> dict[str, Any]:
    definition = rule.rule_definition or {}
    return {
        "id": rule.id,
        "name": rule.name,
        "description": _truncate(rule.description, 1000),
        "category": rule.category,
        "severity": rule.severity,
        "enabled": rule.enabled,
        "threshold": rule.threshold,
        "time_window_seconds": rule.time_window,
        "rule_definition": {key: definition[key] for key in RULE_DEFINITION_KEYS if key in definition},
        "updated_at": rule.updated_at.isoformat(),
    }


def _window(
    from_time: datetime | None, to_time: datetime | None, default_days: int
) -> tuple[datetime, datetime]:
    end = to_time or datetime.now(timezone.utc)
    start = from_time or (end - timedelta(days=default_days))
    return start, end


def _safe_term(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _search_events(db: Session, user_id: int, args: SearchEventsArgs, limit: int) -> dict[str, Any]:
    start, end = _window(args.from_time, args.to_time, 30)
    conditions = [
        Event.user_id == user_id,
        Event.timestamp >= start,
        Event.timestamp <= end,
    ]
    if args.event_type:
        conditions.append(Event.event_type == args.event_type)
    if args.source_ip:
        conditions.append(Event.source_ip == args.source_ip)
    if args.username:
        conditions.append(Event.username == args.username)
    if args.severity:
        conditions.append(Event.severity == args.severity)
    if args.query:
        term = _safe_term(args.query)
        conditions.append(
            or_(
                Event.message.ilike(f"%{term}%", escape="\\"),
                Event.username.ilike(f"%{term}%", escape="\\"),
                Event.source_ip.ilike(f"%{term}%", escape="\\"),
                Event.event_type.ilike(f"%{term}%", escape="\\"),
            )
        )
    total = db.query(func.count(Event.id)).filter(and_(*conditions)).scalar() or 0
    events = (
        db.query(Event)
        .filter(and_(*conditions))
        .order_by(Event.timestamp.desc(), Event.id.desc())
        .limit(limit)
        .all()
    )
    return {
        "total_matched": total,
        "events": [_event_dict(event) for event in events],
    }


def _search_alerts(db: Session, user_id: int, args: SearchAlertsArgs, limit: int) -> dict[str, Any]:
    start, end = _window(args.from_time, args.to_time, 30)
    conditions = [
        Alert.user_id == user_id,
        Alert.created_at >= start,
        Alert.created_at <= end,
    ]
    if args.alert_type:
        conditions.append(Alert.alert_type == args.alert_type)
    if args.status:
        conditions.append(Alert.status == args.status)
    if args.severity:
        conditions.append(Alert.severity == args.severity)
    if args.source_ip:
        conditions.append(Alert.source_ip == args.source_ip)
    if args.query:
        term = _safe_term(args.query)
        conditions.append(
            or_(
                Alert.description.ilike(f"%{term}%", escape="\\"),
                Alert.alert_type.ilike(f"%{term}%", escape="\\"),
                Alert.source_ip.ilike(f"%{term}%", escape="\\"),
            )
        )
    total = db.query(func.count(Alert.id)).filter(and_(*conditions)).scalar() or 0
    alerts = (
        db.query(Alert)
        .filter(and_(*conditions))
        .order_by(Alert.created_at.desc(), Alert.id.desc())
        .limit(limit)
        .all()
    )
    return {
        "total_matched": total,
        "alerts": [_alert_dict(alert) for alert in alerts],
    }


def _dashboard_period(period: str) -> datetime:
    now = datetime.now(timezone.utc)
    if period == "today":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    days = {"24h": 1, "7d": 7, "30d": MAX_DASHBOARD_DAYS}[period]
    return now - timedelta(days=days)


def _count(db: Session, model, *conditions) -> int:
    return db.query(func.count(model.id)).filter(and_(*conditions)).scalar() or 0


def _dashboard_summary(
    db: Session, user_id: int, args: DashboardSummaryArgs, available: int
) -> dict[str, Any]:
    start = _dashboard_period(args.period)
    event_base = [Event.user_id == user_id, Event.timestamp >= start]
    alert_base = [Alert.user_id == user_id, Alert.created_at >= start]

    severity_counts = {
        row[0] or "UNKNOWN": row[1]
        for row in db.query(Event.severity, func.count(Event.id))
        .filter(and_(*event_base))
        .group_by(Event.severity)
        .all()
    }
    status_counts = {
        row[0] or "UNKNOWN": row[1]
        for row in db.query(Alert.status, func.count(Alert.id))
        .filter(and_(*alert_base))
        .group_by(Alert.status)
        .all()
    }
    top_event_types = [
        {"event_type": row[0], "count": row[1]}
        for row in db.query(Event.event_type, func.count(Event.id))
        .filter(and_(*event_base), Event.source_ip.isnot(None))
        .group_by(Event.event_type)
        .order_by(func.count(Event.id).desc())
        .limit(MAX_GROUP_ROWS)
        .all()
    ]
    top_source_ips = [
        {"source_ip": row[0], "count": row[1]}
        for row in db.query(Event.source_ip, func.count(Event.id))
        .filter(and_(*event_base), Event.source_ip.isnot(None))
        .group_by(Event.source_ip)
        .order_by(func.count(Event.id).desc())
        .limit(MAX_GROUP_ROWS)
        .all()
    ]
    open_investigations = (
        db.query(func.count(Investigation.id))
        .join(Alert, Investigation.alert_id == Alert.id)
        .filter(
            Alert.user_id == user_id,
            Investigation.status.in_(
                [InvestigationStatus.OPEN, InvestigationStatus.INVESTIGATING]
            ),
        )
        .scalar()
        or 0
    )

    event_limit = min(MAX_DASHBOARD_EVENTS, (available + 1) // 2)
    alert_limit = min(MAX_DASHBOARD_ALERTS, available - event_limit)
    events = (
        db.query(Event)
        .filter(and_(*event_base))
        .order_by(Event.timestamp.desc(), Event.id.desc())
        .limit(event_limit)
        .all()
    )
    alerts = (
        db.query(Alert)
        .filter(and_(*alert_base))
        .order_by(Alert.created_at.desc(), Alert.id.desc())
        .limit(alert_limit)
        .all()
    )
    return {
        "period": args.period,
        "period_start_utc": start.isoformat(),
        "totals": {
            "events": _count(db, Event, *event_base),
            "alerts": _count(db, Alert, *alert_base),
            "open_investigations": open_investigations,
        },
        "event_severity_counts": severity_counts,
        "alert_status_counts": status_counts,
        "top_event_types": top_event_types,
        "top_source_ips": top_source_ips,
        "recent_events": [_event_dict(event) for event in events],
        "recent_alerts": [_alert_dict(alert) for alert in alerts],
    }


def _search_security_activity(
    db: Session, user_id: int, args: SearchSecurityActivityArgs, available: int
) -> dict[str, Any]:
    start = datetime.now(timezone.utc) - timedelta(hours=args.hours)
    conditions = [
        Event.user_id == user_id,
        Event.timestamp >= start,
    ]
    if args.source_ip:
        conditions.append(Event.source_ip == args.source_ip)
    if args.username:
        conditions.append(Event.username == args.username)
    if args.event_type:
        conditions.append(Event.event_type == args.event_type)
    if args.severity:
        conditions.append(Event.severity == args.severity)

    alert_conditions = [Alert.user_id == user_id, Alert.created_at >= start]
    if args.source_ip:
        alert_conditions.append(Alert.source_ip == args.source_ip)

    severity_counts = {
        row[0] or "UNKNOWN": row[1]
        for row in db.query(Event.severity, func.count(Event.id))
        .filter(and_(*conditions))
        .group_by(Event.severity)
        .all()
    }
    total_events = db.query(func.count(Event.id)).filter(and_(*conditions)).scalar() or 0
    total_alerts = db.query(func.count(Alert.id)).filter(and_(*alert_conditions)).scalar() or 0

    alert_reserve = min(5, available // 3)
    event_limit = min(args.limit, max(0, available - alert_reserve))
    events = (
        db.query(Event)
        .filter(and_(*conditions))
        .order_by(Event.timestamp.desc(), Event.id.desc())
        .limit(event_limit)
        .all()
    )
    alerts = (
        db.query(Alert)
        .filter(and_(*alert_conditions))
        .order_by(Alert.created_at.desc(), Alert.id.desc())
        .limit(available - len(events))
        .all()
    )
    return {
        "window_hours": args.hours,
        "window_start_utc": start.isoformat(),
        "totals": {"events": total_events, "alerts": total_alerts},
        "event_severity_counts": severity_counts,
        "events": [_event_dict(event) for event in events],
        "alerts": [_alert_dict(alert) for alert in alerts],
    }


def _tool(name: str, description: str, properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
        },
    }


_TIME_PROPERTIES = {
    "from_time": {
        "type": "string",
        "format": "date-time",
        "description": f"Start of the range (ISO 8601, timezone required). Maximum span {MAX_DAYS} days.",
    },
    "to_time": {
        "type": "string",
        "format": "date-time",
        "description": "End of the range (ISO 8601, timezone required).",
    },
}
_LIMIT_PROPERTY = {
    "type": "integer",
    "minimum": 1,
    "maximum": MAX_RESULT_LIMIT,
    "description": f"Maximum records to return (1-{MAX_RESULT_LIMIT}).",
}
_TEXT_PROPERTY = {"type": "string", "maxLength": MAX_QUERY}

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    _tool(
        "get_my_dashboard_summary",
        "Get an aggregated summary of the current user's security posture: totals, severity and status breakdowns, top event types and source IPs, and recent records. Start here for overview questions such as 'what is happening in my environment'.",
        {
            "period": {
                "type": "string",
                "enum": ["today", "24h", "7d", "30d"],
                "description": "Reporting window. Defaults to 24h.",
            }
        },
        [],
    ),
    _tool(
        "search_my_events",
        "Search the current user's security events with optional filters. Use for questions about specific activity, logins, IPs, users, or event types.",
        {
            "query": {**_TEXT_PROPERTY, "description": "Case-insensitive text search over message, username, source IP and event type."},
            "event_type": {"type": "string", "maxLength": 80},
            "source_ip": {"type": "string", "maxLength": 45},
            "username": {"type": "string", "maxLength": 100},
            "severity": {"type": "string", "enum": list(EVENT_SEVERITIES)},
            "limit": _LIMIT_PROPERTY,
            **_TIME_PROPERTIES,
        },
        [],
    ),
    _tool(
        "get_my_event",
        "Get one of the current user's security events by ID, including a truncated message.",
        {"event_id": {"type": "integer", "minimum": 1, "description": "Event ID."}},
        ["event_id"],
    ),
    _tool(
        "search_my_alerts",
        "Search the current user's alerts with optional filters. Use for questions about detections, alert volume, alert types, or alert status.",
        {
            "query": {**_TEXT_PROPERTY, "description": "Case-insensitive text search over description, alert type and source IP."},
            "alert_type": {"type": "string", "maxLength": 80},
            "status": {"type": "string", "enum": list(AlertStatus.ALL)},
            "severity": {"type": "string", "enum": list(SEVERITIES)},
            "source_ip": {"type": "string", "maxLength": 45},
            "limit": _LIMIT_PROPERTY,
            **_TIME_PROPERTIES,
        },
        [],
    ),
    _tool(
        "get_my_alert",
        "Get one of the current user's alerts by ID, including its linked event and detection rule name.",
        {"alert_id": {"type": "integer", "minimum": 1, "description": "Alert ID."}},
        ["alert_id"],
    ),
    _tool(
        "get_my_investigations",
        "List the current user's investigations, optionally filtered by alert or status. Use for questions about triage progress or open investigations.",
        {
            "alert_id": {"type": "integer", "minimum": 1, "description": "Only investigations for this alert ID."},
            "status": {"type": "string", "enum": list(InvestigationStatus.ALL)},
            "limit": _LIMIT_PROPERTY,
            **_TIME_PROPERTIES,
        },
        [],
    ),
    _tool(
        "get_my_investigation",
        "Get one of the current user's investigations by ID, including a bounded list of its notes and the linked alert summary.",
        {
            "investigation_id": {
                "type": "integer",
                "minimum": 1,
                "description": "Investigation ID.",
            }
        },
        ["investigation_id"],
    ),
    _tool(
        "get_detection_rule",
        "Get a detection rule definition by ID or exact name, including threshold, time window and declarative match conditions. Use to explain why an alert fired.",
        {
            "rule_id": {"type": "integer", "minimum": 1, "description": "Detection rule ID. Provide exactly one of rule_id or name."},
            "name": {"type": "string", "maxLength": 120, "description": "Exact detection rule name. Provide exactly one of rule_id or name."},
        },
        [],
    ),
    _tool(
        "search_security_activity",
        "High-level correlation query over the current user's events and alerts for a time window, with severity breakdown and recent records. Use for questions about a suspicious source IP, user, or attack pattern.",
        {
            "hours": {
                "type": "integer",
                "minimum": 1,
                "maximum": 24 * 30,
                "description": "Window size in hours (1-720).",
            },
            "source_ip": {"type": "string", "maxLength": 45},
            "username": {"type": "string", "maxLength": 100},
            "event_type": {"type": "string", "maxLength": 80},
            "severity": {"type": "string", "enum": list(EVENT_SEVERITIES)},
            "limit": _LIMIT_PROPERTY,
        },
        [],
    ),
]

TOOL_ARGUMENT_MODELS: dict[str, type[ToolArguments]] = {
    "get_my_dashboard_summary": DashboardSummaryArgs,
    "search_my_events": SearchEventsArgs,
    "get_my_event": GetEventArgs,
    "search_my_alerts": SearchAlertsArgs,
    "get_my_alert": GetAlertArgs,
    "get_my_investigations": GetInvestigationsArgs,
    "get_my_investigation": GetInvestigationArgs,
    "get_detection_rule": GetDetectionRuleArgs,
    "search_security_activity": SearchSecurityActivityArgs,
}

TOOL_NAMES = tuple(TOOL_ARGUMENT_MODELS)


class ToolRegistry:
    """Executes approved tools for a single authenticated user."""

    def __init__(self, db: Session, user_id: int, max_context_records: int) -> None:
        self._db = db
        self._user_id = user_id
        self._available = max(0, min(MAX_RESULT_LIMIT, max_context_records))

    def execute(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        model = TOOL_ARGUMENT_MODELS.get(name)
        if model is None:
            return self._error("unknown_tool", "That tool is not available. Use one of the approved read-only tools.")
        if not isinstance(arguments, dict):
            return self._error("invalid_arguments", "Tool arguments must be an object.")
        try:
            args = model.model_validate(arguments)
        except ValidationError:
            return self._error(
                "invalid_arguments",
                "Tool arguments were invalid. Check filter names, value types and limits, then retry once.",
            )
        if self._available <= 0:
            return self._error("limit_reached", "The record budget for this answer is exhausted. Answer with what you already have.")
        try:
            return self._dispatch(name, args)
        except ToolError as exc:
            return self._error(exc.code, exc.message)
        except Exception:  # noqa: BLE001 — never leak internal errors or SQL to the model.
            return self._error("tool_failed", "The tool could not complete the request. Answer without it.")

    def _error(self, code: str, message: str) -> dict[str, Any]:
        return {"ok": False, "error": {"code": code, "message": message}}

    def _limit(self, requested: int) -> int:
        return max(0, min(requested, self._available))

    def _sources(self, *groups: dict[str, list]) -> list[dict[str, Any]]:
        sources: list[dict[str, Any]] = []
        for group in groups:
            for source_type, records in group.items():
                for record in records:
                    sources.append({"type": source_type, "id": record["id"]})
        return sources

    def _dispatch(self, name: str, args: ToolArguments) -> dict[str, Any]:
        db, user_id = self._db, self._user_id
        if name == "get_my_dashboard_summary":
            summary = _dashboard_summary(db, user_id, args, self._available)  # type: ignore[arg-type]
            self._available -= len(summary["recent_events"]) + len(summary["recent_alerts"])
            return {
                "ok": True,
                "data": summary,
                "sources": self._sources(
                    {
                        "event": summary["recent_events"],
                        "alert": summary["recent_alerts"],
                    }
                ),
            }
        if name == "search_my_events":
            limit = self._limit(args.limit)  # type: ignore[attr-defined]
            data = _search_events(db, user_id, args, limit)  # type: ignore[arg-type]
            self._available -= len(data["events"])
            return {
                "ok": True,
                "data": data,
                "sources": self._sources({"event": data["events"]}),
            }
        if name == "get_my_event":
            event = (
                db.query(Event)
                .filter(Event.user_id == user_id, Event.id == args.event_id)  # type: ignore[attr-defined]
                .first()
            )
            if event is None:
                raise ToolError("not_found", "That event does not exist or is not visible to you.")
            data = _event_dict(event)
            self._available -= 1
            return {"ok": True, "data": {"event": data}, "sources": self._sources({"event": [data]})}
        if name == "search_my_alerts":
            limit = self._limit(args.limit)  # type: ignore[attr-defined]
            data = _search_alerts(db, user_id, args, limit)  # type: ignore[arg-type]
            self._available -= len(data["alerts"])
            return {
                "ok": True,
                "data": data,
                "sources": self._sources({"alert": data["alerts"]}),
            }
        if name == "get_my_alert":
            alert = (
                db.query(Alert)
                .filter(Alert.user_id == user_id, Alert.id == args.alert_id)  # type: ignore[attr-defined]
                .first()
            )
            if alert is None:
                raise ToolError("not_found", "That alert does not exist or is not visible to you.")
            data = _alert_dict(alert)
            self._available -= 1
            return {"ok": True, "data": {"alert": data}, "sources": self._sources({"alert": [data]})}
        if name == "get_my_investigations":
            limit = self._limit(args.limit)  # type: ignore[attr-defined]
            start, end = _window(args.from_time, args.to_time, 90)  # type: ignore[attr-defined]
            conditions = [
                Alert.user_id == user_id,
                Investigation.updated_at >= start,
                Investigation.updated_at <= end,
            ]
            if args.alert_id is not None:  # type: ignore[attr-defined]
                conditions.append(Investigation.alert_id == args.alert_id)  # type: ignore[attr-defined]
            if args.status:  # type: ignore[attr-defined]
                conditions.append(Investigation.status == args.status)  # type: ignore[attr-defined]
            investigations = (
                db.query(Investigation)
                .join(Alert, Investigation.alert_id == Alert.id)
                .filter(and_(*conditions))
                .order_by(Investigation.updated_at.desc(), Investigation.id.desc())
                .limit(limit)
                .all()
            )
            data = [_investigation_dict(investigation) for investigation in investigations]
            self._available -= len(data)
            return {
                "ok": True,
                "data": {"total_matched": len(data), "investigations": data},
                "sources": self._sources({"investigation": data}),
            }
        if name == "get_my_investigation":
            investigation = (
                db.query(Investigation)
                .join(Alert, Investigation.alert_id == Alert.id)
                .filter(Alert.user_id == user_id, Investigation.id == args.investigation_id)  # type: ignore[attr-defined]
                .first()
            )
            if investigation is None:
                raise ToolError(
                    "not_found", "That investigation does not exist or is not visible to you."
                )
            data = _investigation_dict(investigation, include_notes=True)
            self._available -= 1
            return {
                "ok": True,
                "data": {"investigation": data},
                "sources": self._sources({"investigation": [data]}),
            }
        if name == "get_detection_rule":
            query = db.query(DetectionRule)
            if args.rule_id is not None:  # type: ignore[attr-defined]
                query = query.filter(DetectionRule.id == args.rule_id)  # type: ignore[attr-defined]
            else:
                query = query.filter(DetectionRule.name == args.name)  # type: ignore[attr-defined]
            rule = query.first()
            if rule is None:
                raise ToolError("not_found", "No detection rule matched that selector.")
            data = _rule_dict(rule)
            self._available -= 1
            return {
                "ok": True,
                "data": {"rule": data},
                "sources": self._sources({"detection_rule": [data]}),
            }
        if name == "search_security_activity":
            data = _search_security_activity(db, user_id, args, self._available)  # type: ignore[arg-type]
            self._available -= len(data["events"]) + len(data["alerts"])
            return {
                "ok": True,
                "data": data,
                "sources": self._sources(
                    {"event": data["events"], "alert": data["alerts"]}
                ),
            }
        raise ToolError("unknown_tool", "That tool is not available.")
