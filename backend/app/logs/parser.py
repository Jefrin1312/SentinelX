"""Log parser.

Turns a raw log line into a structured, normalised record. Only declarative
regular-expression matching is used — input is always treated as data and is
never executed or interpolated into anything dangerous.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

UNKNOWN_TYPE = "UNKNOWN"


@dataclass
class ParsedLog:
    """Structured representation of one log line before normalisation."""

    event_type: str
    status: str
    severity: str
    source: str
    message: str
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    timestamp: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------- SSH login

_RE_SSH_FAILED_USER = re.compile(
    r"Failed password for invalid user (\S+) from (\S+) port \d+ ssh2"
)
_RE_SSH_FAILED = re.compile(
    r"Failed password for (\S+) from (\S+) port \d+ (?:ssh2|sshd\D)"
)
_RE_SSH_OVER_LIMIT = re.compile(
    r"maximum authentication attempts exceeded for (\S+) from (\S+) port \d+ ssh2"
)
_RE_SSH_INVALID_USER = re.compile(r"Invalid user (\S+) from (\S+) port \d+")
_RE_SSH_ACCEPT_PASSWORD = re.compile(r"Accepted password for (\S+) from (\S+) port \d+ ssh2")
_RE_SSH_ACCEPT_PUBKEY = re.compile(r"Accepted publickey for (\S+) from (\S+) port \d+ ssh2")
_RE_SSH_AUTH_FAILURE = re.compile(
    r"authentication failure; logname=(\S*) uid=\d+ euid=\d+ tty=(\S+) ruser=(\S*) rhost=(\S+) user=(\S+)"
)
_RE_SSH_BAD_METHOD = re.compile(r"Failed method (\S+) for invalid user (\S+) from (\S+) port \d+ ssh2")
_RE_SSH_DISCONNECT_PREAUTH = re.compile(
    r"Connection (?:closed|reset) by (?:invalid user )?(\S+) (\S+) port \d+ \[preauth\]"
)
_RE_SSH_RECV_DISCONNECT = re.compile(
    r"Received disconnect from (\S+): \d+: .+ \[preauth\]"
)

# ------------------------------------------------------------- system/user

_RE_SUDO = re.compile(r"(\S+) : TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(.+)$")
_SYSLOG_PREFIX = re.compile(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\b")
_RE_USERADD = re.compile(
    r"useradd\[(?:\d+)\]: new user: name=(\S+), UID=\d+, GID=\d+, home=(\S+), shell=(\S+)"
)
_RE_USERDEL = re.compile(r"userdel\[\d+\]: deleted user '(\S+)'")

# -------------------------------------------------------------------- HTTP

_RE_HTTP = re.compile(
    r"^(\S+) - (\S+) \[([^\]]+)\] \"(\S+) (\S+) HTTP/\d\.\d\" (\d{3}) (\S+|\-).*$"
)

# Suspicious request signatures — detection only, payloads are never executed.
_SUSPICIOUS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("path_traversal", re.compile(r"(\.\./){1,}|\.\.|%2e%2e", re.IGNORECASE)),
    ("sql_injection", re.compile(r"(\bunion\s+select|union%20select|\bselect\s+.*\bfrom\b|'(\s|-|%)|\bor\s+1=1)", re.IGNORECASE)),
    ("command_injection", re.compile(r"[;&|]\s*(cat|bash|sh|whoami|id|nc|wget|curl)\b|`.*`|%00", re.IGNORECASE)),
    ("xss_attempt", re.compile(r"<script|javascript:|onerror\s*=|alert\s*\(", re.IGNORECASE)),
    ("encoded_payload", re.compile(r"(%[0-9a-fA-F]{2}){6,}")),
]

HTTP_SUSPICIOUS_TYPES = {"path_traversal", "sql_injection", "command_injection", "xss_attempt", "encoded_payload"}


def parse_log_line(line: str) -> ParsedLog:
    """Parse a single raw log line into a ParsedLog.

    Unknown lines never raise — they become ``UNKNOWN`` events with the
    original message preserved so nothing is silently lost.
    """
    message = line.rstrip("\n")
    if not message.strip():
        return ParsedLog(
            event_type=UNKNOWN_TYPE,
            status="UNKNOWN",
            severity="LOW",
            source="UNKNOWN",
            message=message,
        )

    parsed = _match_ssh(message)
    if parsed:
        if parsed.timestamp is None:
            parsed.timestamp = _extract_syslog_prefix(message)
        return parsed

    parsed = _match_system(message)
    if parsed:
        if parsed.timestamp is None:
            parsed.timestamp = _extract_syslog_prefix(message)
        return parsed

    parsed = _match_http(message)
    if parsed:
        return parsed

    return ParsedLog(
        event_type=UNKNOWN_TYPE,
        status="UNKNOWN",
        severity="LOW",
        source="UNKNOWN",
        message=message,
    )


def _match_ssh(message: str) -> ParsedLog | None:
    match = _RE_SSH_FAILED_USER.search(message)
    if match:
        return _parsed(
            "SSH_LOGIN_FAILURE", "FAILED", "SSH", message,
            username=match.group(1), source_ip=match.group(2),
            metadata={"reason": "invalid_user"},
        )
    match = _RE_SSH_FAILED.search(message)
    if match:
        return _parsed(
            "SSH_LOGIN_FAILURE", "FAILED", "SSH", message,
            username=match.group(1), source_ip=match.group(2),
        )
    match = _RE_SSH_OVER_LIMIT.search(message)
    if match:
        return _parsed(
            "SSH_LOGIN_FAILURE", "FAILED", "SSH", message,
            username=match.group(1), source_ip=match.group(2),
            metadata={"reason": "max_attempts"},
        )
    match = _RE_SSH_INVALID_USER.search(message)
    if match:
        return _parsed(
            "SSH_LOGIN_FAILURE", "FAILED", "SSH", message,
            username=match.group(1), source_ip=match.group(2),
            metadata={"reason": "invalid_user"},
        )
    match = _RE_SSH_BAD_METHOD.search(message)
    if match:
        return _parsed(
            "SSH_LOGIN_FAILURE", "FAILED", "SSH", message,
            username=match.group(2), source_ip=match.group(3),
            metadata={"reason": "bad_method", "method": match.group(1)},
        )

    match = _RE_SSH_ACCEPT_PASSWORD.search(message)
    if match:
        return _parsed(
            "SSH_LOGIN_SUCCESS", "SUCCESS", "SSH", message,
            username=match.group(1), source_ip=match.group(2),
            metadata={"method": "password"},
        )
    match = _RE_SSH_ACCEPT_PUBKEY.search(message)
    if match:
        return _parsed(
            "SSH_LOGIN_SUCCESS", "SUCCESS", "SSH", message,
            username=match.group(1), source_ip=match.group(2),
            metadata={"method": "publickey"},
        )

    match = _RE_SSH_AUTH_FAILURE.search(message)
    if match:
        return _parsed(
            "AUTH_FAILURE", "FAILED", "AUTH", message,
            username=match.group(5) or None,
            source_ip=match.group(4) or None,
        )

    match = _RE_SSH_DISCONNECT_PREAUTH.search(message)
    if match:
        return _parsed(
            "SSH_LOGIN_FAILURE", "FAILED", "SSH", message,
            username=match.group(1), source_ip=match.group(2),
            metadata={"reason": "preauth_disconnect"},
        )

    match = _RE_SSH_RECV_DISCONNECT.search(message)
    if match:
        return _parsed(
            "SSH_LOGIN_FAILURE", "FAILED", "SSH", message,
            source_ip=match.group(1), metadata={"reason": "preauth_disconnect"},
        )

    return None


def _match_system(message: str) -> ParsedLog | None:
    match = _RE_SUDO.search(message)
    if match:
        return _parsed(
            "SUDO_COMMAND", "SUCCESS", "AUTH", message,
            username=match.group(1),
            metadata={"target_user": match.group(4), "command": match.group(5)[:500]},
        )

    match = _RE_USERADD.search(message)
    if match:
        return _parsed(
            "USER_CREATED", "SUCCESS", "AUTH", message,
            username=match.group(1),
            metadata={"home": match.group(2), "shell": match.group(3)},
        )

    match = _RE_USERDEL.search(message)
    if match:
        return _parsed(
            "USER_DELETED", "SUCCESS", "AUTH", message, username=match.group(1)
        )

    return None


def _match_http(message: str) -> ParsedLog | None:
    match = _RE_HTTP.match(message)
    if not match:
        return None

    source_ip, user, date_str, method, path, status_code, _bytes = match.groups()
    status_code_int = int(status_code)

    suspicious_kinds = _detect_suspicious(path)
    metadata: dict[str, Any] = {
        "method": method,
        "path": path[:500],
        "status_code": status_code_int,
        "bytes": _bytes,
    }

    if suspicious_kinds:
        metadata["suspicious_signatures"] = sorted(suspicious_kinds)
        event_type = "HTTP_SUSPICIOUS_REQUEST"
        status = "SUSPICIOUS"
        severity = "HIGH" if status_code_int >= 400 else "MEDIUM"
    else:
        event_type = "HTTP_REQUEST"
        severity = "MEDIUM" if status_code_int >= 500 else "LOW"
        if status_code_int in (401, 403, 404):
            status = "DENIED"
        elif status_code_int >= 500:
            status = "ERROR"
        else:
            status = "SUCCESS"

    timestamp = None
    try:
        timestamp = _parse_http_date(date_str)
    except (ValueError, IndexError):
        timestamp = None

    return ParsedLog(
        event_type=event_type,
        status=status,
        severity=severity,
        source="WEB",
        message=message,
        source_ip=source_ip,
        username=user if user and user != "-" else None,
        timestamp=timestamp,
        metadata=metadata,
    )


def _detect_suspicious(value: str) -> set[str]:
    kinds: set[str] = set()
    for name, pattern in _SUSPICIOUS_PATTERNS:
        if pattern.search(value):
            kinds.add(name)
    return kinds


def _extract_syslog_prefix(message: str) -> datetime | None:
    """Best-effort parse of a ``Mon DD HH:MM:SS`` syslog prefix into UTC.

    Syslog lines carry no year or timezone; we assume the current calendar
    year and UTC so the demo data shares one consistent clock with the
    HTTP sample logs. Returns ``None`` when the line has no such prefix.
    """
    match = _SYSLOG_PREFIX.match(message)
    if not match:
        return None
    month, day, hour, minute, second = match.groups()
    year = datetime.now(timezone.utc).year
    try:
        dt = datetime.strptime(
            f"{year} {month} {day} {hour}:{minute}:{second}", "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc)


def _parse_http_date(value: str) -> datetime:
    """Parse an Apache-style date ``10/Oct/2026:13:55:36 +0000`` to UTC."""
    dt = datetime.strptime(value.strip(), "%d/%b/%Y:%H:%M:%S %z")
    return dt.astimezone(timezone.utc)


def _parsed(
    event_type: str,
    status: str,
    source: str,
    message: str,
    *,
    username: str | None = None,
    source_ip: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> ParsedLog:
    return ParsedLog(
        event_type=event_type,
        status=status,
        severity="LOW",
        source=source,
        message=message[:2000],
        source_ip=source_ip,
        username=username,
        metadata=metadata or {},
    )