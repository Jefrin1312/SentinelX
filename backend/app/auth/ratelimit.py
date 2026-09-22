"""In-memory fixed-window rate limiting for login brute-force protection.

Attempts are tracked per client key (typically the remote IP) in a small
in-memory store; windows are reset lazily so the map never grows unbounded.
The limit is configured as ``"N/second"``, ``"N/minute"`` or ``"N/hour"``.
An empty or zero limit disables enforcement (used by the test suite, which
shares a single TestClient IP across every request).
"""

import threading
import time

from app.config import get_settings

_PERIODS = {"second": 1.0, "minute": 60.0, "hour": 3600.0}

_windows: dict[str, tuple[float, int]] = {}
_lock = threading.Lock()


def _parse_limit(limit: str) -> tuple[int, float] | None:
    """Return ``(max_requests, window_seconds)`` or ``None`` if disabled/invalid."""
    raw = limit.strip().lower()
    if not raw or raw == "0":
        return None
    try:
        count_text, unit = raw.split("/", 1)
        count = int(count_text.strip())
    except ValueError:
        return None
    period = _PERIODS.get(unit.strip())
    if period is None or count <= 0:
        return None
    return count, period


def is_rate_limited(key: str, limit: str | None = None) -> bool:
    """Record one attempt for ``key`` and report whether it exceeds the limit.

    The configured limit string is read from settings on every call unless an
    explicit ``limit`` is passed, which lets tests exercise the limiter without
    touching the cached settings.
    """
    if limit is None:
        limit = get_settings().LOGIN_RATE_LIMIT
    parsed = _parse_limit(limit)
    if parsed is None:
        return False

    max_count, window_seconds = parsed
    now = time.monotonic()

    with _lock:
        existing = _windows.get(key)
        if existing is None:
            _windows[key] = (now, 1)
            return False

        window_start, count = existing
        if now - window_start >= window_seconds:
            _windows[key] = (now, 1)
            return False

        count += 1
        _windows[key] = (window_start, count)

        # Lazy housekeeping: drop keys whose window has fully elapsed.
        if len(_windows) > 1024:
            for k, (start, _) in list(_windows.items()):
                if now - start >= window_seconds:
                    del _windows[k]

        return count > max_count