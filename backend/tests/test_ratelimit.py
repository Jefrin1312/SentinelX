"""Rate limiting tests: parser, in-memory limiter, and the login endpoint.

The shared TestClient uses a single remote IP, so these tests pass an explicit
``limit`` to keep them independent of the globally configured value.
"""

import time

from app.api import auth as auth_module
from app.auth.ratelimit import _parse_limit, _windows, is_rate_limited
from app.config import Settings


def test_parse_limit_units() -> None:
    assert _parse_limit("10/minute") == (10, 60.0)
    assert _parse_limit("3/second") == (3, 1.0)
    assert _parse_limit("100/hour") == (100, 3600.0)


def test_parse_limit_disabled_or_invalid() -> None:
    assert _parse_limit("0/minute") is None
    assert _parse_limit("") is None
    assert _parse_limit("bogus") is None
    assert _parse_limit("10/fortnight") is None


def test_is_rate_limited_respects_window() -> None:
    _windows.clear()
    key = "192.0.2.1"
    assert is_rate_limited(key, limit="2/minute") is False
    assert is_rate_limited(key, limit="2/minute") is False
    assert is_rate_limited(key, limit="2/minute") is True
    assert is_rate_limited(key, limit="2/minute") is True


def test_is_rate_limited_disabled_never_blocks() -> None:
    _windows.clear()
    key = "198.51.100.7"
    for _ in range(20):
        assert is_rate_limited(key, limit="0/minute") is False


def test_is_rate_limited_window_rolls_over() -> None:
    _windows.clear()
    key = "203.0.113.9"
    assert is_rate_limited(key, limit="1/second") is False
    assert is_rate_limited(key, limit="1/second") is True
    time.sleep(1.05)
    assert is_rate_limited(key, limit="1/second") is False


def test_login_returns_429_when_rate_limited(client, monkeypatch) -> None:
    _windows.clear()
    monkeypatch.setattr(
        auth_module,
        "get_settings",
        lambda: Settings(LOGIN_RATE_LIMIT="2/minute"),
    )

    client.post(
        "/api/auth/register",
        json={
            "username": "ratelimited",
            "email": "ratelimited@example.com",
            "password": "AnotherStr0ng@1",
        },
    )
    payload = {"username": "ratelimited", "password": "AnotherStr0ng@1"}
    assert client.post("/api/auth/login", json=payload).status_code == 200
    assert client.post("/api/auth/login", json=payload).status_code == 200
    assert client.post("/api/auth/login", json=payload).status_code == 429