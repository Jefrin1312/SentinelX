"""Security hardening regression tests.

Covers the audit fixes: JWT claim enforcement, spoof-resistant client IPs,
per-account/per-registration rate limiting, investigation IDOR scoping,
report user isolation, and RBAC on admin endpoints.
"""

import uuid
from datetime import datetime, timedelta, timezone

import jwt

from app.api import auth as auth_module
from app.auth.ratelimit import _windows
from app.config import Settings, get_settings

_SECRET = get_settings().SECRET_KEY


def _make_token(
    *,
    sub: str = "1",
    username: str = "tester",
    role: str = "ANALYST",
    jti: str = "somejti",
    exp: int | None = None,
    include_jti: bool = True,
) -> str:
    now = datetime.now(timezone.utc)
    payload: dict = {
        "sub": sub,
        "username": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp())
        if exp is None
        else exp,
    }
    if include_jti:
        payload["jti"] = jti
    return jwt.encode(payload, _SECRET, algorithm="HS256")


def _headers(client, token: str) -> dict:
    """Install the given JWT as the session cookie for the client."""
    client.cookies.set("sentinelx_token", token)
    return {}


def _register(client, tag: str) -> dict:
    response = client.post(
        "/api/auth/register",
        json={
            "username": f"{tag}_{uuid.uuid4().hex[:8]}",
            "email": f"{tag}_{uuid.uuid4().hex[:8]}@example.com",
            "password": "Str0ngPass!word",
        },
    )
    assert response.status_code == 201, response.text
    return {"X-CSRF-Token": client.cookies.get("sentinelx_csrf")}


def _make_open_alert(client, auth_headers) -> int:
    """Ingest a sudo line which fires the single-hit sudo alert."""
    username = f"sec{uuid.uuid4().hex[:6]}"
    line = (
        f"{username} : TTY=tty1 ; PWD=/home/{username} ; USER=root ; "
        f"COMMAND=/usr/bin/systemctl restart sshd SEC{uuid.uuid4().hex[:6]}"
    )
    response = client.post("/api/logs/ingest", json={"lines": [line]}, headers=auth_headers)
    assert response.status_code == 201, response.text
    alerts = client.get(
        "/api/alerts",
        params={"alert_type": "Privilege Escalation via Sudo"},
        headers=auth_headers,
    ).json()["items"]
    for alert in alerts:
        if alert["metadata"].get("key_value") == username:
            return alert["id"]
    raise AssertionError(f"no sudo alert for {username}: {alerts}")


class TestJwtClaimEnforcement:
    """Tokens must carry every issued claim with a valid ``sub``."""

    def test_token_missing_sub_is_rejected(self, client) -> None:
        payload = jwt.decode(
            _make_token(), _SECRET, algorithms=["HS256"], options={"verify_signature": False}
        )
        del payload["sub"]
        token = jwt.encode(payload, _SECRET, algorithm="HS256")
        assert client.get("/api/auth/me", headers=_headers(client, token)).status_code == 401

    def test_token_with_non_numeric_sub_is_rejected(self, client) -> None:
        assert (
            client.get(
                "/api/auth/me", headers=_headers(client, _make_token(sub="not-a-number"))
            ).status_code
            == 401
        )

    def test_token_with_zero_sub_is_rejected(self, client) -> None:
        assert (
            client.get(
                "/api/auth/me", headers=_headers(client, _make_token(sub="0"))
            ).status_code
            == 401
        )

    def test_token_missing_jti_is_rejected(self, client) -> None:
        token = _make_token(include_jti=False)
        assert client.get("/api/auth/me", headers=_headers(client, token)).status_code == 401

    def test_expired_token_is_rejected(self, client) -> None:
        exp_past = int((datetime.now(timezone.utc) - timedelta(minutes=5)).timestamp())
        assert (
            client.get(
                "/api/auth/me", headers=_headers(client, _make_token(exp=exp_past))
            ).status_code
            == 401
        )

    def test_algorithm_confusion_is_rejected(self, client) -> None:
        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {
                "sub": "1",
                "username": "tester",
                "role": "ANALYST",
                "jti": "x",
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(hours=1)).timestamp()),
            },
            key="",
            algorithm="none",
        )
        assert client.get("/api/auth/me", headers=_headers(client, token)).status_code == 401

    def test_signature_tampering_is_rejected(self, client) -> None:
        valid = _make_token()
        tampered = valid[:-4] + "AAAA"
        assert client.get("/api/auth/me", headers=_headers(client, tampered)).status_code == 401


class TestRbac:
    """Analysts must never reach administrator endpoints."""

    def test_analyst_cannot_create_rules(self, client, auth_headers) -> None:
        response = client.post(
            "/api/rules",
            json={
                "name": "analyst forbid",
                "category": "general",
                "severity": "MEDIUM",
                "enabled": True,
                "threshold": 5,
                "time_window": 300,
                "rule_definition": {"event_type": "SSH_LOGIN_FAILURE", "status": "UNKNOWN"},
            },
            headers=auth_headers,
        )
        assert response.status_code == 403

    def test_analyst_cannot_view_audit_logs(self, client, auth_headers) -> None:
        assert client.get("/api/audit-logs", headers=auth_headers).status_code == 403

    def test_analyst_cannot_view_settings(self, client, auth_headers) -> None:
        assert client.get("/api/settings", headers=auth_headers).status_code == 403

    def test_disabled_user_token_is_rejected(self, client, auth_headers, make_client) -> None:
        me = client.get("/api/auth/me", headers=auth_headers).json()
        admin = make_client()
        admin_login = admin.post(
            "/api/auth/login", json={"username": "admin", "password": "Admin@12345"}
        )
        assert admin_login.status_code == 200
        admin_headers = {"X-CSRF-Token": admin.cookies.get("sentinelx_csrf")}
        response = admin.patch(
            f"/api/users/{me['id']}", json={"is_active": False}, headers=admin_headers
        )
        assert response.status_code == 200
        # Disabling the account makes its existing JWT unusable.
        assert client.get("/api/auth/me", headers=auth_headers).status_code == 401


class TestInvestigationIdor:
    """Investigations belong to the owner of the linked alert."""

    def test_other_user_cannot_access_investigation(self, client, auth_headers, make_client) -> None:
        owner = auth_headers
        alert_id = _make_open_alert(client, owner)
        investigation_id = client.post(
            "/api/investigations", json={"alert_id": alert_id}, headers=owner
        ).json()["id"]

        intruder = make_client()
        _register(intruder, "intruder")
        intruder_headers = {"X-CSRF-Token": intruder.cookies.get("sentinelx_csrf")}

        listing = intruder.get("/api/investigations", headers=intruder_headers).json()["items"]
        assert all(item["id"] != investigation_id for item in listing)

        assert (
            intruder.get(
                f"/api/investigations/{investigation_id}", headers=intruder_headers
            ).status_code
            == 404
        )
        assert (
            intruder.patch(
                f"/api/investigations/{investigation_id}",
                json={"status": "RESOLVED"},
                headers=intruder_headers,
            ).status_code
            == 404
        )
        assert (
            intruder.post(
                f"/api/investigations/{investigation_id}/notes",
                json={"note": "pwned"},
                headers=intruder_headers,
            ).status_code
            == 404
        )

        assert (
            client.get(f"/api/investigations/{investigation_id}", headers=owner).status_code
            == 200
        )


class TestReportIsolation:
    """Report aggregates must never include another user's security data."""

    def test_report_summary_is_scoped_to_current_user(self, client, auth_headers) -> None:
        _make_open_alert(client, auth_headers)

        bystander = _register(client, "bystander")
        body = client.get("/api/reports/summary", params={"days": 7}, headers=bystander).json()
        assert body["total_alerts"] == 0
        assert body["total_events"] == 0
        assert body["top_source_ips"] == []
        assert body["top_event_types"] == []


class TestRateLimitingAuthPolicy:
    """Register and per-account throttling, plus spoof-resistant client IPs."""

    def test_register_rate_limited(self, client, monkeypatch) -> None:
        _windows.clear()
        monkeypatch.setattr(
            auth_module,
            "get_settings",
            lambda: Settings(REGISTER_RATE_LIMIT="2/minute"),
        )
        first = _register(client, "rl1")
        assert client.cookies.get("sentinelx_token")
        _register(client, "rl2")
        response = client.post(
            "/api/auth/register",
            json={
                "username": f"rl3_{uuid.uuid4().hex[:8]}",
                "email": f"rl3_{uuid.uuid4().hex[:8]}@example.com",
                "password": "Str0ngPass!word",
            },
        )
        assert response.status_code == 429

    def test_login_per_account_rate_limited(self, client, monkeypatch) -> None:
        user = _register(client, "acct")
        username = client.get("/api/auth/me", headers=user).json()["username"]
        _windows.clear()
        monkeypatch.setattr(
            auth_module,
            "get_settings",
            lambda: Settings(
                LOGIN_RATE_LIMIT="0/minute", LOGIN_ACCOUNT_RATE_LIMIT="3/minute"
            ),
        )
        for _ in range(3):
            assert (
                client.post(
                    "/api/auth/login",
                    json={"username": username, "password": "Str0ngPass!word"},
                ).status_code
                == 200
            )
        fourth = client.post(
            "/api/auth/login",
            json={"username": username, "password": "Str0ngPass!word"},
        )
        assert fourth.status_code == 429

    def test_spoofed_forwarded_for_does_not_bypass_ip_limit(self, client, monkeypatch) -> None:
        user = _register(client, "xff")
        username = client.get("/api/auth/me", headers=user).json()["username"]
        _windows.clear()
        monkeypatch.setattr(
            auth_module,
            "get_settings",
            lambda: Settings(
                LOGIN_RATE_LIMIT="2/minute",
                LOGIN_ACCOUNT_RATE_LIMIT="0/minute",
                REGISTER_RATE_LIMIT="0/minute",
            ),
        )
        payload = {"username": username, "password": "Str0ngPass!word"}
        for i in range(2):
            assert (
                client.post(
                    "/api/auth/login",
                    json=payload,
                    headers={"X-Forwarded-For": f"203.0.113.{i}", "X-Real-IP": "9.9.9.9"},
                ).status_code
                == 200
            )
        assert (
            client.post(
                "/api/auth/login",
                json=payload,
                headers={"X-Forwarded-For": "203.0.113.99", "X-Real-IP": "9.9.9.9"},
            ).status_code
            == 429
        )


class TestRegisterEnumeration:
    """Duplicate registration must not reveal account existence."""

    def test_duplicate_register_uses_generic_message(self, client) -> None:
        tag = uuid.uuid4().hex[:8]
        payload = {
            "username": f"gen_{tag}",
            "email": f"gen_{tag}@example.com",
            "password": "Str0ngPass!word",
        }
        assert client.post("/api/auth/register", json=payload).status_code == 201
        dup = client.post("/api/auth/register", json=payload)
        assert dup.status_code == 409
        detail = dup.json()["detail"].lower()
        assert "may already exist" in detail
        assert "already exists." not in detail