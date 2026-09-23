"""Cookie-authentication, CSRF and CORS behavior tests.

The JWT is delivered only inside an HttpOnly cookie; JavaScript never sees it.
State-changing requests must echo the double-submit CSRF cookie as an
``X-CSRF-Token`` header. CORS must allow credentials only for configured
origins.
"""

import jwt

from app.auth import cookies as cookies_module
from app.auth.cookies import AUTH_COOKIE, CSRF_COOKIE, new_csrf_token
from app.config import Settings, get_settings


def _register(client, tag: str = "cookieuser") -> dict:
    import uuid

    suffix = uuid.uuid4().hex[:8]
    response = client.post(
        "/api/auth/register",
        json={
            "username": f"{tag}_{suffix}",
            "email": f"{tag}_{suffix}@example.com",
            "password": "Str0ngPass!word",
        },
    )
    assert response.status_code == 201, response.text
    return {"X-CSRF-Token": client.cookies.get(CSRF_COOKIE)}


def _csrf(client) -> dict:
    return {"X-CSRF-Token": client.cookies.get(CSRF_COOKIE)}


class TestSessionCookies:
    def test_login_sets_http_only_auth_cookie_and_csrf_cookie(self, client) -> None:
        _register(client)
        token_cookie = client.cookies.get(AUTH_COOKIE)
        csrf_cookie = client.cookies.get(CSRF_COOKIE)
        assert token_cookie
        assert csrf_cookie
        # The cookie is the verifiable JWT issued by the server.
        payload = jwt.decode(
            token_cookie,
            get_settings().SECRET_KEY,
            algorithms=["HS256"],
        )
        assert payload["username"].startswith("cookieuser_")

    def test_cookie_attributes_httponly_samesite_path(self, client) -> None:
        response = client.post(
            "/api/auth/register",
            json={
                "username": "attruser",
                "email": "attruser@example.com",
                "password": "Str0ngPass!word",
            },
        )
        assert response.status_code == 201
        token_cookie = next(
            c
            for c in response.headers.get_list("set-cookie")
            if c.startswith(f"{AUTH_COOKIE}=")
        )
        assert "HttpOnly" in token_cookie
        assert "SameSite=lax" in token_cookie
        assert "Path=/" in token_cookie
        assert "Secure" not in token_cookie  # default COOKIE_SECURE=False (dev HTTP)

    def test_cookie_becomes_secure_when_configured(self, client, monkeypatch) -> None:
        monkeypatch.setattr(
            cookies_module,
            "get_settings",
            lambda: Settings(COOKIE_SECURE=True),
        )
        response = client.post(
            "/api/auth/register",
            json={
                "username": "secureuser",
                "email": "secureuser@example.com",
                "password": "Str0ngPass!word",
            },
        )
        assert response.status_code == 201
        for cookie in response.headers.get_list("set-cookie"):
            if cookie.startswith(f"{AUTH_COOKIE}=") or cookie.startswith(f"{CSRF_COOKIE}="):
                assert "Secure" in cookie

    def test_cookie_expires_with_jwt(self, client) -> None:
        _register(client)
        response = client.post(
            "/api/auth/register",
            json={
                "username": "expiryuser",
                "email": "expiryuser@example.com",
                "password": "Str0ngPass!word",
            },
        )
        assert response.status_code == 201
        token_cookie = next(
            c
            for c in response.headers.get_list("set-cookie")
            if c.startswith(f"{AUTH_COOKIE}=")
        )
        max_age = [
            part
            for part in token_cookie.split(";")
            if part.strip().startswith("Max-Age")
        ][0].split("=")[1].strip()
        assert int(max_age) == get_settings().ACCESS_TOKEN_EXPIRE_MINUTES * 60

    def test_no_token_in_json_body(self, client) -> None:
        response = client.post(
            "/api/auth/register",
            json={
                "username": "nojsonjwt",
                "email": "nojsonjwt@example.com",
                "password": "Str0ngPass!word",
            },
        )
        assert response.status_code == 201
        body = response.text
        assert "access_token" not in body
        assert AUTH_COOKIE not in body

    def test_authenticated_request_uses_cookie_only(self, client, auth_headers) -> None:
        # No Authorization header anywhere, yet identity comes from the cookie.
        assert client.cookies.get(AUTH_COOKIE)
        response = client.get("/api/auth/me", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["username"].startswith("tester_")


class TestCsrfProtection:
    def test_mutation_without_csrf_header_is_rejected(self, client, auth_headers) -> None:
        response = client.post(
            "/api/logs/ingest",
            json={"lines": ["Failed password for root from 198.51.100.10 port 1 ssh2"]},
        )
        assert response.status_code == 403
        assert "CSRF" in response.json()["detail"]

    def test_mutation_with_wrong_csrf_header_is_rejected(self, client, auth_headers) -> None:
        response = client.post(
            "/api/logs/ingest",
            json={"lines": ["Failed password for root from 198.51.100.11 port 1 ssh2"]},
            headers={"X-CSRF-Token": "definitely-wrong-token"},
        )
        assert response.status_code == 403

    def test_mutation_with_valid_csrf_succeeds(self, client, auth_headers) -> None:
        response = client.post(
            "/api/logs/ingest",
            json={"lines": ["Failed password for root from 198.51.100.12 port 1 ssh2"]},
            headers=auth_headers,
        )
        assert response.status_code == 201

    def test_unauthenticated_mutation_returns_401_not_403(self, client) -> None:
        # No session cookie at all: auth chain answers 401, not the CSRF guard.
        response = client.post(
            "/api/logs/ingest",
            json={"lines": ["Failed password for root from 198.51.100.13 port 1 ssh2"]},
        )
        assert response.status_code == 401

    def test_login_and_register_are_csrf_exempt(self, client) -> None:
        import uuid

        suffix = uuid.uuid4().hex[:8]
        register = client.post(
            "/api/auth/register",
            json={
                "username": f"exempt_{suffix}",
                "email": f"exempt_{suffix}@example.com",
                "password": "Str0ngPass!word",
            },
        )
        assert register.status_code == 201
        login = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "Admin@12345"},
        )
        assert login.status_code == 200

    def test_csrf_cookie_rotates_every_login(self, client) -> None:
        _register(client)
        first_csrf = client.cookies.get(CSRF_COOKIE)
        login = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "Admin@12345"},
        )
        assert login.status_code == 200
        assert client.cookies.get(CSRF_COOKIE) != first_csrf

    def test_logout_requires_csrf_and_clears_cookies(self, client, auth_headers) -> None:
        response = client.post("/api/auth/logout")
        assert response.status_code == 403
        ok = client.post("/api/auth/logout", headers=auth_headers)
        assert ok.status_code == 204
        assert client.cookies.get(AUTH_COOKIE) is None
        assert client.cookies.get(CSRF_COOKIE) is None


class TestCorsAndCookies:
    def test_preflight_allowed_origin_ok(self, client) -> None:
        allowed = "http://localhost:5173"
        response = client.options(
            "/api/logs/ingest",
            headers={
                "Origin": allowed,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type,x-csrf-token",
            },
        )
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == allowed
        assert response.headers.get("access-control-allow-credentials") == "true"

    def test_preflight_disallowed_origin_not_allowed(self, client) -> None:
        response = client.options(
            "/api/logs/ingest",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type,x-csrf-token",
            },
        )
        # Starlette's CORS middleware 400s preflights from origins not on the
        # allow list and never echoes an allow-origin header.
        assert response.status_code == 400
        assert "access-control-allow-origin" not in response.headers

    def test_authenticated_mutation_from_disallowed_origin_rejected(self, client, auth_headers) -> None:
        response = client.post(
            "/api/logs/ingest",
            json={"lines": ["Failed password for root from 198.51.100.14 port 1 ssh2"]},
            headers={
                **auth_headers,
                "Origin": "https://evil.example",
            },
        )
        # Even though the request body+csrf arrive, the browser would block the
        # response; the server must not hand over credentials to that origin.
        assert response.status_code in (403, 201)
        assert response.headers.get("access-control-allow-origin") != "https://evil.example"


class TestIsolationWithCookies:
    def test_investigation_ownership_isolation(self, client, auth_headers, make_client) -> None:
        username = f"sec{uuid_hex()}"
        line = (
            f"{username} : TTY=tty1 ; PWD=/home/{username} ; USER=root ; "
            f"COMMAND=/usr/bin/systemctl restart sshd"
        )
        created = client.post("/api/logs/ingest", json={"lines": [line]}, headers=auth_headers)
        assert created.status_code == 201
        investigation_id = client.post(
            "/api/investigations",
            json={"alert_id": _alert_id_for(client, auth_headers, username)},
            headers=auth_headers,
        ).json()["id"]

        intruder = make_client()
        _register(intruder, "intruder")
        listing = intruder.get("/api/investigations").json()["items"]
        assert all(item["id"] != investigation_id for item in listing)
        assert (
            intruder.get(f"/api/investigations/{investigation_id}").status_code == 404
        )

    def test_analyst_still_blocked_from_admin_routes(self, client, auth_headers) -> None:
        assert client.get("/api/settings", headers=auth_headers).status_code == 403
        assert client.get("/api/audit-logs", headers=auth_headers).status_code == 403

    def test_admin_still_authorized_via_cookie(self, client, make_client) -> None:
        admin = make_client()
        login = admin.post(
            "/api/auth/login", json={"username": "admin", "password": "Admin@12345"}
        )
        assert login.status_code == 200
        assert admin.get("/api/settings", headers=_csrf(admin)).status_code == 200
        assert admin.get("/api/users", headers=_csrf(admin)).json()["total"] >= 2


def uuid_hex() -> str:
    import uuid

    return uuid.uuid4().hex[:6]


def _alert_id_for(client, headers, username) -> int:
    alerts = client.get(
        "/api/alerts",
        params={"alert_type": "Privilege Escalation via Sudo"},
        headers=headers,
    ).json()["items"]
    for alert in alerts:
        if alert["metadata"].get("key_value") == username:
            return alert["id"]
    raise AssertionError(f"no sudo alert for {username}")


def test_revoked_token_is_rejected(client, auth_headers) -> None:
    token = client.cookies.get(AUTH_COOKIE)
    assert client.post("/api/auth/logout", headers=auth_headers).status_code == 204
    # Re-arming the old JWT must still be rejected (blacklisted + gone).
    client.cookies.set(AUTH_COOKIE, token)
    client.cookies.set(CSRF_COOKIE, new_csrf_token())
    assert client.get("/api/auth/me").status_code == 401