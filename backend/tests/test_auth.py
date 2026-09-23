"""Authentication and role based access control tests."""

from app.auth.security import hash_password, verify_password


def test_password_hashing_roundtrip() -> None:
    hashed = hash_password("Sup3rSecret!")
    assert hashed != "Sup3rSecret!"
    assert verify_password("Sup3rSecret!", hashed)
    assert not verify_password("WrongPassword", hashed)


def test_password_hash_is_salted() -> None:
    a = hash_password("Sup3rSecret!")
    b = hash_password("Sup3rSecret!")
    assert a != b


def test_register_creates_analyst_and_sets_cookies(client) -> None:
    response = client.post(
        "/api/auth/register",
        json={
            "username": "newanalyst",
            "email": "newanalyst@example.com",
            "password": "AnotherStr0ng@1",
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["user"]["role"] == "ANALYST"
    assert "password_hash" not in body["user"]
    # The JWT must never appear in the JSON body...
    assert "access_token" not in body
    assert "token_type" not in body
    # ...it lives only in the HttpOnly cookie.
    assert client.cookies.get("sentinelx_token")
    assert client.cookies.get("sentinelx_csrf")


def test_register_rejects_duplicate_username(client) -> None:
    payload = {
        "username": "dupe",
        "email": "dupe@example.com",
        "password": "AnotherStr0ng@1",
    }
    assert client.post("/api/auth/register", json=payload).status_code == 201
    assert client.post("/api/auth/register", json=payload).status_code == 409


def test_register_rejects_weak_password(client) -> None:
    response = client.post(
        "/api/auth/register",
        json={"username": "weak", "email": "weak@example.com", "password": "short"},
    )
    assert response.status_code == 422


def test_login_success_sets_session_cookies(client) -> None:
    client.post(
        "/api/auth/register",
        json={
            "username": "loginuser",
            "email": "loginuser@example.com",
            "password": "Log1nPass!word",
        },
    )
    response = client.post(
        "/api/auth/login",
        json={"username": "loginuser", "password": "Log1nPass!word"},
    )
    assert response.status_code == 200
    assert "access_token" not in response.json()
    assert client.cookies.get("sentinelx_token")
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == "loginuser"


def test_login_wrong_password_returns_401(client) -> None:
    client.post(
        "/api/auth/register",
        json={
            "username": "failuser",
            "email": "failuser@example.com",
            "password": "Log1nPass!word",
        },
    )
    response = client.post(
        "/api/auth/login",
        json={"username": "failuser", "password": "not-the-password"},
    )
    assert response.status_code == 401


def test_me_requires_session(client) -> None:
    assert client.get("/api/auth/me").status_code == 401


def test_me_with_valid_session(client, auth_headers) -> None:
    response = client.get("/api/auth/me", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["username"].startswith("tester_")


def test_me_with_garbage_cookie(client) -> None:
    client.cookies.set("sentinelx_token", "not.a.jwt.value")
    response = client.get("/api/auth/me")
    assert response.status_code == 401


def test_logout_revokes_token_and_clears_cookie(client, auth_headers) -> None:
    response = client.post("/api/auth/logout", headers=auth_headers)
    assert response.status_code == 204
    # Both session cookies are gone and the revoked JWT no longer authenticates.
    assert client.cookies.get("sentinelx_token") is None
    assert client.cookies.get("sentinelx_csrf") is None
    me = client.get("/api/auth/me", headers=auth_headers)
    assert me.status_code == 401


def test_analyst_cannot_access_admin_users_endpoint(client, auth_headers) -> None:
    response = client.get("/api/users", headers=auth_headers)
    assert response.status_code == 403


def test_admin_can_access_users_endpoint(client) -> None:
    login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Admin@12345"},
    )
    assert login.status_code == 200
    assert login.json()["user"]["role"] == "ADMIN"
    headers = {"X-CSRF-Token": client.cookies.get("sentinelx_csrf")}
    response = client.get("/api/users", headers=headers)
    assert response.status_code == 200
    assert response.json()["total"] >= 2