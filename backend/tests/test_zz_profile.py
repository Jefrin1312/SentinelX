"""Self-service account tests — profile updates and password changes."""

import uuid

from app.models.audit import AuditLog


def _registered_auth(client):
    username = f"pro_{uuid.uuid4().hex[:8]}"
    response = client.post(
        "/api/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": "Or!ginalPass1",
        },
    )
    assert response.status_code == 201, response.text
    return {"X-CSRF-Token": client.cookies.get("sentinelx_csrf")}, username


def test_update_profile_requires_auth(client) -> None:
    assert client.patch("/api/auth/me", json={"email": "x@example.com"}).status_code == 401


def test_update_profile_changes_email(client, db) -> None:
    headers, _ = _registered_auth(client)
    new_email = f"new_{uuid.uuid4().hex[:8]}@example.com"
    response = client.patch("/api/auth/me", json={"email": new_email}, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == new_email
    assert client.get("/api/auth/me", headers=headers).json()["email"] == new_email

    uid = client.get("/api/auth/me", headers=headers).json()["id"]
    actions = [
        e.action
        for e in db.query(AuditLog)
        .filter(AuditLog.resource_type == "user", AuditLog.resource_id == str(uid))
        .all()
    ]
    assert "PROFILE_UPDATED" in actions


def test_update_profile_email_conflict(client, make_client) -> None:
    first, _ = _registered_auth(client)
    second_client = make_client()
    _, _ = _registered_auth(second_client)
    taken = client.get("/api/auth/me", headers=first).json()["email"]
    response = second_client.patch(
        "/api/auth/me",
        json={"email": taken},
        headers={"X-CSRF-Token": second_client.cookies.get("sentinelx_csrf")},
    )
    assert response.status_code == 409


def test_update_profile_rejects_invalid_email(client) -> None:
    headers, _ = _registered_auth(client)
    response = client.patch("/api/auth/me", json={"email": "not-an-email"}, headers=headers)
    assert response.status_code == 422


def test_change_password_requires_auth(client) -> None:
    response = client.post(
        "/api/auth/change-password",
        json={"current_password": "x", "new_password": "y"},
    )
    assert response.status_code == 401


def test_change_password_wrong_current(client) -> None:
    headers, _ = _registered_auth(client)
    response = client.post(
        "/api/auth/change-password",
        json={"current_password": "wrong-password", "new_password": "Br@ndNewPass1"},
        headers=headers,
    )
    assert response.status_code == 401


def test_change_password_rejects_weak_new_password(client) -> None:
    headers, _ = _registered_auth(client)
    response = client.post(
        "/api/auth/change-password",
        json={"current_password": "Or!ginalPass1", "new_password": "short"},
        headers=headers,
    )
    assert response.status_code == 422


def test_change_password_revokes_session_and_audits(client, db) -> None:
    headers, username = _registered_auth(client)
    response = client.post(
        "/api/auth/change-password",
        json={"current_password": "Or!ginalPass1", "new_password": "Br@ndNewPass1"},
        headers=headers,
    )
    assert response.status_code == 204

    assert client.get("/api/auth/me", headers=headers).status_code == 401

    old_login = client.post(
        "/api/auth/login", json={"username": username, "password": "Or!ginalPass1"}
    )
    assert old_login.status_code == 401

    new_login = client.post(
        "/api/auth/login", json={"username": username, "password": "Br@ndNewPass1"}
    )
    assert new_login.status_code == 200
    uid = client.get("/api/auth/me").json()["id"]

    actions = [
        e.action
        for e in db.query(AuditLog)
        .filter(AuditLog.resource_type == "user", AuditLog.resource_id == str(uid))
        .all()
    ]
    assert "PASSWORD_CHANGED" in actions