"""Audit log viewer API tests (administrator)."""

import uuid


def test_audit_logs_require_admin(client, auth_headers) -> None:
    assert client.get("/api/audit-logs", headers=auth_headers).status_code == 403


def test_audit_logs_requires_auth(client) -> None:
    assert client.get("/api/audit-logs").status_code == 401


def test_audit_logs_list_and_filter(client, admin_headers, db) -> None:
    from app.models.audit import AuditLog

    marker_action = f"TEST_ACTION_{uuid.uuid4().hex[:8]}"
    db.add(
        AuditLog(
            username="admin",
            action=marker_action,
            resource_type="test",
            resource_id="42",
            details={"probe": True},
        )
    )
    db.add(
        AuditLog(
            username="analyst",
            action=marker_action,
            resource_type="test",
            resource_id="43",
            details={"probe": True},
        )
    )
    db.commit()

    listing = client.get("/api/audit-logs", headers=admin_headers)
    assert listing.status_code == 200
    assert listing.json()["total"] >= 2

    filtered = client.get(
        "/api/audit-logs",
        params={"action": marker_action, "resource_type": "test"},
        headers=admin_headers,
    ).json()
    assert filtered["total"] == 2
    assert {item["resource_id"] for item in filtered["items"]} == {"42", "43"}
    assert all(item["details"].get("probe") is True for item in filtered["items"])

    by_user = client.get(
        "/api/audit-logs",
        params={"action": marker_action, "username": "analyst"},
        headers=admin_headers,
    ).json()
    assert by_user["total"] == 1
    assert by_user["items"][0]["username"] == "analyst"


def test_audit_logs_paginate(client, admin_headers, db) -> None:
    from app.models.audit import AuditLog

    marker_action = f"PAGE_ACTION_{uuid.uuid4().hex[:8]}"
    for i in range(5):
        db.add(
            AuditLog(
                username="admin",
                action=marker_action,
                resource_type="test",
                resource_id=str(i),
                details={},
            )
        )
    db.commit()

    page = client.get(
        "/api/audit-logs",
        params={"action": marker_action, "limit": 2},
        headers=admin_headers,
    ).json()
    assert page["total"] == 5
    assert len(page["items"]) == 2