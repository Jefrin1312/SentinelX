"""Investigation workflow API tests — triage loop and alert sync."""

import uuid


def _make_open_alert(client, auth_headers) -> int:
    """Ingest a sudo line which fires the single-hit sudo alert.

    Syslog lines carry no source IP, so alerts are located by rule + the
    unique sudo username (the rule groups on ``username``).
    """
    username = f"obs{uuid.uuid4().hex[:6]}"
    line = (
        f"{username} : TTY=tty1 ; PWD=/home/{username} ; USER=root ; "
        f"COMMAND=/usr/bin/systemctl restart sshd INVEST{uuid.uuid4().hex[:6]}"
    )
    response = client.post("/api/logs/ingest", json={"lines": [line]}, headers=auth_headers)
    assert response.status_code == 201, response.text
    alerts = client.get(
        "/api/alerts", params={"alert_type": "Privilege Escalation via Sudo"}, headers=auth_headers
    ).json()["items"]
    for alert in alerts:
        if alert["metadata"].get("key_value") == username:
            return alert["id"]
    raise AssertionError(f"no sudo alert for {username}: {alerts}")


def test_create_requires_auth(client) -> None:
    assert client.post("/api/investigations", json={"alert_id": 1}).status_code == 401


def test_create_promotes_alert_and_audits(client, auth_headers, db) -> None:
    alert_id = _make_open_alert(client, auth_headers)

    response = client.post(
        "/api/investigations",
        json={"alert_id": alert_id, "summary": "Investigating repetitive sudo misuse."},
        headers=auth_headers,
    )
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "OPEN"
    assert body["alert_id"] == alert_id

    alert = client.get(f"/api/alerts/{alert_id}", headers=auth_headers).json()
    assert alert["status"] == "INVESTIGATING"

    from app.models.audit import AuditLog

    investigation_actions = [
        entry.action
        for entry in db.query(AuditLog)
        .filter(
            AuditLog.resource_type == "investigation",
            AuditLog.resource_id == str(body["id"]),
        )
        .all()
    ]
    assert "INVESTIGATION_CREATED" in investigation_actions

    alert_actions = [
        entry.action
        for entry in db.query(AuditLog)
        .filter(
            AuditLog.resource_type == "alert", AuditLog.resource_id == str(alert_id)
        )
        .all()
    ]
    assert "ALERT_STATUS_CHANGED" in alert_actions


def test_create_missing_alert_404(client, auth_headers) -> None:
    response = client.post(
        "/api/investigations", json={"alert_id": 999999}, headers=auth_headers
    )
    assert response.status_code == 404


def test_duplicate_investigation_conflicts(client, auth_headers) -> None:
    alert_id = _make_open_alert(client, auth_headers)
    client.post("/api/investigations", json={"alert_id": alert_id}, headers=auth_headers)
    second = client.post(
        "/api/investigations", json={"alert_id": alert_id}, headers=auth_headers
    )
    assert second.status_code == 409


def test_resolve_investigation_resolves_alert(client, auth_headers) -> None:
    alert_id = _make_open_alert(client, auth_headers)
    investigation_id = client.post(
        "/api/investigations", json={"alert_id": alert_id}, headers=auth_headers
    ).json()["id"]

    resolved = client.patch(
        f"/api/investigations/{investigation_id}",
        json={"status": "RESOLVED"},
        headers=auth_headers,
    )
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "RESOLVED"
    assert resolved.json()["resolved_at"] is not None

    alert = client.get(f"/api/alerts/{alert_id}", headers=auth_headers).json()
    assert alert["status"] == "RESOLVED"
    assert alert["resolved_at"] is not None


def test_reopen_investigation_reinstates_investigating_state(client, auth_headers) -> None:
    alert_id = _make_open_alert(client, auth_headers)
    investigation_id = client.post(
        "/api/investigations", json={"alert_id": alert_id}, headers=auth_headers
    ).json()["id"]
    client.patch(
        f"/api/investigations/{investigation_id}",
        json={"status": "RESOLVED"},
        headers=auth_headers,
    )

    reopened = client.patch(
        f"/api/investigations/{investigation_id}",
        json={"status": "OPEN"},
        headers=auth_headers,
    )
    assert reopened.json()["status"] == "OPEN"
    assert reopened.json()["resolved_at"] is None
    alert = client.get(f"/api/alerts/{alert_id}", headers=auth_headers).json()
    assert alert["status"] == "INVESTIGATING"


def test_detail_includes_notes_and_alert(client, auth_headers) -> None:
    alert_id = _make_open_alert(client, auth_headers)
    investigation_id = client.post(
        "/api/investigations", json={"alert_id": alert_id}, headers=auth_headers
    ).json()["id"]

    client.post(
        f"/api/investigations/{investigation_id}/notes",
        json={"note": "Correlated with inbound firewall logs."},
        headers=auth_headers,
    )
    client.post(
        f"/api/investigations/{investigation_id}/notes",
        json={"note": "Quarantined the source address."},
        headers=auth_headers,
    )

    detail = client.get(
        f"/api/investigations/{investigation_id}", headers=auth_headers
    ).json()
    assert detail["alert"]["id"] == alert_id
    assert len(detail["notes"]) == 2
    assert detail["notes"][0]["note"] == "Correlated with inbound firewall logs."
    assert detail["notes"][0]["author_username"] is not None


def test_notes_require_existing_investigation(client, auth_headers) -> None:
    response = client.post(
        "/api/investigations/999999/notes", json={"note": "nope"}, headers=auth_headers
    )
    assert response.status_code == 404


def test_assignee_must_exist(client, auth_headers) -> None:
    alert_id = _make_open_alert(client, auth_headers)
    investigation_id = client.post(
        "/api/investigations", json={"alert_id": alert_id}, headers=auth_headers
    ).json()["id"]
    response = client.patch(
        f"/api/investigations/{investigation_id}",
        json={"assigned_to": 999999},
        headers=auth_headers,
    )
    assert response.status_code == 404


def test_list_filters_by_status(client, auth_headers) -> None:
    first = _make_open_alert(client, auth_headers)
    second = _make_open_alert(client, auth_headers)

    open_id = client.post(
        "/api/investigations", json={"alert_id": first}, headers=auth_headers
    ).json()["id"]
    client.post(
        "/api/investigations", json={"alert_id": second}, headers=auth_headers
    )

    listing = client.get("/api/investigations", params={"status": "OPEN"}, headers=auth_headers).json()
    assert any(item["id"] == open_id for item in listing["items"])