"""Alerts API tests — list, detail, status lifecycle, audit trail."""

import uuid


def _marker_ip() -> str:
    """Return a unique IP literal scope for each test run."""
    return f"198.51.101.{int(uuid.uuid4().hex[:4], 16) % 200 + 20}"


def _insert_alert(db, ip: str, **overrides) -> int:
    """Insert an alert directly (bypassing the engine) and return its id."""
    from app.models.alert import Alert

    status_value = overrides.pop("status", "OPEN")
    alert = Alert(
        alert_type="TEST_CASE",
        severity="MEDIUM",
        source_ip=ip,
        description="test alert",
        status=status_value,
        **overrides,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert.id


def test_alerts_require_auth(client) -> None:
    assert client.get("/api/alerts").status_code == 401


def test_alert_directly_created_by_engine(client, auth_headers, db) -> None:
    """An alert raised by the engine carries rule context from its rule row."""
    from app.models.alert import Alert
    from app.models.event import Event
    from app.models.rule import DetectionRule

    rule = db.query(DetectionRule).first()
    assert rule is not None

    ip = _marker_ip()
    event = Event(
        source_ip=ip,
        event_type="SSH_LOGIN_FAILURE",
        status="FAILED",
        severity="LOW",
        source="SSH",
        message="Failed password for admin",
    )
    db.add(event)
    db.flush()

    db.add(
        Alert(
            event_id=event.id,
            rule_id=rule.id,
            alert_type=rule.name,
            severity=rule.severity,
            source_ip=ip,
            description=rule.description,
            status="OPEN",
        )
    )
    db.commit()

    listing = client.get("/api/alerts", params={"source_ip": ip}, headers=auth_headers)
    assert listing.status_code == 200
    alert = listing.json()["items"][0]
    assert alert["rule_name"] == rule.name
    assert alert["metadata"] == {}

    detail = client.get(f"/api/alerts/{alert['id']}", headers=auth_headers)
    assert detail.status_code == 200
    body = detail.json()
    assert body["event"] is not None
    assert body["event"]["id"] == event.id


def test_list_alerts_filters_and_paginates(client, auth_headers, db) -> None:
    ip = _marker_ip()
    for status_value in ("OPEN", "OPEN", "INVESTIGATING", "RESOLVED"):
        _insert_alert(db, ip, status=status_value)

    scoped = client.get("/api/alerts", params={"source_ip": ip}, headers=auth_headers).json()
    assert scoped["total"] == 4

    open_alerts = client.get(
        "/api/alerts", params={"status": "OPEN", "limit": 2, "source_ip": ip}, headers=auth_headers
    ).json()
    assert open_alerts["total"] == 2
    assert len(open_alerts["items"]) == 2
    assert all(a["status"] == "OPEN" for a in open_alerts["items"])


def test_alert_detail_deleted_returns_404(client, auth_headers) -> None:
    assert client.get("/api/alerts/999999", headers=auth_headers).status_code == 404


def test_alert_status_lifecycle(client, auth_headers, db) -> None:
    alert_id = _insert_alert(db, _marker_ip())

    investigating = client.patch(
        f"/api/alerts/{alert_id}/status",
        json={"status": "INVESTIGATING", "note": "assigning to L2"},
        headers=auth_headers,
    )
    assert investigating.status_code == 200
    assert investigating.json()["status"] == "INVESTIGATING"

    resolved = client.patch(
        f"/api/alerts/{alert_id}/status", json={"status": "RESOLVED"}, headers=auth_headers
    )
    assert resolved.status_code == 200
    assert resolved.json()["resolved_at"] is not None

    detail = client.get(f"/api/alerts/{alert_id}", headers=auth_headers).json()
    assert detail["status"] == "RESOLVED"

    from app.models.audit import AuditLog

    entries = db.query(AuditLog).filter(
        AuditLog.action == "ALERT_STATUS_CHANGED",
        AuditLog.resource_id == str(alert_id),
    ).all()
    assert len(entries) == 2
    assert entries[0].details.get("note") == "assigning to L2"


def test_alert_status_rejects_invalid_value(client, auth_headers, db) -> None:
    alert_id = _insert_alert(db, _marker_ip())
    response = client.patch(
        f"/api/alerts/{alert_id}/status", json={"status": "PURGED"}, headers=auth_headers
    )
    assert response.status_code == 422


def test_alert_status_missing_returns_404(client, auth_headers) -> None:
    response = client.patch(
        "/api/alerts/999999/status", json={"status": "RESOLVED"}, headers=auth_headers
    )
    assert response.status_code == 404