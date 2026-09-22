"""Dashboard endpoint tests."""

DUMMY_EVENT = {
    "timestamp": "2026-09-22T10:00:00Z",
    "source_ip": "203.0.113.10",
    "username": "ops",
    "event_type": "SSH_LOGIN_FAILURE",
    "status": "FAILED",
    "severity": "LOW",
    "source": "SSH",
    "message": "Failed password for ops from 203.0.113.10",
}


def test_dashboard_summary_requires_auth(client) -> None:
    assert client.get("/api/dashboard/summary").status_code == 401


def test_dashboard_summary_returns_zeroed_stats(client, auth_headers) -> None:
    response = client.get("/api/dashboard/summary", headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["total_events"] == 0
    assert body["total_alerts"] == 0
    assert body["severity"] == {"low": 0, "medium": 0, "high": 0, "critical": 0}
    assert body["status"] == {"open": 0, "investigating": 0, "resolved": 0}
    assert body["top_source_ips"] == []
    assert body["recent_events"] == []


def test_dashboard_timeline_returns_empty_window(client, auth_headers) -> None:
    response = client.get("/api/dashboard/timeline", headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert 24 <= len(body) <= 25
    assert all(point["events"] == 0 for point in body)


def test_dashboard_reflects_ingested_data(client, auth_headers, db) -> None:
    """The dashboard must aggregate real rows, never hardcoded values."""
    from app.models.alert import Alert
    from app.models.event import Event

    for _ in range(3):
        db.add(
            Event(
                source_ip="203.0.113.50",
                event_type="SSH_LOGIN_FAILURE",
                status="FAILED",
                severity="HIGH",
                source="SSH",
                message="Failed password for admin from 203.0.113.50",
            )
        )
    db.add(
        Alert(
            alert_type="SSH_BRUTE_FORCE",
            severity="HIGH",
            source_ip="203.0.113.50",
            description="test alert",
            status="OPEN",
        )
    )
    db.commit()

    response = client.get("/api/dashboard/summary", headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["total_events"] == 3
    assert body["total_alerts"] == 1
    assert body["severity"]["high"] == 1
    assert body["status"]["open"] == 1
    assert body["top_source_ips"] == [{"source_ip": "203.0.113.50", "count": 3}]

    timeline = client.get("/api/dashboard/timeline", headers=auth_headers).json()
    assert sum(point["events"] for point in timeline) == 3
    assert sum(point["alerts"] for point in timeline) == 1