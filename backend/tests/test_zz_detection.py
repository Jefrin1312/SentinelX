"""Detection engine and rule pipeline tests.

These tests operate through the public ingest + alerts APIs so they exercise
the whole chain: YAML rule loading, collector integration and the engine's
threshold logic. Markers scope queries so shared-database assertions stay
correct.
"""

import uuid


def _marker() -> str:
    return f"MARKER{uuid.uuid4().hex[:10]}"


def _ssh_burst(ip: str, count: int, marker: str) -> list[str]:
    return [
        f"Failed password for root from {ip} port {50000 + i} ssh2 {marker}"
        for i in range(count)
    ]


def test_engine_is_wired_into_ingest(client, auth_headers, db) -> None:
    """Five failed SSH logins from one IP cross the brute-force threshold."""
    from app.models.rule import DetectionRule

    assert db.query(DetectionRule).filter(DetectionRule.name == "SSH Brute Force Attempt").count() == 1

    marker = _marker()
    response = client.post(
        "/api/logs/ingest",
        json={"lines": _ssh_burst("198.51.100.77", 5, marker)},
        headers=auth_headers,
    )
    assert response.status_code == 201
    assert response.json()["alerts_created"] >= 1


def test_brute_force_alert_is_listed_and_detailed(client, auth_headers) -> None:
    marker = _marker()
    client.post(
        "/api/logs/ingest",
        json={"lines": _ssh_burst("198.51.100.78", 5, marker)},
        headers=auth_headers,
    )

    listing = client.get(
        "/api/alerts",
        params={"alert_type": "SSH Brute Force Attempt", "source_ip": "198.51.100.78"},
        headers=auth_headers,
    )
    assert listing.status_code == 200
    items = listing.json()["items"]
    assert items, listing.text
    alert = items[0]
    assert alert["severity"] == "HIGH"
    assert alert["status"] == "OPEN"
    assert alert["source_ip"] == "198.51.100.78"
    assert alert["rule_name"] == "SSH Brute Force Attempt"
    assert alert["metadata"]["count"] >= 5

    detail = client.get(f"/api/alerts/{alert['id']}", headers=auth_headers)
    assert detail.status_code == 200
    body = detail.json()
    assert body["event"] is not None
    assert body["event"]["event_type"] == "SSH_LOGIN_FAILURE"


def test_below_threshold_produces_no_alert(client, auth_headers) -> None:
    marker = _marker()
    response = client.post(
        "/api/logs/ingest",
        json={"lines": _ssh_burst("198.51.100.79", 3, marker)},  # SSH brute-force threshold is 5
        headers=auth_headers,
    )
    assert response.json()["alerts_created"] == 0


def test_duplicate_alerts_are_suppressed(client, auth_headers) -> None:
    marker = _marker()
    client.post(
        "/api/logs/ingest",
        json={"lines": _ssh_burst("198.51.100.80", 5, marker)},
        headers=auth_headers,
    )
    client.post(
        "/api/logs/ingest",
        json={"lines": _ssh_burst("198.51.100.80", 5, marker)},
        headers=auth_headers,
    )
    listing = client.get(
        "/api/alerts", params={"source_ip": "198.51.100.80"}, headers=auth_headers
    ).json()
    assert len(listing["items"]) == 1


def test_resolved_alert_allows_reopening(client, auth_headers) -> None:
    marker = _marker()
    client.post(
        "/api/logs/ingest",
        json={"lines": _ssh_burst("198.51.100.81", 5, marker)},
        headers=auth_headers,
    )
    alert_id = client.get(
        "/api/alerts", params={"source_ip": "198.51.100.81"}, headers=auth_headers
    ).json()["items"][0]["id"]

    resolved = client.patch(
        f"/api/alerts/{alert_id}/status", json={"status": "RESOLVED"}, headers=auth_headers
    )
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "RESOLVED"
    assert resolved.json()["resolved_at"] is not None

    # A later burst from the same IP now creates a fresh OPEN alert.
    client.post(
        "/api/logs/ingest",
        json={"lines": _ssh_burst("198.51.100.81", 5, marker + "B")},
        headers=auth_headers,
    )
    related = client.get(
        "/api/alerts", params={"source_ip": "198.51.100.81"}, headers=auth_headers
    ).json()["items"]
    assert len(related) == 2
    assert {a["status"] for a in related} == {"OPEN", "RESOLVED"}


def test_sql_injection_single_hit_fires_critical_alert(client, auth_headers) -> None:
    marker = _marker()
    line = (
        '203.0.113.9 - - [10/Oct/2026:13:55:36 +0000] '
        '"GET /items?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 403 512 - '
        + marker
    )
    response = client.post("/api/logs/ingest", json={"lines": [line]}, headers=auth_headers)
    assert response.status_code == 201
    assert response.json()["alerts_created"] >= 1

    listing = client.get(
        "/api/alerts", params={"alert_type": "SQL Injection Attempt"}, headers=auth_headers
    ).json()
    assert listing["items"], listing
    alert = listing["items"][0]
    assert alert["severity"] == "CRITICAL"
    assert alert["source_ip"] == "203.0.113.9"