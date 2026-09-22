"""Reporting API tests — daily trends, breakdowns, and resolution times."""

import uuid
from datetime import date


def _make_sudo_alert(client, auth_headers) -> int:
    username = f"rep{uuid.uuid4().hex[:6]}"
    line = (
        f"{username} : TTY=tty1 ; PWD=/home/{username} ; USER=root ; "
        f"COMMAND=/usr/bin/systemctl restart sshd REP{uuid.uuid4().hex[:6]}"
    )
    response = client.post("/api/logs/ingest", json={"lines": [line]}, headers=auth_headers)
    assert response.status_code == 201, response.text
    alerts = client.get(
        "/api/alerts", params={"alert_type": "Privilege Escalation via Sudo"}, headers=auth_headers
    ).json()["items"]
    for alert in alerts:
        if alert["metadata"].get("key_value") == username:
            return alert["id"]
    raise AssertionError(f"no sudo alert for {username}")


def test_reports_require_auth(client) -> None:
    assert client.get("/api/reports/summary").status_code == 401


def test_report_summary_reflects_recent_data(client, auth_headers) -> None:
    alert_id = _make_sudo_alert(client, auth_headers)
    client.patch(f"/api/alerts/{alert_id}/status", json={"status": "RESOLVED"}, headers=auth_headers)

    report = client.get("/api/reports/summary", params={"days": 7}, headers=auth_headers)
    assert report.status_code == 200
    body = report.json()

    assert body["total_alerts"] >= 1
    assert body["total_events"] >= 1

    today = date.today().isoformat()
    today_alerts = next((p for p in body["by_day_alerts"] if p["day"] == today), None)
    today_events = next((p for p in body["by_day_events"] if p["day"] == today), None)
    assert today_alerts is not None
    assert today_alerts["alerts"] >= 1
    assert today_events is not None
    assert today_events["events"] >= 1

    assert "Privilege Escalation via Sudo" in {
        item["alert_type"] for item in body["top_alert_types"]
    }
    assert any(item["severity"] == "MEDIUM" for item in body["by_severity"])
    assert any(item["status"] == "RESOLVED" for item in body["by_status"])
    assert body["avg_resolution_minutes"] is not None
    assert len(body["by_day_alerts"]) == 7


def test_report_window_length(client, auth_headers) -> None:
    body = client.get("/api/reports/summary", params={"days": 30}, headers=auth_headers).json()
    assert len(body["by_day_events"]) == 30
    assert len(body["by_day_alerts"]) == 30
    assert body["days"] == 30


def test_report_no_data_gives_zeroed_series(client, auth_headers) -> None:
    body = client.get("/api/reports/summary", params={"days": 3}, headers=auth_headers).json()
    assert len(body["by_day_events"]) == 3
    assert body["total_alerts"] >= 0