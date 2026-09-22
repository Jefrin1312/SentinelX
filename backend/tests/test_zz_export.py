"""CSV evidence export tests — alerts, events, and the audit trail."""

import uuid


def test_alerts_export_requires_auth(client) -> None:
    assert client.get("/api/alerts/export").status_code == 401


def test_alerts_export_reflects_filters(client, auth_headers) -> None:
    username = f"exp{uuid.uuid4().hex[:6]}"
    client.post(
        "/api/logs/ingest",
        json={
            "lines": [
                f"{username} : TTY=tty1 ; PWD=/home/{username} ; USER=root ; "
                f"COMMAND=/usr/bin/systemctl restart sshd X{uuid.uuid4().hex[:6]}"
            ]
        },
        headers=auth_headers,
    )
    response = client.get(
        "/api/alerts/export",
        params={"alert_type": "Privilege Escalation via Sudo"},
        headers=auth_headers,
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert 'filename="alerts.csv"' in response.headers["content-disposition"]

    body = response.text
    assert "alert_type,severity,status,source_ip" in body
    assert "Privilege Escalation via Sudo" in body
    assert "MEDIUM" in body


def test_alerts_export_respects_empty_filter(client, auth_headers) -> None:
    response = client.get(
        "/api/alerts/export",
        params={"alert_type": "Definitely Not a Real Rule"},
        headers=auth_headers,
    )
    assert response.status_code == 200
    lines = response.text.strip().splitlines()
    assert len(lines) == 1  # header only


def test_events_export_requires_auth(client) -> None:
    assert client.get("/api/logs/export").status_code == 401


def test_events_export_matches_search(client, auth_headers) -> None:
    marker = f"MARK{uuid.uuid4().hex[:8]}"
    client.post(
        "/api/logs/ingest",
        json={"lines": [f"May  5 10:11:12 server sshd[123]: Failed password for nobody from 198.51.100.7 port 22 {marker}"]},
        headers=auth_headers,
    )
    response = client.get("/api/logs/export", params={"search": marker}, headers=auth_headers)
    assert response.status_code == 200
    assert 'filename="events.csv"' in response.headers["content-disposition"]
    body = response.text
    assert "event_type,source_ip,username" in body
    assert marker in body


def test_audit_export_requires_admin(client, auth_headers) -> None:
    assert client.get("/api/audit-logs/export", headers=auth_headers).status_code == 403


def test_audit_export_for_admin(client, admin_headers) -> None:
    response = client.get("/api/audit-logs/export", headers=admin_headers)
    assert response.status_code == 200
    assert 'filename="audit-logs.csv"' in response.headers["content-disposition"]
    body = response.text
    assert "username,action,resource_type,resource_id" in body
    assert "LOGIN_SUCCESS" in body