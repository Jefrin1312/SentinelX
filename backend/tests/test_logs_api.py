"""Log ingest and event API tests.

Each test ingests content tagged with a unique marker and lists filtered by
that marker, so assertions stay correct even though the test database is
shared across the whole session.
"""

import uuid


def _marker() -> str:
    return f"MARKER{uuid.uuid4().hex[:10]}"


def _batch(marker: str) -> list[str]:
    return [
        f"Failed password for admin from 203.0.113.10 port 52347 ssh2 {marker}",
        f"Failed password for admin from 203.0.113.10 port 52362 ssh2 {marker}",
        f"Accepted password for admin from 203.0.113.10 port 52509 ssh2 {marker}",
        f"alice : TTY=tty1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt-get update {marker}",
        f"this line is garbage and cannot be parsed {marker}",
    ]


def test_ingest_requires_auth(client) -> None:
    response = client.post("/api/logs/ingest", json={"lines": ["raw line"]})
    assert response.status_code == 401


def test_ingest_parses_and_stores(client, auth_headers) -> None:
    marker = _marker()
    response = client.post("/api/logs/ingest", json={"lines": _batch(marker)}, headers=auth_headers)
    assert response.status_code == 201
    body = response.json()
    assert body["events_created"] == 5
    assert body["parsed"] == 4
    assert body["unknown"] == 1


def test_list_events(client, auth_headers) -> None:
    marker = _marker()
    client.post("/api/logs/ingest", json={"lines": _batch(marker)}, headers=auth_headers)
    response = client.get("/api/logs", params={"search": marker}, headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 5
    types = {item["event_type"] for item in body["items"]}
    assert "SSH_LOGIN_FAILURE" in types
    assert "SUDO_COMMAND" in types
    assert "UNKNOWN" in types


def test_list_events_filter_by_event_type(client, auth_headers) -> None:
    marker = _marker()
    client.post("/api/logs/ingest", json={"lines": _batch(marker)}, headers=auth_headers)
    response = client.get(
        "/api/logs",
        params={"search": marker, "event_type": "SSH_LOGIN_FAILURE"},
        headers=auth_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert all(item["event_type"] == "SSH_LOGIN_FAILURE" for item in body["items"])


def test_list_events_filter_by_source_ip(client, auth_headers) -> None:
    marker = _marker()
    client.post("/api/logs/ingest", json={"lines": _batch(marker)}, headers=auth_headers)
    response = client.get(
        "/api/logs",
        params={"source_ip": "203.0.113.10"},
        headers=auth_headers,
    )
    # All four SSH lines share the IP; only three carry our marker.
    marker_ips = client.get(
        "/api/logs", params={"search": marker, "source_ip": "203.0.113.10"}, headers=auth_headers
    )
    assert marker_ips.status_code == 200
    assert marker_ips.json()["total"] == 3


def test_get_event_detail(client, auth_headers) -> None:
    marker = _marker()
    response = client.post("/api/logs/ingest", json={"lines": [f"{_batch(marker)[0]}"]}, headers=auth_headers)
    event_id = response.json()["event_ids"][0]
    detail = client.get(f"/api/logs/{event_id}", headers=auth_headers)
    assert detail.status_code == 200
    assert detail.json()["source_ip"] == "203.0.113.10"


def test_get_missing_event_not_found(client, auth_headers) -> None:
    response = client.get("/api/logs/999999", headers=auth_headers)
    assert response.status_code == 404


def test_upload_requires_auth(client) -> None:
    response = client.post(
        "/api/logs/upload",
        files={"file": ("logs.txt", b"Failed password for admin from 10.0.0.1 port 1 ssh2", "text/plain")},
    )
    assert response.status_code == 401


def test_upload_parses_file(client, auth_headers) -> None:
    marker = _marker()
    content = "\n".join(
        [
            f"Failed password for admin from 10.0.0.1 port 1 ssh2 {marker}",
            f"garbage line {marker}",
        ]
    ).encode()
    response = client.post(
        "/api/logs/upload",
        files={"file": ("ssh-bruteforce.log", content, "text/plain")},
        headers=auth_headers,
    )
    assert response.status_code == 201
    body = response.json()
    assert body["events_created"] == 2
    assert body["parsed"] == 1
    assert body["unknown"] == 1


def test_upload_rejects_huge_payload(client, auth_headers) -> None:
    response = client.post(
        "/api/logs/upload",
        files={"file": ("huge.log", b"\n".join([b"y" * 512] * 12000), "text/plain")},
        headers=auth_headers,
    )
    assert response.status_code == 413


def test_import_sample_ssh(client, auth_headers) -> None:
    response = client.post("/api/logs/import", params={"sample": "ssh"}, headers=auth_headers)
    assert response.status_code == 201
    body = response.json()
    assert body["parsed"] >= 20
    assert body["unknown"] == 0


def test_import_unknown_sample_not_found(client, auth_headers) -> None:
    response = client.post("/api/logs/import", params={"sample": "doesnotexist"}, headers=auth_headers)
    assert response.status_code == 404