"""PDF report export tests — authorization, real-data content, and validity."""

import uuid
import zlib
from base64 import a85decode
from datetime import datetime, timedelta, timezone

from app.models.event import Event


def _pdf_text(blob: bytes) -> str:
    """Recover the readable text for assertions.

    ReportLab content streams are ``/ASCII85Decode /FlateDecode`` filtered, so
    each embedded stream is decoded through ascii85 and zlib before inspection.
    """
    pieces: list[bytes] = []
    idx = 0
    while True:
        start = blob.find(b"stream", idx)
        if start == -1:
            break
        start += len(b"stream")
        while start < len(blob) and blob[start] in (10, 13):  # \n, \r
            start += 1
        end = blob.find(b"endstream", start)
        if end == -1:
            break
        raw = blob[start:end].strip()
        decoded = None
        try:
            decoded = zlib.decompress(raw)
        except Exception:
            try:
                decoded = zlib.decompress(a85decode(raw, adobe=True))
            except Exception:
                pass
        if decoded is not None:
            pieces.append(decoded)
        idx = end + len(b"endstream")
    return b"\n".join(pieces).decode("latin-1", errors="replace")


def _seed_signal(client, auth_headers) -> str:
    """Ingest a unique SSH brute-force burst and return the marker in the IP."""
    ip = f"198.51.100.{uuid.uuid4().hex[:2].upper()}"
    client.post(
        "/api/logs/ingest",
        json={
            "lines": [
                f"Failed password for root from {ip} port 54001 ssh2",
                f"Failed password for root from {ip} port 54002 ssh2",
                f"Failed password for root from {ip} port 54003 ssh2",
                f"Failed password for root from {ip} port 54004 ssh2",
                f"Failed password for root from {ip} port 54005 ssh2",
            ]
        },
        headers=auth_headers,
    )
    return ip


def test_report_export_requires_auth(client) -> None:
    assert client.get("/api/reports/export").status_code == 401


def test_report_export_rejects_bad_window(client, auth_headers) -> None:
    assert client.get("/api/reports/export", params={"days": 91}, headers=auth_headers).status_code == 422


def test_report_export_downloads_valid_pdf(client, auth_headers) -> None:
    ip = _seed_signal(client, auth_headers)

    response = client.get("/api/reports/export", params={"days": 7}, headers=auth_headers)
    assert response.status_code == 200
    assert response.headers["content-type"].split(";")[0] == "application/pdf"
    disposition = response.headers["content-disposition"]
    assert disposition.startswith("attachment")
    filename = disposition.split("filename=")[1].strip('"')
    assert filename.endswith(".pdf")
    assert filename.startswith("sentinelx_report_")

    blob = response.content
    assert blob[:5] == b"%PDF-"
    assert b"/Type /Pages" in blob
    assert blob.rstrip().endswith(b"%%EOF")

    text = _pdf_text(blob)
    # Live data made it into the document.
    assert "SentinelX" in text
    assert "SSH Brute Force Attempt" in text
    assert ip in text
    assert "SSH_LOGIN_FAILURE" in text
    # Required report sections.
    assert "Report period" in text
    assert "Total security events" in text
    assert "Total alerts raised" in text
    assert "Alerts by severity" in text
    assert "Critical" in text
    assert "High" in text
    assert "Medium" in text
    assert "Low" in text
    assert "Alerts by status" in text
    assert "Open" in text
    assert "Investigating" in text
    assert "Resolved" in text
    assert "Most triggered detection rules" in text
    assert "Top source IPs" in text
    assert "Top event types" in text
    assert "Generated" in text


def test_report_export_respects_date_range(client, auth_headers, db) -> None:
    _seed_signal(client, auth_headers)

    stale_ip = "203.0.113.99"
    db.add(
        Event(
            timestamp=datetime.now(timezone.utc) - timedelta(days=60),
            source_ip=stale_ip,
            event_type="SSH_LOGIN_FAILURE",
            status="UNKNOWN",
            severity="LOW",
            source="test",
            message=f"Failed password for root from {stale_ip}",
        )
    )
    db.commit()

    blob = client.get("/api/reports/export", params={"days": 1}, headers=auth_headers).content
    text = _pdf_text(blob)
    assert stale_ip not in text  # 60-day-old event falls outside the window


def test_report_export_records_report_generated_audit(client, auth_headers, admin_headers) -> None:
    _seed_signal(client, auth_headers)
    response = client.get("/api/reports/export", params={"days": 3}, headers=auth_headers)
    assert response.status_code == 200

    audit = client.get(
        "/api/audit-logs", params={"action": "REPORT_GENERATED"}, headers=admin_headers
    ).json()["items"]
    pdf_entries = [entry for entry in audit if entry["resource_id"] == "pdf"]
    assert pdf_entries, "expected a REPORT_GENERATED entry with resource_id 'pdf'"
    latest = pdf_entries[0]
    assert latest["details"].get("format") == "pdf"
    assert latest["details"].get("days") == 3