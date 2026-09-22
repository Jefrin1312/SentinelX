"""Detection rule authoring tests — POST /api/rules (admin only)."""

import shutil
import tempfile
from pathlib import Path

import pytest

from app.config import get_settings
from app.models.audit import AuditLog
from app.models.rule import DetectionRule

RULES_SRC = Path(__file__).resolve().parents[2] / "rules"


@pytest.fixture()
def temp_rules_dir():
    """Point RULES_DIR at a temp copy of the real bundles, restore afterwards."""
    settings = get_settings()
    original = settings.RULES_DIR
    tmp = Path(tempfile.mkdtemp(prefix="sentinelx-rules-"))
    for path in RULES_SRC.glob("*.yaml"):
        shutil.copy(path, tmp / path.name)
    settings.RULES_DIR = str(tmp)
    yield tmp
    settings.RULES_DIR = original
    shutil.rmtree(tmp, ignore_errors=True)


def _rule_payload(name: str, **overrides) -> dict:
    payload = {
        "name": name,
        "description": "Authoring test rule",
        "category": "general",
        "severity": "MEDIUM",
        "threshold": 3,
        "time_window": 120,
        "rule_definition": {"event_type": "SSH_LOGIN_FAILURE", "key": "source_ip"},
    }
    payload.update(overrides)
    return payload


def test_create_requires_auth(client) -> None:
    assert client.post("/api/rules", json=_rule_payload("Auth Probe")).status_code == 401


def test_create_requires_admin(client, auth_headers) -> None:
    response = client.post("/api/rules", json=_rule_payload("Admin Only Probe"), headers=auth_headers)
    assert response.status_code == 403


def test_create_rejects_invalid_payload(client, admin_headers) -> None:
    bad = _rule_payload("Bad Rule")
    bad["rule_definition"] = {"event_type": "", "key": "source_ip"}
    assert client.post("/api/rules", json=bad, headers=admin_headers).status_code == 422

    bad = _rule_payload("Bad Severity", severity="URGENT")
    assert client.post("/api/rules", json=bad, headers=admin_headers).status_code == 422

    bad = _rule_payload("x")
    assert client.post("/api/rules", json=bad, headers=admin_headers).status_code == 422


def test_create_duplicate_name_conflicts(client, admin_headers) -> None:
    response = client.post(
        "/api/rules", json=_rule_payload("SSH Brute Force Attempt"), headers=admin_headers
    )
    assert response.status_code == 409


def test_create_persists_rule_and_audits(client, admin_headers, db, temp_rules_dir) -> None:
    name = "Authoring Integration Probe"
    response = client.post("/api/rules", json=_rule_payload(name), headers=admin_headers)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["name"] == name
    assert body["category"] == "general"
    assert body["severity"] == "MEDIUM"
    assert body["threshold"] == 3
    assert body["time_window"] == 120
    assert body["rule_definition"] == {"event_type": "SSH_LOGIN_FAILURE", "key": "source_ip"}

    # Written to disk in the resolved rules directory
    general_yaml = temp_rules_dir / "general.yaml"
    assert general_yaml.is_file()
    assert name in general_yaml.read_text(encoding="utf-8")

    # Loaded into the database
    rule = db.query(DetectionRule).filter(DetectionRule.name == name).first()
    assert rule is not None
    assert rule.category == "general"

    # Audited
    entries = (
        db.query(AuditLog)
        .filter(
            AuditLog.action == "RULE_CREATED",
            AuditLog.resource_type == "rule",
            AuditLog.resource_id == str(rule.id),
        )
        .all()
    )
    assert len(entries) == 1
    assert entries[0].details.get("rule") == name

    # Visible in the list API
    listing = client.get("/api/rules", params={"search": name}, headers=admin_headers)
    assert listing.status_code == 200
    assert listing.json()["total"] >= 1

    # Cleanup: remove the created rule so later tests keep total == 12
    db.delete(rule)
    db.commit()
