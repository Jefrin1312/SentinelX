"""Detection rule management API tests."""


def test_rules_require_auth(client) -> None:
    assert client.get("/api/rules").status_code == 401


def test_rules_loaded_from_disk(client, auth_headers) -> None:
    """Startup loads the bundled YAML bundles into the ruleset."""
    response = client.get("/api/rules", headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 12  # authentication(3) + ssh(3) + web(3) + system(3)

    names = {rule["name"] for rule in body["items"]}
    assert "SSH Brute Force Attempt" in names
    assert "SQL Injection Attempt" in names
    assert "Privilege Escalation via Sudo" in names


def test_rules_can_be_filtered(client, auth_headers) -> None:
    response = client.get("/api/rules", params={"category": "web"}, headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert all(rule["category"] == "web" for rule in body["items"])


def test_toggle_requires_admin(client, auth_headers) -> None:
    rules = client.get("/api/rules", headers=auth_headers).json()["items"]
    rule_id = rules[0]["id"]
    response = client.patch(f"/api/rules/{rule_id}", json={"enabled": False}, headers=auth_headers)
    assert response.status_code == 403


def test_admin_toggles_rule(client, admin_headers) -> None:
    rules = client.get("/api/rules", headers=admin_headers).json()["items"]
    rule = rules[0]
    response = client.patch(
        f"/api/rules/{rule['id']}", json={"enabled": False}, headers=admin_headers
    )
    assert response.status_code == 200
    assert response.json()["enabled"] is False
    assert client.patch(
        f"/api/rules/{rule['id']}", json={"enabled": True}, headers=admin_headers
    ).json()["enabled"] is True


def test_reload_requires_admin(client, auth_headers) -> None:
    response = client.post("/api/rules/reload", headers=auth_headers)
    assert response.status_code == 403


def test_admin_reloads_rules(client, admin_headers) -> None:
    response = client.post("/api/rules/reload", headers=admin_headers)
    assert response.status_code == 200
    body = response.json()
    # Bundles already exist, so reload only updates/skips — never duplicates.
    assert body["updated"] + body["skipped"] >= 0
    assert client.get("/api/rules", headers=admin_headers).json()["total"] == 12


def test_toggle_missing_rule_not_found(client, admin_headers) -> None:
    response = client.patch("/api/rules/999999", json={"enabled": False}, headers=admin_headers)
    assert response.status_code == 404