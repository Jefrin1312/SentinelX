"""Platform settings API tests (administrator)."""


def test_settings_require_auth(client) -> None:
    assert client.get("/api/settings").status_code == 401


def test_settings_require_admin(client, auth_headers) -> None:
    assert client.get("/api/settings", headers=auth_headers).status_code == 403


def test_settings_exposed_to_admin(client, admin_headers) -> None:
    response = client.get("/api/settings", headers=admin_headers)
    assert response.status_code == 200
    body = response.json()

    assert body["app_name"] == "SentinelX"
    assert body["app_env"] == "development"
    assert body["app_version"]
    assert body["api_prefix"] == "/api"
    assert isinstance(body["debug"], bool)
    assert body["jwt_expire_minutes"] > 0
    assert body["login_rate_limit"]
    assert body["max_upload_mb"] > 0
    assert body["max_upload_lines"] > 0
    assert body["rules_dir"]
    assert body["rule_count"] >= 1
    assert body["user_count"] >= 1

    serialized = response.text
    assert "SECRET_KEY" not in serialized
    assert "DATABASE_URL" not in serialized
    assert "sentinelx_dev_password" not in serialized