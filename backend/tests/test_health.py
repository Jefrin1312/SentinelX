"""Initial foundation tests for the SentinelX backend."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_endpoint() -> None:
    """The health endpoint reports the backend as healthy."""
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "up"


def test_root_endpoint() -> None:
    """The root route exposes API documentation links."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["application"] == "SentinelX"


def test_openapi_schema_available() -> None:
    """Swagger/OpenAPI schema is exposed for API documentation."""
    response = client.get("/api/openapi.json")
    assert response.status_code == 200
    assert "paths" in response.json()