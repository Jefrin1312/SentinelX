"""Conftest: shared fixtures for the backend test suite.

The test suite runs against a dedicated ``sentinelx_test`` database so it
never touches development data. The environment variable is set here, before
the application modules are imported, so that ``app.config`` picks up the
test database for the whole session.
"""

import os
import uuid

os.environ["DATABASE_URL"] = (
    "postgresql+psycopg://sentinelx:change_me@127.0.0.1:5432/sentinelx_test"
)
os.environ["SECRET_KEY"] = "test-only-secret-key-that-is-long-enough-for-hmac-sha256-33bytes"

import pytest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app


@pytest.fixture(scope="session", autouse=True)
def _database_schema():
    """Recreate the schema once per test session against the test database."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def db():
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture()
def auth_headers(client):
    """Register a fresh analyst with a unique name and return bearer headers."""
    suffix = uuid.uuid4().hex[:8]
    response = client.post(
        "/api/auth/register",
        json={
            "username": f"tester_{suffix}",
            "email": f"tester_{suffix}@example.com",
            "password": "Str0ngPass!word",
        },
    )
    assert response.status_code == 201, response.text
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}