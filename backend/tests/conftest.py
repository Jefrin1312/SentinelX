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
# The whole suite shares a single TestClient IP, so rate limiting must be
# disabled or later tests would be blocked regardless of correctness.
os.environ["LOGIN_RATE_LIMIT"] = "0/minute"
os.environ["LOGIN_ACCOUNT_RATE_LIMIT"] = "0/minute"
os.environ["REGISTER_RATE_LIMIT"] = "0/minute"

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
def make_client():
    """Create an additional TestClient with its own cookie jar.

    Cookie sessions live on the client, so tests that need two authenticated
    users at once (ownership isolation, RBAC) use this instead of sharing one
    client. The demo admin is seeded by the first (session-scoped) client's
    lifespan, so a second client can log in as admin against the shared DB.
    """
    clients = []

    def factory():
        test_client = TestClient(app)
        clients.append(test_client)
        return test_client

    yield factory
    for test_client in clients:
        test_client.close()


@pytest.fixture()
def db():
    session = SessionLocal()
    yield session
    session.close()


def _csrf_headers(client):
    """Return the CSRF header matching the client's current session cookie.

    The JWT rides in the client's HttpOnly cookie jar; state-changing requests
    must also echo the sentinelx_csrf cookie value via X-CSRF-Token.
    """
    csrf = client.cookies.get("sentinelx_csrf")
    return {"X-CSRF-Token": csrf} if csrf else {}


@pytest.fixture()
def auth_headers(client):
    """Register a fresh analyst on the client and return CSRF-session headers."""
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
    return _csrf_headers(client)


@pytest.fixture()
def admin_headers(client):
    """Log in as the seeded administrator and return CSRF-session headers.

    Only valid while the shared client's cookie jar holds the admin session;
    tests that need a second concurrent identity use ``make_client``.
    """
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Admin@12345"},
    )
    assert response.status_code == 200, response.text
    return _csrf_headers(client)


@pytest.fixture()
def session_user(client, db):
    """Return the User row for the identity currently held by ``client``.

    Tests that write rows directly (rather than through the API) must scope
    them to this user, because events and alerts are tenant-owned.
    """
    from app.auth.cookies import AUTH_COOKIE
    from app.auth.security import decode_access_token
    from app.models.user import User

    token = client.cookies.get(AUTH_COOKIE)
    assert token, "client holds no session cookie; use a fixture that logs in first"
    payload = decode_access_token(token)
    return db.query(User).filter(User.id == int(payload["sub"])).one()