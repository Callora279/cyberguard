"""Shared pytest fixtures: isolated SQLite DB + seeded org + auth token."""
from __future__ import annotations

import os
import tempfile

import pytest

os.environ.setdefault("ENV", "test")
# Dummy credentials for the test run only — never real keys.
os.environ.setdefault("GROQ_API_KEY", "gsk_test_dummy_key_for_testing")
os.environ.setdefault("GITHUB_TOKEN", "ghp_test_dummy_token")
os.environ.setdefault("CHAKRA_ORG_ID", "test-chakra-org-id")
os.environ.setdefault("INTERNAL_SYNC_SECRET", "test-internal-sync-secret")
os.environ.setdefault("JWT_SECRET", "test-jwt-secret")
_db_fd, _db_path = tempfile.mkstemp(suffix=".db")
os.environ["DATABASE_URL"] = f"sqlite:///{_db_path}"
os.environ["CYBERGUARD_STATE_DIR"] = tempfile.mkdtemp()


@pytest.fixture(scope="session", autouse=True)
def _bootstrap_db():
    from core.database.db import init_db
    from core.database.seed import seed

    init_db()
    seed()
    yield
    os.close(_db_fd)
    try:
        os.unlink(_db_path)
    except OSError:
        pass


@pytest.fixture(scope="session")
def org_id(_bootstrap_db) -> str:
    from sqlalchemy import select

    from core.database.db import session_scope
    from core.database.models import Organisation

    with session_scope() as db:
        return db.scalar(select(Organisation)).id


@pytest.fixture(scope="session")
def client(_bootstrap_db):
    from fastapi.testclient import TestClient

    from core.api.main import app

    return TestClient(app)


@pytest.fixture(scope="session")
def token(client) -> str:
    res = client.post(
        "/api/auth/login",
        json={"email": "admin@cyberguard.ai", "password": "cyberguard-demo"},
    )
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


@pytest.fixture()
def auth_headers(token) -> dict:
    return {"Authorization": f"Bearer {token}"}
