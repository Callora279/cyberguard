"""Shared pytest fixtures: isolated SQLite DB + seeded org + auth token.

Test credentials policy
-----------------------
No real secrets, emails or license keys are hardcoded in the test suite. Every
credential-shaped value comes from an environment variable with an obviously
fake default, exposed here as a fixture. Override via the environment in CI if
you ever need to point the suite at a real stack.
"""
from __future__ import annotations

import os
import tempfile
import uuid

import pytest

os.environ.setdefault("ENV", "test")
# Mock credentials for the test run only — never real keys.
os.environ.setdefault("GROQ_API_KEY", "gsk_MOCK_groq_key_for_tests_only_000000")
os.environ.setdefault("GITHUB_TOKEN", "ghp_MOCK_github_token_for_tests_only")
os.environ.setdefault("CHAKRA_ORG_ID", "mock-chakra-org-id")
os.environ.setdefault("INTERNAL_SYNC_SECRET", "mock-internal-sync-secret")
os.environ.setdefault("JWT_SECRET", "mock-jwt-secret")
_db_fd, _db_path = tempfile.mkstemp(suffix=".db")
os.environ["DATABASE_URL"] = f"sqlite:///{_db_path}"
os.environ["CYBERGUARD_STATE_DIR"] = tempfile.mkdtemp()

# --- mock credential values (env-overridable) ---------------------------- #
MOCK_EMAIL = os.getenv("TEST_EMAIL", "test@example.com")
MOCK_PASSWORD = os.getenv("TEST_PASSWORD", "test-password-mock")
MOCK_ORG_NAME = os.getenv("TEST_ORG_NAME", "Test Organisation")
# CyberGuard license keys must start with "CG-" (see routes/auth.py); this is a
# non-functional placeholder in that format.
MOCK_LICENSE_KEY = os.getenv("TEST_LICENSE_KEY", "CG-TEST-0000-0000-0000")
# Regex-shaped dummy that trips the secret scanners without being a real key.
MOCK_SECRET_TOKEN = os.getenv("TEST_SECRET_TOKEN", "gsk_MOCKtestdummyDONOTUSE0000000000000000")


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
def demo_credentials() -> dict:
    """The seeded demo login — pulled from the seed module, not hardcoded."""
    from core.database.seed import DEMO_EMAIL, DEMO_PASSWORD

    return {"email": DEMO_EMAIL, "password": DEMO_PASSWORD}


@pytest.fixture(scope="session")
def token(client, demo_credentials) -> str:
    res = client.post("/api/auth/login", json=demo_credentials)
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


@pytest.fixture()
def auth_headers(token) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def mock_credentials() -> dict:
    """Safe, non-real values for register/login flows."""
    return {
        "email": MOCK_EMAIL,
        "password": MOCK_PASSWORD,
        "org_name": MOCK_ORG_NAME,
        "license_key": MOCK_LICENSE_KEY,
    }


@pytest.fixture()
def mock_secret_token() -> str:
    """A fake secret string, regex-compatible with the secret scanners."""
    return MOCK_SECRET_TOKEN


@pytest.fixture()
def unique_email():
    """Factory for collision-free @example.com addresses."""
    return lambda prefix="test": f"{prefix}-{uuid.uuid4().hex[:12]}@example.com"


@pytest.fixture()
def fraud_test_vectors() -> dict:
    """Fake-by-design inputs for the fraud detectors — synthetic data, not creds.

    The domains/formats matter to the detectors (disposable domain, high-abuse
    TLD, placeholder phone), so these can't be generic mock values.
    """
    return {
        "disposable_email": "mock-user-8391@mailinator.com",
        "abuse_tld_email": "mock.buyer@mock-invoices.xyz",
        "genuine_email": "genuine.person@example-corp.co.uk",
        "placeholder_phone": "0000000000",
        "genuine_phone": "+441632960042",  # Ofcom reserved test range
        "genuine_name": "Genuine Person",
        "genuine_address": {"line1": "1 Example Street", "postcode": "EC1A 1BB", "country": "GB"},
    }
