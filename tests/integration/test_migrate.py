"""The startup column migration adds columns missing from an older database."""
from __future__ import annotations

import tempfile

import pytest
from sqlalchemy import create_engine, inspect, text

from core.database import migrate


@pytest.fixture()
def legacy_engine(monkeypatch):
    """A throw-away SQLite DB whose ``organisations`` table predates the
    license_key / trial_ends_at / chakra_org_id columns."""
    fd, path = tempfile.mkstemp(suffix=".db")
    eng = create_engine(f"sqlite:///{path}", future=True)
    with eng.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE organisations ("
                "  id VARCHAR(36) PRIMARY KEY,"
                "  name VARCHAR(255) NOT NULL,"
                "  plan VARCHAR(32),"
                "  created_at DATETIME"
                ")"
            )
        )
        conn.execute(
            text("INSERT INTO organisations (id, name, plan) VALUES ('o1', 'Acme', 'trial')")
        )
    monkeypatch.setattr(migrate, "engine", eng)
    yield eng
    eng.dispose()


def _org_columns(eng) -> set[str]:
    return {c["name"] for c in inspect(eng).get_columns("organisations")}


def test_adds_missing_columns(legacy_engine):
    assert "license_key" not in _org_columns(legacy_engine)

    applied = migrate.run_migrations()

    assert set(applied) == {
        "organisations.license_key",
        "organisations.trial_ends_at",
        "organisations.chakra_org_id",
    }
    assert {"license_key", "trial_ends_at", "chakra_org_id"} <= _org_columns(legacy_engine)


def test_is_idempotent(legacy_engine):
    migrate.run_migrations()
    assert migrate.run_migrations() == []  # second pass changes nothing

    # existing rows survive and the new columns are NULL
    with legacy_engine.connect() as conn:
        row = conn.execute(
            text("SELECT name, license_key, trial_ends_at FROM organisations WHERE id='o1'")
        ).one()
    assert row.name == "Acme"
    assert row.license_key is None
    assert row.trial_ends_at is None


def test_skips_when_table_absent(monkeypatch):
    fd, path = tempfile.mkstemp(suffix=".db")
    eng = create_engine(f"sqlite:///{path}", future=True)
    monkeypatch.setattr(migrate, "engine", eng)
    assert migrate.run_migrations() == []  # no organisations table yet, no error
    eng.dispose()
