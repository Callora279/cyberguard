"""Initial migration.

This project uses ``Base.metadata.create_all`` for schema bootstrap (see
``core/database/db.py::init_db``). This module documents the baseline schema and
provides an idempotent ``upgrade`` / ``downgrade`` pair so the same entrypoint
works if you later adopt Alembic.
"""
from __future__ import annotations

from core.database.db import Base, engine

revision = "0001_initial"
down_revision = None


def upgrade() -> None:
    from core.database import models  # noqa: F401

    Base.metadata.create_all(bind=engine)


def downgrade() -> None:
    Base.metadata.drop_all(bind=engine)


if __name__ == "__main__":
    upgrade()
    print("applied", revision)
