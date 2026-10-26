"""Lightweight, idempotent schema migrations.

The project bootstraps its schema with ``Base.metadata.create_all`` (see
``core/database/db.py::init_db``). ``create_all`` creates *missing tables* but
never alters an existing one, so a database that was created before a column was
added to a model is left without that column — exactly the "production database
is missing columns" failure mode.

This module closes that gap. It inspects the live database and issues
``ALTER TABLE ... ADD COLUMN`` for every column listed in :data:`ADDITIVE_COLUMNS`
that the table does not already have. It is safe to run on every startup (it is
called from the FastAPI lifespan in ``core/api/main.py``) and can also be run by
hand::

    python -m core.database.migrate

Only *additive* changes are handled here — new nullable columns. Anything more
involved (renames, type changes, back-fills, drops) should be a real Alembic
migration.
"""
from __future__ import annotations

from sqlalchemy import inspect, text
from sqlalchemy.exc import SQLAlchemyError

from core.database.db import engine, init_db
from core.utils.logger import get_logger

logger = get_logger("database.migrate")

# table -> column -> SQL type per dialect.
#
# Keep the types dialect-safe: SQLite is forgiving about column types but still
# needs one; PostgreSQL wants a real type. All columns here are nullable (no
# NOT NULL / DEFAULT) so the ALTER is instant and cannot fail on existing rows.
ADDITIVE_COLUMNS: dict[str, dict[str, dict[str, str]]] = {
    "organisations": {
        "license_key": {"postgresql": "VARCHAR(128)", "sqlite": "VARCHAR"},
        "trial_ends_at": {
            "postgresql": "TIMESTAMP WITH TIME ZONE",
            "sqlite": "DATETIME",
        },
        "chakra_org_id": {"postgresql": "VARCHAR(64)", "sqlite": "VARCHAR"},
    },
    "org_settings": {
        # Phase 2 — notifications / webhooks / integrations
        "github_webhook_secret": {"postgresql": "VARCHAR(128)", "sqlite": "VARCHAR"},
        "slack_daily_digest": {"postgresql": "BOOLEAN DEFAULT FALSE", "sqlite": "BOOLEAN DEFAULT 0"},
        "notification_email": {"postgresql": "VARCHAR(255)", "sqlite": "VARCHAR"},
        "notify_types": {"postgresql": "JSONB DEFAULT '[]'::jsonb", "sqlite": "TEXT DEFAULT '[]'"},
        "weekly_digest": {"postgresql": "BOOLEAN DEFAULT TRUE", "sqlite": "BOOLEAN DEFAULT 1"},
        "last_notified_score": {"postgresql": "DOUBLE PRECISION", "sqlite": "REAL"},
        "jira_url": {"postgresql": "VARCHAR(255)", "sqlite": "VARCHAR"},
        "jira_user": {"postgresql": "VARCHAR(255)", "sqlite": "VARCHAR"},
        "jira_token": {"postgresql": "VARCHAR(255)", "sqlite": "VARCHAR"},
        "jira_project_key": {"postgresql": "VARCHAR(32)", "sqlite": "VARCHAR"},
    },
    "alerts": {
        # alert dedupe: one open alert per (org, module, kind)
        "kind": {"postgresql": "VARCHAR(64)", "sqlite": "VARCHAR"},
        "count": {"postgresql": "INTEGER", "sqlite": "INTEGER"},
        "last_seen": {"postgresql": "TIMESTAMP WITH TIME ZONE", "sqlite": "DATETIME"},
    },
}


def _column_type(dialect: str, spec: dict[str, str]) -> str:
    return spec.get(dialect) or spec.get("sqlite", "VARCHAR")


def run_migrations() -> list[str]:
    """Add any missing additive columns.

    Returns the list of ``"table.column"`` changes that were applied. Idempotent:
    a second call on an up-to-date database returns ``[]`` and touches nothing.
    """
    dialect = engine.dialect.name
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    applied: list[str] = []

    for table, columns in ADDITIVE_COLUMNS.items():
        if table not in existing_tables:
            # A brand-new database has no such table yet; init_db()/create_all
            # will build it from the model with every column already present.
            logger.debug("migrate: table %s absent, skipping", table)
            continue

        present = {col["name"] for col in inspector.get_columns(table)}
        for column, type_spec in columns.items():
            if column in present:
                continue

            col_type = _column_type(dialect, type_spec)
            # PostgreSQL supports IF NOT EXISTS, which makes concurrent startups
            # (multiple API replicas) race-safe. SQLite does not, but the
            # inspector check above already guards it there.
            guard = "IF NOT EXISTS " if dialect == "postgresql" else ""
            ddl = f"ALTER TABLE {table} ADD COLUMN {guard}{column} {col_type}"
            try:
                with engine.begin() as conn:
                    conn.execute(text(ddl))
            except SQLAlchemyError as exc:  # pragma: no cover - defensive
                # Another replica added it first, or the column already exists
                # on a dialect without IF NOT EXISTS. Log and carry on.
                logger.warning("migrate: could not add %s.%s: %s", table, column, exc)
                continue

            applied.append(f"{table}.{column}")
            logger.info("migrate: added column %s.%s (%s)", table, column, col_type)

    if applied:
        logger.info("migrate: applied %d column change(s)", len(applied))
    else:
        logger.info("migrate: schema already up to date (%s)", dialect)
    return applied


def suppress_ignored_findings() -> int:
    """One-time cleanup: open findings under ignored paths become "suppressed".

    Rows are kept (not deleted) but leave every "open" count, score and alert.
    Idempotent: once suppressed, a row no longer matches ``status == 'open'``.
    """
    from core.database.db import session_scope
    from core.database.models import SecurityFinding
    from core.services.security_debt.scanner import is_ignored_path

    with session_scope() as db:
        rows = db.query(SecurityFinding).filter(SecurityFinding.status == "open").all()
        hits = [r for r in rows if r.file_path and is_ignored_path(r.file_path)]
        for r in hits:
            r.status = "suppressed"
    if hits:
        logger.info("migrate: suppressed %d finding(s) under ignored paths", len(hits))
    return len(hits)


def main() -> None:
    """CLI entrypoint: ``python -m core.database.migrate``."""
    init_db()  # make sure the baseline tables exist first
    applied = run_migrations()
    suppressed = suppress_ignored_findings()
    if suppressed:
        print(f"Suppressed {suppressed} finding(s) under ignored paths.")
    if applied:
        print(f"Applied {len(applied)} column migration(s):")
        for change in applied:
            print(f"  + {change}")
    else:
        print("No migrations needed - schema is up to date.")


if __name__ == "__main__":
    main()
