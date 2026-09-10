"""Database engine, session factory and schema bootstrap.

Uses SQLAlchemy 2.0. PostgreSQL in production (``DATABASE_URL``), SQLite for dev.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from core.utils.config import settings
from core.utils.logger import get_logger

logger = get_logger("database")

_connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    pool_pre_ping=True,
    connect_args=_connect_args,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def init_db() -> None:
    """Create all tables. Safe to call on every startup."""
    from core.database import models  # noqa: F401  (registers mappers)

    Base.metadata.create_all(bind=engine)
    logger.info("database schema ready (%s)", engine.url.get_backend_name())


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for background workers / scripts."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session() -> Iterator[Session]:
    """FastAPI dependency."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
