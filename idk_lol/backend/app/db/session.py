"""Database session management.

Supports PostgreSQL (production) via DATABASE_URL=postgresql+psycopg2://...
and SQLite (local development / tests) via DATABASE_URL=sqlite:///...
"""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

_engine: Engine | None = None
_SessionLocal: sessionmaker | None = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        settings = get_settings()
        database_url = settings.DATABASE_URL
        connect_args: dict = {}
        if database_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
        _engine = create_engine(database_url, connect_args=connect_args, pool_pre_ping=True)
    return _engine


def get_session_factory() -> sessionmaker:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(), autoflush=False, autocommit=False)
    return _SessionLocal


def get_db() -> Session:
    """Yield a SQLAlchemy session (FastAPI dependency)."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def reset_engine() -> None:
    """For tests: recreate engine and session factory."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None