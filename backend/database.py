"""
database.py
-----------
Establishes the SQLAlchemy engine, session factory, and declarative Base
for CloudSentinel. All models import Base from here; all route handlers
use get_db() as a FastAPI dependency to obtain a scoped session.
"""

from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

# SQLite file stored at the project root when uvicorn is run from there.
SQLALCHEMY_DATABASE_URL: str = "sqlite:///./cloudsentinel.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},  # Required for SQLite + FastAPI
)

# Each request gets its own session; never share sessions across threads.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""

    pass


def get_db() -> Generator:
    """
    FastAPI dependency that yields a database session and ensures
    it is closed after the request completes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
