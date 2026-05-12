"""
models/user.py
--------------
SQLAlchemy ORM model for the `users` table.

Schema
------
id         : UUID primary key (stored as TEXT in SQLite).
email      : Unique, indexed email address.
password   : Hashed password string.

Relationships
-------------
tokens  -> Token   (one-to-many)
scans   -> Scan    (one-to-many)
"""

import uuid

from sqlalchemy import Column, String
from sqlalchemy.orm import relationship

from backend.database import Base


class User(Base):
    __tablename__ = "users"

    # Auto-generated UUID stored as a plain string in SQLite.
    id: str = Column(
        String,
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )
    email: str = Column(String, unique=True, nullable=False, index=True)
    password: str = Column(String, nullable=False)  # Must be stored hashed.

    # ORM back-references
    tokens = relationship("Token", back_populates="user", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
