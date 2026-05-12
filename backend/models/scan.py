"""
models/scan.py
--------------
SQLAlchemy ORM model for the `scans` table.

Schema
------
scan_id      : UUID primary key.
user_id      : FK → users.id
filename     : Original uploaded filename.
scan_time    : UTC datetime when the scan was submitted.
scan_status  : "pending" | "completed" | "failed"
raw_response : Full JSON response from the scanner engine (stored as TEXT).

Relationships
-------------
user            -> User          (many-to-one)
vulnerabilities -> Vulnerability (one-to-many)
"""

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from backend.database import Base


class Scan(Base):
    __tablename__ = "scans"

    scan_id: str = Column(
        String,
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )
    user_id: str = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    filename: str = Column(String, nullable=False)
    scan_time: datetime = Column(DateTime, default=datetime.utcnow, nullable=False)
    scan_status: str = Column(String, default="pending", nullable=False)
    raw_response: str = Column(Text, nullable=True)  # JSON blob from scanner

    user = relationship("User", back_populates="scans")
    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="scan",
        cascade="all, delete-orphan",
    )
