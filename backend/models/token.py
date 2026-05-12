"""
models/token.py
---------------
SQLAlchemy ORM model for the `tokens` table.

Schema
------
token_id  : UUID primary key.
user_id   : FK → users.id  (each token belongs to one user).
token_str : The opaque API token in "<uuid>-<uuid>" format.

Relationships
-------------
user -> User (many-to-one)
"""

import uuid

from sqlalchemy import Column, ForeignKey, String
from sqlalchemy.orm import relationship

from backend.database import Base


class Token(Base):
    __tablename__ = "tokens"

    token_id: str = Column(
        String,
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )
    user_id: str = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    # "<uuid4>-<uuid4>" opaque token — 72 chars.
    token_str: str = Column(String, unique=True, nullable=False, index=True)

    user = relationship("User", back_populates="tokens")

    @staticmethod
    def generate_token_str() -> str:
        """Generate a token in the '<uuid>-<uuid>' format."""
        return f"{uuid.uuid4()}-{uuid.uuid4()}"
