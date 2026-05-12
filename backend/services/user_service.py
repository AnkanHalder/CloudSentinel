"""
services/user_service.py
------------------------
Business logic for user registration and token management.

Functions
---------
get_or_create_user : Looks up a user by email. Creates a new user + token if
                     none is found; returns the existing token otherwise.
validate_token     : Verifies a token string exists in the DB and returns the
                     associated User, or raises HTTP 401 if invalid.
"""

import hashlib
import uuid
from typing import Tuple

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from backend.models.token import Token
from backend.models.user import User


def _hash_password(plain: str) -> str:
    """SHA-256 hash of the plain-text password. Replace with bcrypt in production."""
    return hashlib.sha256(plain.encode()).hexdigest()


def get_or_create_user(
    db: Session,
    email: str,
    password: str,
) -> Tuple[str, bool]:
    """
    Look up a user by email. If found, return (token_str, False).
    If not found, create user + token and return (token_str, True).

    Parameters
    ----------
    db       : Active SQLAlchemy session.
    email    : Email address from the request.
    password : Plain-text password (will be hashed before storage).

    Returns
    -------
    (token_str, is_new_user)
    """
    existing_user: User | None = db.query(User).filter(User.email == email).first()

    if existing_user:
        # Return the first token associated with this user.
        token: Token | None = (
            db.query(Token).filter(Token.user_id == existing_user.id).first()
        )
        if not token:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="User exists but has no associated token.",
            )
        return token.token_str, False

    # --- New user path ---
    new_user = User(
        id=str(uuid.uuid4()),
        email=email,
        password=_hash_password(password),
    )
    db.add(new_user)
    db.flush()  # Assigns PK without committing so FK below can reference it.

    new_token = Token(
        token_id=str(uuid.uuid4()),
        user_id=new_user.id,
        token_str=Token.generate_token_str(),
    )
    db.add(new_token)
    db.commit()
    db.refresh(new_token)

    return new_token.token_str, True


def validate_token(db: Session, token_str: str) -> User:
    """
    Validate an API token string. Returns the owning User on success.
    Raises HTTP 401 if the token does not exist.
    """
    token: Token | None = db.query(Token).filter(Token.token_str == token_str).first()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API token.",
        )
    return token.user
