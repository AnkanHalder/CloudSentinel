"""
api/user.py
-----------
POST /user — User registration / login endpoint.

Behaviour
---------
• Accepts email + password.
• If the user exists  → return their existing token  (is_new_user=False).
• If the user is new  → create user + token row       (is_new_user=True).
• Always returns HTTP 200 with a TokenOut body.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.schemas.user import TokenOut, UserCreate
from backend.services.user_service import get_or_create_user

router = APIRouter(tags=["User"])


@router.post(
    "/user", response_model=TokenOut, summary="Register or authenticate a user"
)
def register_or_login(
    payload: UserCreate,
    db: Session = Depends(get_db),
) -> TokenOut:
    """
    Register a new user or return the existing user's token.

    - **email**: Valid email address.
    - **password**: Minimum 6-character password (stored hashed).
    """
    token_str, is_new = get_or_create_user(
        db=db,
        email=payload.email,
        password=payload.password,
    )
    return TokenOut(token=token_str, is_new_user=is_new)
