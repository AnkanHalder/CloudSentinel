"""
schemas/user.py
---------------
Pydantic v2 request / response schemas for User and Token operations.

UserCreate  : Incoming POST /user payload.
TokenOut    : Response body returned to the caller on /user.
"""

from pydantic import BaseModel, Field


class UserCreate(BaseModel):
    """Payload accepted by POST /user."""

    email: str = Field(..., description="User's email address.")
    password: str = Field(
        ..., min_length=6, description="Plain-text password (hashed server-side)."
    )


class TokenOut(BaseModel):
    """Response returned to the caller after user creation or lookup."""

    token: str = Field(..., description="Opaque API access token (<uuid>-<uuid>).")
    is_new_user: bool = Field(..., description="True if the user was just created.")

    model_config = {"from_attributes": True}
