'''
app/schemas/token.py — Schemas for JWT authentication payloads.
'''
# from typing import Optional

from pydantic import BaseModel


class Token(BaseModel):
    """Schema for returning JWT access tokens to clients."""

    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """Schema for extracted payload claims inside a decoded JWT token."""

    id: int | None = None
    username: str | None = None
    role: str | None = None