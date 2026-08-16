'''
app/schemas/user.py — Schemas for Admin registration, updates, and responses.

1. Imports
BaseModel: The core class from Pydantic. Inheriting from BaseModel turns a standard Python class into an automated data validator and JSON serializer.

EmailStr: A specialized Pydantic string type that automatically enforces RFC-compliant email formatting (e.g., checks for @ and valid domains).

ConfigDict: Used in Pydantic v2 to pass configuration options to a schema model.

2. UserBase(BaseModel)
Purpose: Acts as a shared parent schema to keep code DRY (Don't Repeat Yourself). It holds common fields needed across both registration requests and outgoing user responses (email, username, full_name, role).

Defaults: full_name is optional (defaults to None), and role defaults to "admin".

3. UserCreate(UserBase) — Input Schema
Purpose: Validates incoming JSON sent by a client during user registration (POST /api/v1/auth/register).

Inheritance: Inherits all fields from UserBase and adds the password field.

Security Design: password exists only in UserCreate. It is never included in response schemas.

4. UserResponse(UserBase) — Output Schema
Purpose: Formats outgoing JSON returned to clients after querying a user.

Field Additions: Adds id (database primary key) and is_active (account status).

model_config = ConfigDict(from_attributes=True):

By default, Pydantic expects inputs to be Python dictionaries ({"id": 1, "email": "..."}).

from_attributes=True allows Pydantic to read directly from SQLAlchemy ORM instances (where attributes are accessed via dot notation, like user_orm.email).

'''

from pydantic import BaseModel, ConfigDict, Field

# from pydantic import BaseModel, ConfigDict, EmailStr, Field


# class UserBase(BaseModel):
#     """Shared user properties."""

#     email: EmailStr = Field(title="Email Address", example="vishal@example.com")
#     username: str
#     full_name: str | None = None
#     role: str = "admin"


class UserBase(BaseModel):
    """Shared user properties."""

    email: str = Field(..., title="Email Address", example="vishal@intunelite.local")
    username: str = Field(..., max_length=50)
    full_name: str | None = None
    role: str = "admin"


class UserCreate(UserBase):
    """Schema for incoming registration payload (requires raw password)."""

    password: str


class UserResponse(UserBase):
    """Schema for outgoing API responses (excludes password/hashes)."""

    id: int
    is_active: bool

    # Enables Pydantic to automatically read attributes from SQLAlchemy ORM models
    model_config = ConfigDict(from_attributes=True)

class PasswordResetSelf(BaseModel):
    """Schema for a user changing their own password."""

    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8)


class PasswordResetAdmin(BaseModel):
    """Schema for an admin forcing a password reset for another user."""

    new_password: str = Field(..., min_length=8)