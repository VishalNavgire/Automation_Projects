'''
The IT Administrator ORM Model:

This file defines the SQL table schema for human administrators who manage the IntuneLite system 
(such as creating compliance rules, running device actions, or deploying scripts).

Core Logic:
__tablename__ = "users": Explicitly sets the physical table name in SQLite.

Mapped[...] & mapped_column(...): Modern SQLAlchemy 2.0 type-hinting constructs:

Mapped[int] tells Python’s type checker that the column holds integers.

primary_key=True, index=True: Auto-increments unique IDs and adds a B-Tree index for lightning-fast database lookups.

unique=True: Ensures no two administrators can register with the exact same email or username.

hashed_password: Stores cryptographically hashed passwords (never raw plain text).

role: Defaults to "admin", preparing the system for Role-Based Access Control (RBAC).

'''
# from typing import Optional

from app.db.base import Base
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(150), nullable=True)
    role: Mapped[str] = mapped_column(String(50), default="admin", nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)