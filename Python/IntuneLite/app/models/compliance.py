'''

Module Imports
from typing import Optional: Standard Python type hint used to declare fields that can either hold a specific data type or be None (for optional database columns).

from app.db.base import Base: Imports our SQLAlchemy DeclarativeBase catalog. Inheriting from Base registers this class as a database table that Base.metadata.create_all() will generate in intunelite.db.

from sqlalchemy import Boolean, String: SQLAlchemy column types representing SQL VARCHAR / TEXT strings and BOOLEAN flags.

from sqlalchemy.orm import Mapped, mapped_column: Modern SQLAlchemy 2.0 type-annotation constructs:

Mapped[T]: Declares the Python type of the column for static type checking.

mapped_column(...): Defines database constraints such as primary key, nullability, defaults, and field length limits

'''

from app.db.base import Base
from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column


class CompliancePolicy(Base):
    """SQLAlchemy ORM model representing endpoint security baseline rules."""

    __tablename__ = "compliance_policies"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    name: Mapped[str] = mapped_column(String(150), unique=True, index=True, nullable=False)

    description: Mapped[str | None] = mapped_column(String(255), nullable=True)

    target_os: Mapped[str] = mapped_column(String(50), default="All", nullable=False)

    min_os_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    
    require_encryption: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    def __repr__(self) -> str:
        return (
            f"<CompliancePolicy(id={self.id}, name='{self.name}', "
            f"target_os='{self.target_os}', require_encryption={self.require_encryption})>"
        )