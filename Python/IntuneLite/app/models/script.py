'''
Text to be added.
'''


from app.db.base import Base
from sqlalchemy import Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column


class DeploymentScript(Base):
    """SQLAlchemy ORM model representing automation scripts (PowerShell/Bash)."""

    __tablename__ = "deployment_scripts"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(150), unique=True, index=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_os: Mapped[str] = mapped_column(String(50), default="All", nullable=False)
    script_type: Mapped[str] = mapped_column(String(20), nullable=False)  # "PowerShell" or "Bash"
    content: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    def __repr__(self) -> str:
        return (
            f"<DeploymentScript(id={self.id}, name='{self.name}', "
            f"target_os='{self.target_os}', script_type='{self.script_type}')>"
        )