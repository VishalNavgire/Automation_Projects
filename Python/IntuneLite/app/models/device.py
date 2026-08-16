'''
The Endpoint Telemetry ORM Model

This file represents the core asset of an Endpoint Management platform: the endpoints (laptops, servers, workstations) being monitored.
Core Logic:
Endpoint Telemetry Columns:

device_name & serial_number: Hardware identifiers to uniquely track physical or virtual machines.

operating_system & os_version: OS metadata (e.g., Fedora 40, Windows 11) used by compliance policy algorithms.

compliance_status: Tracks state (COMPLIANT, NON_COMPLIANT, or UNKNOWN).

is_encrypted: Boolean flag indicating disk encryption state (e.g., LUKS or BitLocker).

last_checkin with Timezone Awareness

Mapped[<type>] & mapped_column(...): SQLAlchemy 2.0 type-hinting pattern.

'''
from datetime import datetime, timezone

# from typing import Optional
from app.db.base import Base
from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column


class ManagedDevice(Base):
    __tablename__ = "managed_devices"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    device_name: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    serial_number: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    operating_system: Mapped[str] = mapped_column(String(50), nullable=False)  # e.g., Fedora, Windows, macOS
    os_version: Mapped[str] = mapped_column(String(50), nullable=False)       # e.g., 40.0, 11.0
    # ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    compliance_status: Mapped[str] = mapped_column(String(50), default="UNKNOWN", nullable=False) # COMPLIANT / NON_COMPLIANT
    is_encrypted: Mapped[bool] = mapped_column(default=False, nullable=False)
    last_checkin: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        default=lambda: datetime.now(timezone.utc), 
        nullable=False
    )