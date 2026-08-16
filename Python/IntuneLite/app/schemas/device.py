'''
app/schemas/device.py — Schemas for endpoint telemetry registration and updates.

'''

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ManagedDeviceBase(BaseModel):
    """Shared device telemetry properties."""

    device_name: str
    serial_number: str
    operating_system: str
    os_version: str
    ip_address: str | None = None
    compliance_status: str = "UNKNOWN"
    is_encrypted: bool = False
    is_ms_entra_joined: bool = False
    has_primary_user: bool = True


class ManagedDeviceCreate(ManagedDeviceBase):
    """Schema for registering a new endpoint."""


class ManagedDeviceUpdate(BaseModel):
    """Schema for partial device telemetry updates."""

    os_version: str | None = None
    ip_address: str | None = None
    compliance_status: str | None = None
    is_encrypted: bool | None = None
    is_ms_entra_joined: bool | None = None 
    has_primary_user: bool | None = None


class ManagedDeviceResponse(ManagedDeviceBase):
    """Schema for outgoing device responses."""

    id: int
    last_checkin: datetime
    has_primary_user: bool = True

    model_config = ConfigDict(from_attributes=True)