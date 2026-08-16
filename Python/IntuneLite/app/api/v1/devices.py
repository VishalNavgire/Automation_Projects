'''
app/api/v1/devices.py
This router handles endpoint registration, listing managed endpoints, updating device status (compliance/encryption), and deleting endpoints. 
It uses our SessionDep and get_current_admin_user dependency for security.

from sqlalchemy import select
SQLAlchemy 2.0 ORM construct used to build type-safe SQL query statements.

setattr(device, field, value): Dynamically updates the attributes on the ORM object in memory before db.commit() writes the changes to disk.

'''

from typing import Annotated

from app.api.dependencies import SessionDep, get_current_admin_user
from app.models.device import ManagedDevice
from app.models.user import User
from app.schemas.device import (
    ManagedDeviceCreate,
    ManagedDeviceResponse,
    ManagedDeviceUpdate,
)
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

router = APIRouter(prefix="/devices", tags=["Managed Devices"])


@router.post("/",response_model=ManagedDeviceResponse,status_code=status.HTTP_201_CREATED,)
def register_a_new_device(
    device_in: ManagedDeviceCreate,
    db: SessionDep,
    current_admin: Annotated[User, Depends(get_current_admin_user)],
):
    """Enrolls a new endpoint device into IntuneLite (Admin Only)."""
    # Check if hostname or serial number already exists
    existing = db.execute(
        select(ManagedDevice).where(
            (ManagedDevice.device_name == device_in.device_name)
            | (ManagedDevice.serial_number == device_in.serial_number)
        )
    ).scalar_one_or_none()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device with this hostname or serial number is already enrolled",
        )

    # Create device model
    device = ManagedDevice(**device_in.model_dump())
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


@router.get("/", response_model=list[ManagedDeviceResponse])
def list_devices(db: SessionDep, current_admin: Annotated[User, Depends(get_current_admin_user)],skip: int = 0, limit: int = 100):
    """Retrieves all enrolled managed endpoints with pagination (Admin Only)."""
    devices = (
        db.execute(select(ManagedDevice).offset(skip).limit(limit))
        .scalars()
        .all()
    )
    return devices


@router.get("/{device_id}", response_model=ManagedDeviceResponse)
def get_device(
    device_id: int,
    db: SessionDep,
    current_admin: Annotated[User, Depends(get_current_admin_user)],
):
    """Gets telemetry details for a specific device by ID."""
    device = db.execute(
        select(ManagedDevice).where(ManagedDevice.id == device_id)
    ).scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Device not found"
        )
    return device


@router.patch("/{device_id}", response_model=ManagedDeviceResponse)
def update_device_telemetry(device_id: int,device_update: ManagedDeviceUpdate,db: SessionDep,current_admin: Annotated[User, Depends(get_current_admin_user)]):
    """Updates device compliance state, OS version, or IP address."""
    device = db.execute(
        select(ManagedDevice).where(ManagedDevice.id == device_id)
    ).scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Device not found for id: {device_id}"
        )

    # Update only provided fields (exclude_unset=True)
    update_data = device_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(device, field, value)

    db.commit()
    db.refresh(device)
    return device


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
def unenroll_device(
    device_id: int,
    db: SessionDep,
    current_admin: Annotated[User, Depends(get_current_admin_user)],
):
    """Unenrolls and removes a device record from IntuneLite."""
    device = db.execute(
        select(ManagedDevice).where(ManagedDevice.id == device_id)
    ).scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Device not found"
        )

    db.delete(device)
    db.commit()
