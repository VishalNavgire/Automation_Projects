'''
Fetching All Records From the FastAPI App:
    To fetch all database records cleanly through running FastAPI endpoints, adding a dedicated System Inventory / Overview endpoint inside an 
    admin router.
    It retrieves a full snapshot of the entire database catalog.
'''

from typing import Annotated

from app.api.dependencies import SessionDep, get_current_admin_user
from app.models.device import ManagedDevice
from app.models.user import User
from app.schemas.device import ManagedDeviceResponse
from app.schemas.user import UserResponse
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select

router = APIRouter(prefix="/admin", tags=["Admin System Overview"])


class SystemDatabaseDump(BaseModel):
    """Schema representing a complete dump of database records for admins."""

    total_users: int
    total_devices: int
    users: list[UserResponse]
    devices: list[ManagedDeviceResponse]


@router.get("/db-overview", response_model=SystemDatabaseDump)
def get_full_database_overview(
    db: SessionDep,
    current_admin: Annotated[User, Depends(get_current_admin_user)],
):
    """Retrieves all user and device records currently stored in intunelite.db (Admin Only)."""
    # Fetch all users
    users = db.execute(select(User)).scalars().all()

    # Fetch all devices
    devices = db.execute(select(ManagedDevice)).scalars().all()

    return SystemDatabaseDump(
        total_users=len(users),
        total_devices=len(devices),
        users=users,
        devices=devices,
    )