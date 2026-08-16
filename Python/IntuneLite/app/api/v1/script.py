'''
app/api/v1/scripts.py) and register it in main.py!

This router handles uploading automation scripts, retrieving available scripts for target operating systems, updating scripts, and deleting them.

'''

from typing import Annotated

from app.api.dependencies import SessionDep, get_current_admin_user
from app.models.device import ManagedDevice
from app.models.script import DeploymentScript
from app.models.user import User
from app.schemas.script import (
    DeploymentScriptCreate,
    DeploymentScriptResponse,
    DeploymentScriptUpdate,
)
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

router = APIRouter(prefix="/scripts", tags=["Automation Powershell Scripts"])


@router.post("/",response_model=DeploymentScriptResponse,status_code=status.HTTP_201_CREATED)
def create_script(script_in: DeploymentScriptCreate,db: SessionDep,current_admin: Annotated[User, Depends(get_current_admin_user)],):
    """Uploads a new PowerShell or Bash automation script (Admin Only)."""
    existing = db.execute(
        select(DeploymentScript).where(DeploymentScript.name == script_in.name)
    ).scalar_one_or_none()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A script with this name already exists",
        )

    script = DeploymentScript(**script_in.model_dump())
    db.add(script)
    db.commit()
    db.refresh(script)
    return script


@router.get("/", response_model=list[DeploymentScriptResponse])
def list_scripts(
    db: SessionDep,
    current_admin: Annotated[User, Depends(get_current_admin_user)],
):
    """Lists all stored deployment scripts (Admin Only)."""
    scripts = db.execute(select(DeploymentScript)).scalars().all()
    return scripts


@router.get(
    "/device/{device_id}", response_model=list[DeploymentScriptResponse]
)
def get_scripts_for_device(
    device_id: int,
    db: SessionDep,
    current_admin: Annotated[User, Depends(get_current_admin_user)],
):
    """Fetches active scripts targeted to a specific device's operating system."""
    device = db.execute(
        select(ManagedDevice).where(ManagedDevice.id == device_id)
    ).scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Device not found"
        )

    scripts = (
        db.execute(
            select(DeploymentScript).where(
                (DeploymentScript.is_active == True)
                & (
                    (DeploymentScript.target_os == device.operating_system)
                    | (DeploymentScript.target_os == "All")
                )
            )
        )
        .scalars()
        .all()
    )

    return scripts


@router.patch("/{script_id}", response_model=DeploymentScriptResponse)
def update_script(
    script_id: int,
    script_update: DeploymentScriptUpdate,
    db: SessionDep,
    current_admin: Annotated[User, Depends(get_current_admin_user)],
):
    """Updates an existing deployment script or code content."""
    script = db.execute(
        select(DeploymentScript).where(DeploymentScript.id == script_id)
    ).scalar_one_or_none()

    if not script:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Script not found"
        )

    update_data = script_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(script, field, value)

    db.commit()
    db.refresh(script)
    return script


@router.delete("/{script_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_script(
    script_id: int,
    db: SessionDep,
    current_admin: Annotated[User, Depends(get_current_admin_user)],
):
    """Deletes a deployment script record from IntuneLite."""
    script = db.execute(
        select(DeploymentScript).where(DeploymentScript.id == script_id)
    ).scalar_one_or_none()

    if not script:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Script not found"
        )

    db.delete(script)
    db.commit()
