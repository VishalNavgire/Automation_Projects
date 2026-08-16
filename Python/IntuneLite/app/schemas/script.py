'''
app/schemas/script.py

This file defines the data validation contracts for creating, updating, listing, and serving deployment scripts to target endpoints.
'''


from pydantic import BaseModel, ConfigDict, Field


class DeploymentScriptBase(BaseModel):
    """Base Pydantic schema for deployment automation scripts."""

    name: str = Field(..., max_length=150, example="Enable LUKS Disk Encryption")
    description: str | None = Field(None, max_length=255, example="Enforces disk encryption on Linux endpoints")
    target_os: str = Field("All", max_length=50, example="Fedora Linux")
    script_type: str = Field(..., max_length=20, example="Bash")  # "PowerShell" or "Bash"
    content: str = Field(..., example="#!/bin/bash\n echo 'Remediating system baseline...'")
    is_active: bool = Field(True, example=True)


class DeploymentScriptCreate(DeploymentScriptBase):
    """Schema for creating a new deployment script."""


class DeploymentScriptUpdate(BaseModel):
    """Schema for updating an existing deployment script (all fields optional)."""

    name: str | None = Field(None, max_length=150)
    description: str | None = Field(None, max_length=255)
    target_os: str | None = Field(None, max_length=50)
    script_type: str | None = Field(None, max_length=20)
    content: str | None = None
    is_active: bool | None = None


class DeploymentScriptResponse(DeploymentScriptBase):
    """Output schema for returning deployment script data."""

    id: int

    model_config = ConfigDict(from_attributes=True)