'''

app/schemas/compliance.py).

This file defines the data contracts for creating, updating, and returning compliance policies, as well as the schema for compliance evaluation results 
when an endpoint is audited.

from pydantic import BaseModel, ConfigDict, Field:

BaseModel: The foundational class for all Pydantic schemas.

ConfigDict: Configuration dictionary used in Pydantic v2 to enable from_attributes=True (allowing Pydantic to automatically convert SQLAlchemy ORM objects into JSON).

Field: Provides field-level metadata and validation rules (e.g., setting string length limits or default examples).

'''

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class CompliancePolicyBase(BaseModel):
    """Base Pydantic schema for compliance policies."""

    name: str = Field(..., max_length=150, example="Fedora 40 Baseline")
    description: str | None = Field(None, max_length=255, example="Requires Fedora Linux 40.0+ and LUKS encryption")
    target_os: str = Field("All", max_length=50, example="Fedora Linux")
    min_os_version: str | None = Field(None, max_length=50, example="40.0")
    require_encryption: bool = Field(True, example=True)
    is_active: bool = Field(True, example=True)


class CompliancePolicyCreate(CompliancePolicyBase):
    """Schema for creating a new compliance policy."""



class CompliancePolicyUpdate(BaseModel):
    """Schema for updating an existing compliance policy (all fields optional)."""

    name: str | None = Field(None, max_length=150)
    description: str | None = Field(None, max_length=255)
    target_os: str | None = Field(None, max_length=50)
    min_os_version: str | None = Field(None, max_length=50)
    require_encryption: bool | None = None
    is_active: bool | None = None


class CompliancePolicyResponse(CompliancePolicyBase):
    """Output schema for returning compliance policy data."""

    id: int

    model_config = ConfigDict(from_attributes=True)


class ComplianceEvaluationResult(BaseModel):
    """Schema representing the result of evaluating a device against active policies."""

    device_id: int
    device_name: str
    compliance_status: str  # "COMPLIANT" or "NON_COMPLIANT"
    evaluated_at: datetime
    violations: list[str] = []