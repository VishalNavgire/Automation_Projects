'''
Policy & Evaluation Router (app/api/v1/compliance.py).

This router handles two main responsibilities:

CRUD Operations for Policies: Allows IT Admins to create, read, update, and delete security baseline policies.

Compliance Evaluation Engine: Takes a specific device ID, queries all active policies targeting its OS, compares the device's telemetry against 
those baseline rules, and updates the device's status in SQLite to COMPLIANT or NON_COMPLIANT.


Module Imports
from datetime import datetime, timezone: Generates standard UTC timestamps for evaluation audit records.

from typing import Annotated, List: Used for type hints, dependency injection metadata, and returning JSON lists.

from app.api.dependencies import SessionDep, get_current_admin_user: Provides the SQLite database session and enforces admin RBAC via JWT authentication.

from app.models.compliance import CompliancePolicy & from app.models.device import ManagedDevice: Imports the ORM models to query policies and update device records in intunelite.db.

from app.schemas.compliance import (...): Imports Pydantic schemas for input validation, partial updates, policy responses, and evaluation output.

from fastapi import APIRouter, Depends, HTTPException, status: Imports core FastAPI routing structures and HTTP exception handling.

from sqlalchemy import select: SQLAlchemy 2.0 query builder syntax.


'''

from datetime import datetime, timezone
from typing import Annotated

from app.api.dependencies import SessionDep, get_current_admin_user
from app.models.compliance import CompliancePolicy
from app.models.device import ManagedDevice
from app.models.user import User
from app.schemas.compliance import (
    ComplianceEvaluationResult,
    CompliancePolicyCreate,
    CompliancePolicyResponse,
    CompliancePolicyUpdate,
)
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

router = APIRouter(prefix="/compliance", tags=["Compliance Policies"])


@router.post("/policies",response_model=CompliancePolicyResponse,status_code=status.HTTP_201_CREATED)
def create_compliance_policy(policy_in: CompliancePolicyCreate,db: SessionDep,current_admin: Annotated[User, Depends(get_current_admin_user)]):
    """Creates a new endpoint compliance policy baseline (Admin Only)."""
    existing = db.execute(
        select(CompliancePolicy).where(CompliancePolicy.name == policy_in.name)
    ).scalar_one_or_none()

    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail=f"A policy with this name or id : {policy_in.name} already exists")

# **policy_in.model_dump() converts the validated Pydantic input object into a dictionary:

    policy = CompliancePolicy(**policy_in.model_dump())
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy


@router.get("/policies", response_model=list[CompliancePolicyResponse])
def list_compliance_policies(
    db: SessionDep,
    current_admin: Annotated[User, Depends(get_current_admin_user)],
):
    """Lists all created compliance policies (Admin Only)."""
    policies = db.execute(select(CompliancePolicy)).scalars().all()
    return policies


@router.patch(
    "/policies/{policy_id}", response_model=CompliancePolicyResponse
)
def update_compliance_policy(
    policy_id: int,
    policy_update: CompliancePolicyUpdate,
    db: SessionDep,
    current_admin: Annotated[User, Depends(get_current_admin_user)],
):
    """Updates an existing compliance policy baseline."""
    policy = db.execute(
        select(CompliancePolicy).where(CompliancePolicy.id == policy_id)
    ).scalar_one_or_none()

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found"
        )

    update_data = policy_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(policy, field, value)

    db.commit()
    db.refresh(policy)
    return policy


@router.post(
    "/evaluate/{device_id}", response_model=ComplianceEvaluationResult
)
def evaluate_device_compliance(
    device_id: int,
    db: SessionDep,
    current_admin: Annotated[User, Depends(get_current_admin_user)],
):
    """Evaluates an endpoint against all active compliance policies and updates its status in SQLite."""
    # 1. Fetch targeted device
    device = db.execute(
        select(ManagedDevice).where(ManagedDevice.id == device_id)
    ).scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Device not found"
        )

    # 2. Fetch active policies targeting this OS or 'All'
    policies = (
        db.execute(
            select(CompliancePolicy).where(
                (CompliancePolicy.is_active == True)
                & (
                    (CompliancePolicy.target_os == device.operating_system)
                    | (CompliancePolicy.target_os == "All")
                )
            )
        )
        .scalars()
        .all()
    )

    violations: list[str] = []

    # 3. Evaluate device telemetry against active rules
    for policy in policies:
        # Check Encryption Rule
        if policy.require_encryption and not device.is_encrypted:
            violations.append(
                f"[{policy.name}] Device disk encryption is disabled."
            )

        # Check Minimum OS Version Rule
        if policy.min_os_version and device.os_version:  # noqa: SIM102
            if device.os_version < policy.min_os_version:
                violations.append(
                    f"[{policy.name}] OS version ({device.os_version}) is below required baseline ({policy.min_os_version})."
                )

    # 4. Update Device Compliance Status in Database
    new_status = "NON_COMPLIANT" if violations else "COMPLIANT"
    device.compliance_status = new_status
    db.commit()
    db.refresh(device)

    # 5. Return Evaluation Result DTO
    return ComplianceEvaluationResult(
        device_id=device.id,
        device_name=device.device_name,
        compliance_status=new_status,
        evaluated_at=datetime.now(timezone.utc),
        violations=violations,
    )