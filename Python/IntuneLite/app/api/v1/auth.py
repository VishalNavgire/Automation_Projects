'''
app/api/v1/auth.py — Registration and Login endpoints (/api/v1/auth/register and /api/v1/auth/token).

Core Logic Breakdown for app/api/v1/auth.py :

[1] APIRouter(prefix="/auth", tags=["Authentication"]): Groups all authentication routes under the /api/v1/auth path prefix in Swagger UI.
[2] OAuth2PasswordRequestForm: FastAPI's built-in dependency that expects standard form data containing username and password. 
    This enables the "Authorize" button in Swagger UI to log in interactively.
[3] register_user: Validates input against UserCreate, checks for duplicate users in SQLite, hashes the password via get_password_hash(), 
    and returns UserResponse (which safely excludes the password).
[4] login_for_access_token: Verifies login credentials against stored hashes via verify_password() and returns a signed JWT token string.

'''

from typing import Annotated

from app.api.dependencies import SessionDep, get_current_admin_user, get_current_user
from app.core.security import (
    create_access_token,
    get_password_hash,
    verify_password,
)
from app.models.user import User
from app.schemas.token import Token
from app.schemas.user import (
    PasswordResetAdmin,
    PasswordResetSelf,
    UserCreate,
    UserResponse,
)
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select

router = APIRouter(prefix="/authentication", tags=["Authentication"])

@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):  # noqa: B008
    """Fetches details for the currently authenticated user."""
    return current_user

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_a_new_user(user_in: UserCreate, db: SessionDep):
    """Registers a new IT Administrator account."""
    # 1. Check if email or username already exists
    existing_user = db.execute(
        select(User).where(
            (User.email == user_in.email) | (User.username == user_in.username)
        )
    ).scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email or username already exists",
        )

    # 2. Hash raw password
    hashed_password = get_password_hash(user_in.password)

    # 3. Create and save User ORM object
    new_user = User(
        email=user_in.email,
        username=user_in.username,
        hashed_password=hashed_password,
        full_name=user_in.full_name,
        role=user_in.role,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.post("/token", response_model=Token)
def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: SessionDep):
    """Authenticates admin credentials and returns a signed JWT access token."""
    # 1. Query user by username (form_data.username contains username input)
    user = db.execute(
        select(User).where(User.username == form_data.username)
    ).scalar_one_or_none()

    # 2. Verify existence and password hash
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user"
        )

    # 3. Mint JWT token
    access_token = create_access_token(
        subject=user.id,
        extra_claims={"username": user.username, "role": user.role},
    )

    return Token(access_token=access_token, token_type="bearer")


@router.post("/reset-password/me", status_code=status.HTTP_200_OK)
def reset_own_password(
    password_data: PasswordResetSelf,
    db: SessionDep,
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Self-service password reset for the currently logged-in user."""
    # Verify current password
    if not verify_password(password_data.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect current password",
        )

    # Hash and update new password
    current_user.hashed_password = get_password_hash(password_data.new_password)
    db.commit()

    return {"message": "Password updated successfully"}


@router.post("/reset-password/admin/{user_id}", status_code=status.HTTP_200_OK)
def admin_reset_user_password(
    user_id: int,
    password_data: PasswordResetAdmin,
    db: SessionDep,
    current_admin: Annotated[User, Depends(get_current_admin_user)],
):
    """Administrative password reset override for any targeted user ID (Admin Only)."""
    target_user = db.execute(
        select(User).where(User.id == user_id)
    ).scalar_one_or_none()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target user not found",
        )

    # Hash and assign new password
    target_user.hashed_password = get_password_hash(password_data.new_password)
    db.commit()

    return {
        "message": f"Password for user '{target_user.username}' (ID: {target_user.id}) has been reset successfully."
    }