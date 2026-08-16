'''
app/api/dependencies.py

This layer acts as the security gatekeeper for your API. It extracts incoming JWT bearer tokens from HTTP headers, 
validates them using decode_access_token, fetches the user or device from intunelite.db, 
and enforces Role-Based Access Control (RBAC) before route handlers execute.

Core Logic Breakdown
[1] OAuth2PasswordBearer:
Reads the Authorization header from incoming HTTP requests expecting Bearer <JWT_TOKEN>.
Integrates seamlessly with FastAPI's OpenAPI/Swagger UI, adding an "Authorize" button to docs automatically.

[2] get_current_user(...):
Extracts the raw token string from oauth2_scheme.
Calls decode_access_token(token) to extract claims (sub, username, role).
Queries intunelite.db using select(User).where(User.id == token_data.id) to confirm the user exists and is active.
If any step fails (invalid token, missing claims, non-existent user), raises HTTP 401 Unauthorized.

[3] get_current_admin_user(...):
Leverages FastAPI's dependency chaining: It calls get_current_user first to authenticate the user.
Checks current_user.role == "admin". If not, raises HTTP 403 Forbidden.

'''
from collections.abc import Generator
from typing import Annotated

import jwt
from app.core.config import settings
from app.core.security import decode_access_token
from app.db.session import SessionLocal
from app.models.user import User
from app.schemas.token import TokenData
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

# 1. Configures FastAPI to look for "Authorization: Bearer <token>" headers
# tokenUrl points to our upcoming login/token generation endpoint
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/authentication/token")


def get_db() -> Generator[Session, None, None]:
    """Provides a transactional database session per HTTP request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

'''

Explanation of SessionDep = Annotated[Session, Depends(get_db)]
This line is a modern Python/FastAPI pattern (introduced in FastAPI 0.95+) called Dependency Type Aliasing.

Breakdown of the Parts:
Session: The standard SQLAlchemy type hint telling Python that this variable is a database session object.

Depends(get_db): Tells FastAPI: "Before executing any function that uses this dependency, run get_db() first to open a DB connection and yield it here."

Annotated[...]: A built-in Python type feature (typing.Annotated) that attaches metadata (here, Depends(get_db)) to a Python type hint (Session).

SessionDep = ...: Creates a clean, reusable shortcut alias.

'''
# Type alias for database dependency injection
SessionDep = Annotated[Session, Depends(get_db)]


def get_current_user(db: SessionDep, token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    """Validates incoming JWT token and returns the authenticated User ORM instance."""
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Could not validate credentials",headers={"WWW-Authenticate": "Bearer"})

    try:
        # Decode token payload
        payload = decode_access_token(token)
        user_id: str = payload.get("sub")
        username: str = payload.get("username")
        role: str = payload.get("role")

        if user_id is None:
            raise credentials_exception

        token_data = TokenData(id=int(user_id), username=username, role=role)
    except (jwt.PyJWTError, ValueError):
        raise credentials_exception

    # Query user from SQLite database
    user = (
        db.execute(select(User).where(User.id == token_data.id))
        .scalars()
        .first()
    )

    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user"
        )

    return user


def get_current_admin_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Enforces Role-Based Access Control (RBAC): User must have 'admin' role."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user does not have sufficient privileges",
        )
    return current_user