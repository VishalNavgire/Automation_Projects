'''
app/core/security.py, which handles two core jobs:

[1] Password Hashing & Verification: 
Securing user passwords using pwdlib (with Argon2/Bcrypt) so we never store raw passwords in intunelite.db.

[2] JWT Token Generation & Decoding: 
Creating cryptographically signed JSON Web Tokens (using PyJWT and our SECRET_KEY) for stateless user and device authentication.


Core Logic Breakdown
password_hash = PasswordHash.recommended(): Uses pwdlib to set up secure hashing algorithms. When you call get_password_hash("MySecret123"), it generates a unique salt and hashes the password into a secure string.

verify_password(...): Compares a user's login password input against the hashed string stored in users.hashed_password. It returns True if they match, and False otherwise.

create_access_token(...):

Creates a payload dictionary containing "sub" (Subject ID), "exp" (Expiration timestamp), and optional claims like "role".

Passes the payload and settings.SECRET_KEY into jwt.encode(), producing a signed string.

decode_access_token(...): Accepts a raw JWT string and validates its signature against settings.SECRET_KEY. If the token has been altered or has expired, jwt.decode() throws an error automatically.

A. Standard Python Libraries
datetime: The standard Python class used to represent points in time (date, hours, minutes, seconds).

timedelta: Represents a duration or difference between two points in time (e.g., "60 minutes" or "7 days"). Used to add an expiration buffer to tokens.

timezone.utc: Ensures all generated timestamps use standard Universal Time Coordinated (UTC) instead of local machine time, preventing timezone sync issues across servers.

typing.Any & Optional: Type hinting constructs. Any means a value can be of any data type (string, integer, dict). Optional[X] means the argument can either be of type X or None.

B. Third-Party Libraries
jwt (PyJWT): The industry-standard library for JSON Web Tokens. It converts Python dictionaries into cryptographically signed base64-encoded JWT strings (jwt.encode) and validates incoming token strings against a secret key (jwt.decode).

pwdlib.PasswordHash: A modern password security wrapper. Calling PasswordHash.recommended() automatically configures secure hashing algorithms like Argon2id and Bcrypt with proper salts, shielding passwords from rainbow table attacks.

C. Internal Application Imports
app.core.config.settings: Imports the application's configuration object, giving security.py access to SECRET_KEY, ALGORITHM ("HS256"), and default token expiration settings (ACCESS_TOKEN_EXPIRE_MINUTES).



'''

from datetime import datetime, timedelta, timezone
from typing import Any

# from typing import Any, Optional
import jwt
from app.core.config import settings
from pwdlib import PasswordHash

# Initialize modern password hashing using recommended defaults (Argon2 / Bcrypt)
password_hash = PasswordHash.recommended()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain-text password against a stored cryptographic hash."""
    return password_hash.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hashes a plain-text password before saving to database."""
    return password_hash.hash(password)


def create_access_token(subject: str | int,expires_delta: timedelta | None = None,extra_claims: dict[str, Any] | None = None) -> str:
    
    """Creates a cryptographically signed JWT access token."""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
 
    # Base payload structure
    to_encode = {
        "exp": expire,  # Expiration time claim
        "sub": str(subject),  # Subject claim (e.g., User ID or Username)
    }

    # Add custom claims if provided (e.g., role="admin")
    if extra_claims:
        to_encode.update(extra_claims)

    # Cryptographically sign the JWT using SECRET_KEY and HS256 algorithm
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def decode_access_token(token: str) -> dict[str, Any]:
    """Decodes and verifies a JWT access token using SECRET_KEY.

    Raises jwt.PyJWTError if token signature is invalid or expired.
    """
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    
    return payload