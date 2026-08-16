'''

app/core/config.py — Handles application metadata, secret key management, and environment variable loading.
In FastAPI authentication, SECRET_KEY is the cryptographic key used to sign and verify JSON Web Tokens (JWTs).

Why It Is Necessary:

Prevents Token Tampering: When an IT admin logs into IntuneLite, the server returns an encrypted JWT signed with this SECRET_KEY. 
If an attacker tries to modify the token payload (e.g., changing role: "user" to role: "admin"), FastAPI re-calculates the signature using SECRET_KEY. 
If the signatures do not match, FastAPI rejects the request with an HTTP 401 Unauthorized status.

Stateless Authentication: Because the signature can only be produced with the server's secret key, FastAPI can verify incoming requests without querying the database every time 
to confirm session validity.

'''

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application Metadata
    PROJECT_NAME: str = "IntuneLite - Endpoint Management API"
    VERSION: str = "1.0.0 - 10Aug2026"
    API_V1_STR: str = "/api/v1"
    
    # Developer Contact Info
    DEVELOPER_NAME: str = "Vishal Navgire"
    SECRET_KEY: str
    # Security Configuration
    # SECRET_KEY: str = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    # Local SQLite Database Connection String
    DATABASE_URL: str = "sqlite:///./intunelite_10Aug2026.db"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()