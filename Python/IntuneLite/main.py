'''

main.py (Application Entrypoint)
This is the central file that ties all our modules, configuration, database initialization, and router endpoints together.


from contextlib import asynccontextmanager:
    What it does: Imports Python’s built-in asynccontextmanager decorator.
    Why it exists: FastAPI uses asynchronous context managers to handle application startup and shutdown events in a modern, 
    structured way (replacing legacy on_event("startup") hooks).

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create database tables automatically at server startup
    Base.metadata.create_all(bind=engine)
    yield

    What it does:

    [1] Everything before the yield statement runs when Uvicorn boots up the server. Here, Base.metadata.create_all(bind=engine) checks intunelite.db 
    and automatically creates the users and managed_devices tables if they don't already exist.

    [2] The yield hands control back to FastAPI so it can start accepting incoming HTTP requests.

    [3] Anything placed after yield would execute when the server shuts down (e.g., closing connection pools, stopping background tasks).

'''
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import app.models  # Registers User and ManagedDevice models
from app.api.v1.admin import router as admin_router
from app.api.v1.auth import router as auth_router
from app.api.v1.compliance import router as compliance_router
from app.api.v1.devices import router as devices_router
from app.api.v1.script import router as scripts_router
from app.core.config import settings
from app.db.base import Base
from app.db.session import engine
from fastapi import FastAPI


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager: Runs startup tasks (creates DB tables) and handles shutdown."""
    # Create database tables automatically at server startup
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan,
)

# Register Router Modules
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(devices_router, prefix=settings.API_V1_STR)
app.include_router(compliance_router, prefix=settings.API_V1_STR)
app.include_router(scripts_router, prefix=settings.API_V1_STR)
app.include_router(admin_router, prefix=settings.API_V1_STR)


@app.get("/ping_server", tags=["Health Check"])
def root():
    """API Health check endpoint."""
    return {
        "status": "online",
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "developer": settings.DEVELOPER_NAME,
        "docs_url": "/docs",
        "server_time_utc": datetime.now(timezone.utc).isoformat(),
        "api_v1_prefix": settings.API_V1_STR,
        "database_engine": engine.name,
    }