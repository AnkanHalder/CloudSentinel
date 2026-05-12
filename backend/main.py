"""
main.py
-------
CloudSentinel FastAPI application entry point.

Startup
-------
• Creates all SQLAlchemy tables if they do not already exist.
• Mounts the three route modules under their respective prefixes.

Run
---
    uvicorn backend.main:app --reload
"""

from fastapi import FastAPI

# Import models so their metadata is registered before create_all().
import backend.models  # noqa: F401  (side-effect import)
from backend.api.analytics import router as analytics_router
from backend.api.health import router as health_router
from backend.api.scan import router as scan_router
from backend.api.user import router as user_router
from backend.database import Base, engine

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CloudSentinel API",
    description=(
        "API-first Enterprise Security Guardrail Auditor. "
        "Scans IaC templates for cloud security misconfigurations."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------------------------
# Database initialisation
# ---------------------------------------------------------------------------

Base.metadata.create_all(bind=engine)

# ---------------------------------------------------------------------------
# Route registration
# ---------------------------------------------------------------------------

app.include_router(health_router)
app.include_router(user_router)
app.include_router(scan_router)
app.include_router(analytics_router)
