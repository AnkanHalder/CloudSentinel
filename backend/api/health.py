"""
api/health.py
-------------
GET /health — Lightweight liveness probe. Returns HTTP 200 + JSON body.
No database access is performed here; this is intentional so the probe
works even when the DB is briefly unavailable during startup.
"""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter(tags=["Health"])


@router.get("/health", summary="Server liveness probe")
async def health_check() -> JSONResponse:
    """Return HTTP 200 to indicate the API server is running."""
    return JSONResponse(content={"status": "ok", "service": "CloudSentinel"})
