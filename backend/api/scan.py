"""
api/scan.py
-----------
POST /scan — Authenticated IaC file scanning endpoint.

Behaviour
---------
1. Extract the Bearer token from the Authorization header.
2. Validate the token via user_service.validate_token().
3. Delegate to scan_service.execute_scan() which runs the engine,
   stores the Scan + Vulnerability rows, and returns a ScanOut.
4. Return the ScanOut JSON to the caller.
"""

from typing import Annotated

from fastapi import (APIRouter, Depends, File, Header, HTTPException,
                     UploadFile, status)
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.user import User
from backend.schemas.scan import ScanOut
from backend.services.scan_service import execute_scan
from backend.services.user_service import validate_token

router = APIRouter(tags=["Scan"])


def _extract_bearer(authorization: str | None) -> str:
    """Parse 'Bearer <token>' header and return the raw token string."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header. Expected: 'Bearer <token>'",
        )
    return authorization.removeprefix("Bearer ").strip()


@router.post(
    "/scan", response_model=ScanOut, summary="Submit an IaC file for security scanning"
)
async def submit_scan(
    file: Annotated[
        UploadFile,
        File(description="Terraform (.tf) or CloudFormation (.yaml) template."),
    ],
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> ScanOut:
    """
    Upload an IaC template and receive a structured vulnerability report.

    **Authentication**: Provide your API token as `Authorization: Bearer <token>`.
    """
    # 1. Parse & validate token
    token_str: str = _extract_bearer(authorization)
    user: User = validate_token(db=db, token_str=token_str)

    # 2. Read file bytes
    file_content: bytes = await file.read()
    if not file_content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    # 3. Execute scan (persists DB rows internally)
    result: ScanOut = execute_scan(
        db=db,
        user_id=user.id,
        filename=file.filename or "unknown",
        file_content=file_content,
    )

    return result
