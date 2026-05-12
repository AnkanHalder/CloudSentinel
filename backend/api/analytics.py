from typing import Annotated, List

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.user import User
from backend.schemas.analytics import (FileHistoryOut, FileSummaryOut,
                                       GlobalAnalyticsOut)
from backend.services.analytics_service import (get_all_files,
                                                get_file_history,
                                                get_global_analytics)
from backend.services.user_service import validate_token

router = APIRouter(tags=["Analytics"])


def _extract_bearer(authorization: str | None) -> str:
    """Parse 'Bearer <token>' header and return the raw token string."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header. Expected: 'Bearer <token>'",
        )
    return authorization.removeprefix("Bearer ").strip()


@router.get(
    "/files",
    response_model=List[FileSummaryOut],
    summary="Fetch all scanned files metadata",
)
def list_files(
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> List[FileSummaryOut]:
    """Retrieve lightweight file listing with metadata for the authenticated user."""
    token_str = _extract_bearer(authorization)
    user: User = validate_token(db=db, token_str=token_str)

    return get_all_files(db, user.id)


@router.get(
    "/analytics/global",
    response_model=GlobalAnalyticsOut,
    summary="Fetch global security statistics",
)
def global_analytics(
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> GlobalAnalyticsOut:
    """Retrieve organization-style global metrics for the dashboard landing view."""
    token_str = _extract_bearer(authorization)
    user: User = validate_token(db=db, token_str=token_str)

    return get_global_analytics(db, user.id)


@router.get(
    "/files/{filename:path}/history",
    response_model=FileHistoryOut,
    summary="Fetch historical scan data for a specific file",
)
def file_history(
    filename: str,
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> FileHistoryOut:
    """Retrieve timeline progression and security score evolution across multiple scans of a specific file."""
    token_str = _extract_bearer(authorization)
    user: User = validate_token(db=db, token_str=token_str)

    return get_file_history(db, user.id, filename)
