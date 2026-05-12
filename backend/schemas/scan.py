"""
schemas/scan.py
---------------
Pydantic v2 request / response schemas for Scan and Vulnerability operations.

VulnerabilityOut : Single vulnerability finding returned in a scan response.
ScanOut          : Full scan result including all vulnerability findings.
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class VulnerabilityOut(BaseModel):
    """A single security finding within a scan result."""

    vulnerability_id: str
    severity_score: int = Field(
        ..., ge=1, le=10, description="Severity score 1 (info) – 10 (critical)."
    )
    resource_name: str = Field(..., description="Affected IaC resource identifier.")
    message: str = Field(
        ..., description="Description of the detected misconfiguration."
    )
    remediation: Optional[str] = Field(
        None, description="Recommended remediation steps."
    )

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    """Full scan result returned to the caller and stored in the DB."""

    scan_id: str
    filename: str
    scan_time: datetime
    scan_status: str
    vulnerabilities: List[VulnerabilityOut] = []

    model_config = {"from_attributes": True}
