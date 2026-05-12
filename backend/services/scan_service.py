"""
services/scan_service.py
------------------------
Business logic for scan execution and result persistence.

Functions
---------
execute_scan : Accepts an uploaded file, selects parser, runs OPA engine,
               persists the Scan record and all Vulnerability rows, and
               returns a ScanOut schema instance.
"""

import json
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from backend.config import config
from backend.core.opa import OPAEngine
from backend.core.parsers import get_parser
from backend.models.scan import Scan
from backend.models.vulnerability import Vulnerability
from backend.schemas.scan import ScanOut, VulnerabilityOut


def _run_scanner(filename: str, content: bytes) -> Dict[str, Any]:
    """
    Parses the IaC file and evaluates it against OPA policies.
    """
    try:
        # 1. Parse
        parser = get_parser(filename)
        parsed_data = parser.parse(content)

        # 2. Evaluate using OPA
        opa_engine = OPAEngine(policy_dir=config.POLICY_DIR)
        findings = opa_engine.evaluate(parsed_data)

        return {"status": "completed", "vulnerabilities": findings}
    except Exception as e:
        return {"status": "failed", "error": str(e), "vulnerabilities": []}


def execute_scan(
    db: Session,
    user_id: str,
    filename: str,
    file_content: bytes,
) -> ScanOut:
    """
    Run the scanner, persist results, and return a ScanOut response.
    """
    scan_id = str(uuid.uuid4())
    scan_record = Scan(
        scan_id=scan_id,
        user_id=user_id,
        filename=filename,
        scan_time=datetime.utcnow(),
        scan_status="pending",
    )
    db.add(scan_record)
    db.flush()  # Persist PK so FK inserts below are valid.

    # --- Run scanner ---
    scanner_output: Dict[str, Any] = _run_scanner(filename, file_content)
    raw_vulns = scanner_output.get("vulnerabilities", [])

    # --- Persist vulnerabilities ---
    vuln_out_list = []
    for raw in raw_vulns:
        vuln_id = str(uuid.uuid4())
        vuln = Vulnerability(
            vulnerability_id=vuln_id,
            scan_id=scan_id,
            severity_score=int(raw.get("severity_score", 1)),
            resource_name=str(raw.get("resource_name", "unknown")),
            message=str(raw.get("message", "")),
            remediation=raw.get("remediation"),
        )
        db.add(vuln)
        vuln_out_list.append(
            VulnerabilityOut(
                vulnerability_id=vuln_id,
                severity_score=vuln.severity_score,
                resource_name=vuln.resource_name,
                message=vuln.message,
                remediation=vuln.remediation,
            )
        )

    # --- Update scan record ---
    scan_record.scan_status = scanner_output.get("status", "completed")
    scan_record.raw_response = json.dumps(scanner_output)

    db.commit()
    db.refresh(scan_record)

    return ScanOut(
        scan_id=scan_record.scan_id,
        filename=scan_record.filename,
        scan_time=scan_record.scan_time,
        scan_status=scan_record.scan_status,
        vulnerabilities=vuln_out_list,
    )
