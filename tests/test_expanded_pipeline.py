import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import Base, get_db
from backend.main import app
from backend.models.scan import Scan
from backend.models.token import Token
from backend.models.user import User
from backend.models.vulnerability import Vulnerability

# Use an in-memory SQLite DB for tests
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_expanded.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    app.dependency_overrides[get_db] = override_get_db
    yield
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.clear()


def _scan_file(token: str, relative_path: str):
    file_path = os.path.join(os.getcwd(), relative_path)
    assert os.path.exists(file_path), f"File not found: {file_path}"

    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f, "application/octet-stream")}
        headers = {"Authorization": f"Bearer {token}"}
        response = client.post("/scan", files=files, headers=headers)

    assert response.status_code == 200, f"Scan failed for {relative_path}"
    return response.json()


def test_expanded_pipeline():
    # 1. Create a dummy user and get a token
    user_payload = {
        "email": "expanded_tester@example.com",
        "password": "securepassword123",
    }
    response = client.post("/user", json=user_payload)
    assert response.status_code == 200

    data = response.json()
    assert "token" in data
    token = data["token"]

    # 2. Test AWS File 1: S3 Public Read
    scan_aws1 = _scan_file(
        token, os.path.join("VulnerableFiles", "AWS", "s3_public_read.tf")
    )
    assert scan_aws1["scan_status"] == "completed"
    assert len(scan_aws1["vulnerabilities"]) >= 1
    vulns_aws1 = [v["message"] for v in scan_aws1["vulnerabilities"]]
    assert any("S3 bucket allows public read access" in msg for msg in vulns_aws1)

    # 3. Test AWS File 2: SG Open SSH
    scan_aws2 = _scan_file(
        token, os.path.join("VulnerableFiles", "AWS", "sg_open_ssh.tf")
    )
    assert scan_aws2["scan_status"] == "completed"
    vulns_aws2 = [v["message"] for v in scan_aws2["vulnerabilities"]]
    assert any("inbound SSH (port 22) from the internet" in msg for msg in vulns_aws2)

    # 4. Test Azure File 1: Blob Public Access
    scan_az1 = _scan_file(
        token, os.path.join("VulnerableFiles", "Azure", "blob_public_access.tf")
    )
    assert scan_az1["scan_status"] == "completed"
    vulns_az1 = [v["message"] for v in scan_az1["vulnerabilities"]]
    assert any(
        "Azure Storage Account allows public blob access" in msg for msg in vulns_az1
    )

    # 5. Test Azure File 2: NSG Open RDP
    scan_az2 = _scan_file(
        token, os.path.join("VulnerableFiles", "Azure", "nsg_open_rdp.tf")
    )
    assert scan_az2["scan_status"] == "completed"
    vulns_az2 = [v["message"] for v in scan_az2["vulnerabilities"]]
    assert any("inbound RDP (port 3389) from the internet" in msg for msg in vulns_az2)

    # Validate the correct schema output structure for all vulnerabilities
    all_vulns = (
        scan_aws1["vulnerabilities"]
        + scan_aws2["vulnerabilities"]
        + scan_az1["vulnerabilities"]
        + scan_az2["vulnerabilities"]
    )
    for vuln in all_vulns:
        assert "vulnerability_id" in vuln
        assert "resource_name" in vuln
        assert "severity_score" in vuln
        assert "message" in vuln
        assert "remediation" in vuln

        # Verify severity score bounds
        assert 1 <= vuln["severity_score"] <= 10
