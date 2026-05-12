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

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_analytics.db"
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


def _scan_file(token: str, relative_path: str, filename_override: str = None):
    file_path = os.path.join(os.getcwd(), relative_path)
    assert os.path.exists(file_path), f"File not found: {file_path}"

    with open(file_path, "rb") as f:
        # Use filename_override to simulate uploading the same file multiple times easily
        fname = filename_override if filename_override else os.path.basename(file_path)
        files = {"file": (fname, f, "application/octet-stream")}
        headers = {"Authorization": f"Bearer {token}"}
        response = client.post("/scan", files=files, headers=headers)

    assert response.status_code == 200
    return response.json()


def test_analytics_endpoints():
    # 1. Register User
    response = client.post(
        "/user", json={"email": "analytics@example.com", "password": "password123"}
    )
    assert response.status_code == 200
    token = response.json()["token"]

    # 2. Upload files
    # Upload S3 twice to test history
    _scan_file(
        token, os.path.join("VulnerableFiles", "AWS", "s3_public_read.tf"), "s3_test.tf"
    )
    _scan_file(
        token, os.path.join("VulnerableFiles", "AWS", "s3_public_read.tf"), "s3_test.tf"
    )

    # Upload Blob once
    _scan_file(
        token,
        os.path.join("VulnerableFiles", "Azure", "blob_public_access.tf"),
        "blob_test.tf",
    )

    headers = {"Authorization": f"Bearer {token}"}

    # 3. Test GET /analytics/global
    res_global = client.get("/analytics/global", headers=headers)
    assert res_global.status_code == 200
    data_global = res_global.json()
    assert data_global["total_scans"] == 3
    assert data_global["total_vulnerabilities"] >= 3
    assert "critical" in data_global["severity_distribution"]

    # 4. Test GET /files
    res_files = client.get("/files", headers=headers)
    assert res_files.status_code == 200
    data_files = res_files.json()
    assert len(data_files) == 2  # s3_test.tf and blob_test.tf
    s3_file = next(f for f in data_files if f["filename"] == "s3_test.tf")
    assert s3_file["scan_count"] == 2

    # 5. Test GET /files/{filename}/history
    res_history = client.get("/files/s3_test.tf/history", headers=headers)
    assert res_history.status_code == 200
    data_history = res_history.json()
    assert data_history["filename"] == "s3_test.tf"
    assert len(data_history["history"]) == 2
    assert data_history["history"][0]["vulnerability_count"] >= 1
    # Check security score constraints
    assert 0 <= data_history["history"][0]["security_score"] <= 10
