import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import Base, get_db
from backend.main import app

# Use an in-memory SQLite DB for tests
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
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
    # Setup
    Base.metadata.create_all(bind=engine)
    app.dependency_overrides[get_db] = override_get_db
    yield
    # Teardown
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.clear()


def test_full_scan_pipeline():
    # 1. Create a dummy user and get a token
    user_payload = {"email": "test@example.com", "password": "securepassword123"}
    response = client.post("/user", json=user_payload)
    assert response.status_code == 200

    data = response.json()
    assert "token" in data
    token = data["token"]

    # 2. Upload the vulnerable Terraform file
    file_path = os.path.join(os.getcwd(), "sample_data", "sampleBadInfra", "main.tf")
    assert os.path.exists(file_path), "Sample TF file not found"

    with open(file_path, "rb") as f:
        files = {"file": ("main.tf", f, "application/octet-stream")}
        headers = {"Authorization": f"Bearer {token}"}

        scan_response = client.post("/scan", files=files, headers=headers)

    assert scan_response.status_code == 200
    scan_data = scan_response.json()

    assert scan_data["scan_status"] == "completed"
    assert len(scan_data["vulnerabilities"]) == 1

    vuln = scan_data["vulnerabilities"][0]
    assert vuln["severity_score"] == 8
    assert vuln["resource_name"] == "aws_s3_bucket.my_vulnerable_bucket"
    assert "public read access" in vuln["message"]
