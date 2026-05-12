"""
hooks/api_client.py
-------------------
HTTP communication layer for the CloudSentinel pre-commit hook.
Handles authentication loading and scan submission — no interactive prompts here.
"""

import io
import sys
from pathlib import Path
from typing import Optional

import requests

from hooks.config import API_BASE_URL, SCAN_TIMEOUT_SECONDS, TOKEN_FILE


def load_token() -> Optional[str]:
    """
    Load the saved API token from disk.
    Returns None if the token file does not exist or is empty.
    Never prompts the user interactively.
    """
    if not TOKEN_FILE.exists():
        return None
    token = TOKEN_FILE.read_text().strip()
    return token if token else None


def save_token(token: str) -> None:
    """Persist a token string to disk."""
    TOKEN_FILE.write_text(token)


def authenticate(email: str, password: str) -> Optional[str]:
    """
    POST /user → returns the API token string on success, None on failure.
    Called only by the `cloudsentinel login` CLI — never by the hook itself.
    """
    try:
        resp = requests.post(
            f"{API_BASE_URL}/user",
            json={"email": email, "password": password},
            timeout=SCAN_TIMEOUT_SECONDS,
        )
        if resp.status_code == 200:
            return resp.json().get("token")
        return None
    except requests.exceptions.RequestException:
        return None


def submit_scan(token: str, filename: str, content: bytes) -> Optional[dict]:
    """
    POST /scan with the file content bytes.
    Returns the parsed ScanOut dict on success, None on any error.
    Raises requests.exceptions.ConnectionError if the server is unreachable.
    Raises requests.exceptions.Timeout if the request exceeds SCAN_TIMEOUT_SECONDS.
    """
    headers = {"Authorization": f"Bearer {token}"}
    files = {"file": (filename, io.BytesIO(content), "application/octet-stream")}
    resp = requests.post(
        f"{API_BASE_URL}/scan",
        headers=headers,
        files=files,
        timeout=SCAN_TIMEOUT_SECONDS,
    )
    if resp.status_code == 401:
        raise PermissionError("TOKEN_INVALID")
    if resp.status_code != 200:
        return None
    return resp.json()
