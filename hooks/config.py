"""
hooks/config.py
---------------
Central configuration for the CloudSentinel pre-commit security guardrail.
All tuneable parameters live here.
"""

import os
from pathlib import Path

# ── API ──────────────────────────────────────────────────────────────────────
API_BASE_URL: str = os.getenv("CLOUDSENTINEL_URL", "http://localhost:8000")
SCAN_TIMEOUT_SECONDS: int = 30

# ── Auth ─────────────────────────────────────────────────────────────────────
# Stored at repo root so it is gitignored but accessible to the hook.
TOKEN_FILE: Path = Path(__file__).resolve().parent.parent / ".cloudsentinel_token"

# ── Enforcement ───────────────────────────────────────────────────────────────
# Severity scores >= this threshold will block the commit.
# (8 = Critical tier in the 1-10 CloudSentinel scale)
BLOCK_ON_SEVERITY: int = 8

# ── File Detection ────────────────────────────────────────────────────────────
IAC_EXTENSIONS: tuple = (".tf", ".yaml", ".yml", ".json", ".template")
IAC_EXCLUDE_PATTERNS: tuple = (
    "requirements",
    ".pre-commit-config",
    "package.json",
    "package-lock.json",
)
