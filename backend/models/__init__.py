"""
models/__init__.py
------------------
Exports all ORM models so that a single `from backend.models import *`
import is sufficient to register all tables with the shared Base metadata.
"""

from backend.models.scan import Scan
from backend.models.token import Token
from backend.models.user import User
from backend.models.vulnerability import Vulnerability

__all__ = ["User", "Token", "Scan", "Vulnerability"]
