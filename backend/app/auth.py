# ═══════════════════════════════════════════════════════════
# VulnForge – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# ═══════════════════════════════════════════════════════════

import os
import secrets
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from .config import get_config

security = HTTPBasic()

BASIC_AUTH_USERNAME = get_config("BASIC_AUTH_USERNAME", "admin")
BASIC_AUTH_PASSWORD = get_config("BASIC_AUTH_PASSWORD", "changeme")


def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    """FastAPI dependency that enforces basic authentication."""
    correct_username = secrets.compare_digest(
        credentials.username.encode("utf8"),
        BASIC_AUTH_USERNAME.encode("utf8")
    )
    correct_password = secrets.compare_digest(
        credentials.password.encode("utf8"),
        BASIC_AUTH_PASSWORD.encode("utf8")
    )
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

