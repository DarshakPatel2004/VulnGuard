# ═══════════════════════════════════════════════════════════
# VulnTracker – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# ═══════════════════════════════════════════════════════════

import os
import secrets
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from dotenv import load_dotenv

load_dotenv()

security = HTTPBasic()

BASIC_AUTH_USERNAME = os.getenv("BASIC_AUTH_USERNAME", "admin")
BASIC_AUTH_PASSWORD = os.getenv("BASIC_AUTH_PASSWORD", "changeme")


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

