# ═══════════════════════════════════════════════════════════
# VulnForge – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# ═══════════════════════════════════════════════════════════

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from dotenv import load_dotenv
from .config import auto_obfuscate
load_dotenv()

# Automatically encode keys on startup if they are in plain-text
auto_obfuscate()

from .database import create_db_and_tables
from .scheduler import start_scheduler, stop_scheduler
from .routers import fetcher, rules, assets, cves
from .auth import verify_credentials
from fastapi import Depends


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start up: create DB tables and start the scheduler."""
    create_db_and_tables()
    start_scheduler()
    yield
    """Shutdown: stop the scheduler cleanly."""
    stop_scheduler()


app = FastAPI(
    title="VulnForge – Precision Threat Intelligence",
    description=(
        "Fetches CVE data from NVD, CISA KEV, and AlienVault OTX. "
        "Generates Snort/Suricata, Sigma, and JSON security rules automatically."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# â”€â”€â”€ CORS (allow the Vite dev server) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# â”€â”€â”€ Routers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.include_router(cves.router)
app.include_router(fetcher.router)
app.include_router(rules.router)
app.include_router(assets.router)


@app.get("/", tags=["health"])
def health_check():
    return {
        "status": "running",
        "service": "VulnForge",
        "docs": "/docs",
    }


@app.get("/auth/verify", tags=["auth"])
def verify_auth(_user: str = Depends(verify_credentials)):
    return {"status": "ok", "user": _user}


# â”€â”€â”€ Serve built front-end in production â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
STATIC_DIR = Path(__file__).parent.parent / "static"
if STATIC_DIR.exists():
    app.mount("/app", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

