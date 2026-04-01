# ═══════════════════════════════════════════════════════════
# VulnTracker – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# ═══════════════════════════════════════════════════════════

import threading
from fastapi import APIRouter, Depends
from datetime import timezone, datetime
from sqlmodel import Session, select
from ..models import FetchLog
from ..database import get_session
from ..auth import verify_credentials
from ..services.nvd_service import fetch_nvd
from ..services.cisa_kev_service import fetch_cisa_kev
from ..services.otx_service import fetch_otx_for_recent_cves
from ..rule_generator import generate_all_rules

router = APIRouter(prefix="/fetch", tags=["fetcher"])


@router.get("/all", summary="Trigger a full sync across all sources")
def trigger_full_sync(
    _user: str = Depends(verify_credentials),
):
    """
    Runs all three sources in parallel threads so CISA KEV + OTX + rules
    complete quickly without being blocked by the long NVD crawl.
    """
    def run_nvd():
        print("[Fetch/all] NVD thread started")
        fetch_nvd(since=None)
        print("[Fetch/all] NVD thread done")

    def run_kev_otx_rules():
        print("[Fetch/all] CISA KEV + OTX + rules thread started")
        fetch_cisa_kev()
        fetch_otx_for_recent_cves(limit=100)
        generate_all_rules()
        print("[Fetch/all] CISA KEV + OTX + rules thread done")

    threading.Thread(target=run_nvd, daemon=True).start()
    threading.Thread(target=run_kev_otx_rules, daemon=True).start()

    return {"status": "Full sync started â€” NVD, CISA KEV, OTX running in parallel"}


@router.get("/nvd", summary="Trigger incremental NVD fetch")
def trigger_nvd(
    full: bool = False,
    _user: str = Depends(verify_credentials),
    session: Session = Depends(get_session),
):
    since = None
    if not full:
        log = session.exec(select(FetchLog).where(FetchLog.source == "nvd")).first()
        since = log.last_fetched if log else None

    # Run in detached thread so it doesn't block shutdown
    threading.Thread(target=fetch_nvd, kwargs={"since": since}, daemon=True).start()
    return {"status": "NVD fetch started", "incremental": not full, "since": since.isoformat() if since else None}


@router.get("/cisa-kev", summary="Trigger CISA KEV sync")
def trigger_kev(
    _user: str = Depends(verify_credentials),
):
    threading.Thread(target=fetch_cisa_kev, daemon=True).start()
    return {"status": "CISA KEV sync started"}


@router.get("/otx", summary="Trigger AlienVault OTX IoC fetch")
def trigger_otx(
    limit: int = 50,
    _user: str = Depends(verify_credentials),
):
    threading.Thread(target=fetch_otx_for_recent_cves, kwargs={"limit": limit}, daemon=True).start()
    return {"status": "OTX fetch started", "limit": limit}


@router.get("/status", summary="Get last fetch status for all sources")
def fetch_status(
    _user: str = Depends(verify_credentials),
    session: Session = Depends(get_session),
):
    logs = session.exec(select(FetchLog)).all()
    return {
        log.source: {
            "last_fetched": log.last_fetched.isoformat() if log.last_fetched else None,
            "status": log.last_run_status,
            "error": log.error_message,
        }
        for log in logs
    }

