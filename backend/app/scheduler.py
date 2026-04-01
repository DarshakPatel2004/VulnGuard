# ═══════════════════════════════════════════════════════════
# VulnTracker – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# ═══════════════════════════════════════════════════════════

import threading
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime, timezone
from sqlmodel import Session, select
from .database import engine
from .models import FetchLog
from .services.nvd_service import fetch_nvd
from .services.cisa_kev_service import fetch_cisa_kev
from .services.otx_service import fetch_otx_for_recent_cves
from .rule_generator import generate_all_rules

scheduler = BackgroundScheduler(timezone="UTC")


def _get_last_nvd_fetch() -> datetime | None:
    with Session(engine) as session:
        log = session.exec(select(FetchLog).where(FetchLog.source == "nvd")).first()
        return log.last_fetched if log else None


def daily_full_sync():
    """
    Full sync job: NVD runs in its own thread; CISA KEV + OTX + rules
    run in parallel so rules are never blocked waiting for NVD to crawl
    200k+ CVEs. Runs every day at 02:00 AM UTC.
    """
    print(f"[Scheduler] Starting daily full sync at {datetime.now(timezone.utc).isoformat()}")

    def run_nvd():
        result = fetch_nvd(since=None)
        print(f"[Scheduler] NVD fetch done: {result}")

    def run_kev_otx_rules():
        kev = fetch_cisa_kev()
        print(f"[Scheduler] CISA KEV done: {kev}")
        otx = fetch_otx_for_recent_cves(limit=100)
        print(f"[Scheduler] OTX done: {otx}")
        rules = generate_all_rules()
        print(f"[Scheduler] Rules generated: {rules}")

    t1 = threading.Thread(target=run_nvd, daemon=True)
    t2 = threading.Thread(target=run_kev_otx_rules, daemon=True)
    t1.start()
    t2.start()
    t2.join()  # Wait for rules to finish; NVD continues in background
    print(f"[Scheduler] Daily full sync â€” KEV/OTX/rules done. NVD still running.")


def hourly_incremental_sync():
    """
    Incremental sync job: fetch only CVEs modified since last run.
    Runs every hour.
    """
    print(f"[Scheduler] Starting hourly incremental sync at {datetime.now(timezone.utc).isoformat()}")
    last_fetch = _get_last_nvd_fetch()
    nvd_result = fetch_nvd(since=last_fetch)
    print(f"[Scheduler] NVD incremental fetch done: {nvd_result}")
    kev_result = fetch_cisa_kev()
    print(f"[Scheduler] CISA KEV sync done: {kev_result}")
    rule_result = generate_all_rules()
    print(f"[Scheduler] Rules regenerated: {rule_result}")
    print(f"[Scheduler] Hourly sync complete.")


def start_scheduler():
    """Register and start scheduled jobs."""
    scheduler.add_job(
        daily_full_sync,
        trigger=CronTrigger(hour=2, minute=0),
        id="daily_full_sync",
        replace_existing=True,
        name="Daily Full Sync (02:00 AM UTC)",
    )
    scheduler.add_job(
        hourly_incremental_sync,
        trigger=CronTrigger(minute=0),
        id="hourly_incremental",
        replace_existing=True,
        name="Hourly Incremental Sync",
    )
    scheduler.start()
    print("[Scheduler] APScheduler started. Jobs: daily (02:00 UTC) + hourly incremental.")


def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)
        print("[Scheduler] APScheduler stopped.")

