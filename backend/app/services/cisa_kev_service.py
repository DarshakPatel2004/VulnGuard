# -----------------------------------------------------------
# VulnForge – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# -----------------------------------------------------------

import httpx
from datetime import datetime, timezone
from sqlmodel import Session, select
from ..models import CVE, FetchLog
from ..database import engine

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_cisa_kev() -> dict:
    """
    Download the entire CISA KEV catalog and mark matching CVEs in the DB.
    Returns a summary dict: {'total_kev': N, 'matched': M, 'errors': [...]}
    """
    errors = []
    total_kev = 0
    matched = 0

    try:
        resp = httpx.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        errors.append(str(e))
        return {"total_kev": 0, "matched": 0, "errors": errors}

    vulnerabilities = data.get("vulnerabilities", [])
    total_kev = len(vulnerabilities)

    with Session(engine) as session:
        for item in vulnerabilities:
            cve_id = item.get("cveID", "")
            date_added_str = item.get("dateAdded", "")
            date_added = None
            if date_added_str:
                try:
                    date_added = datetime.strptime(date_added_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                except ValueError:
                    pass

            existing = session.exec(select(CVE).where(CVE.cve_id == cve_id)).first()
            if existing:
                existing.is_kev = True
                existing.kev_date_added = date_added
                session.add(existing)
                matched += 1

        session.commit()

        # Update fetch log
        log = session.exec(select(FetchLog).where(FetchLog.source == "cisa_kev")).first()
        if log:
            log.last_fetched = datetime.now(timezone.utc)
            log.last_run_status = "success" if not errors else "error"
            log.error_message = "; ".join(errors) if errors else None
        else:
            log = FetchLog(
                source="cisa_kev",
                last_fetched=datetime.now(timezone.utc),
                last_run_status="success" if not errors else "error",
                error_message="; ".join(errors) if errors else None,
            )
        session.add(log)
        session.commit()

    return {"total_kev": total_kev, "matched": matched, "errors": errors}

