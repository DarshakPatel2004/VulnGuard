# ═══════════════════════════════════════════════════════════
# VulnForge – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# ═══════════════════════════════════════════════════════════

import time
import httpx
from datetime import datetime, timezone
from sqlmodel import Session, select
from ..models import CVE, FetchLog
from ..database import engine
from ..config import get_config

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = get_config("NVD_API_KEY", "")
RESULTS_PER_PAGE = 2000
# With API key: 50 req/30s = 0.6s between pages. Without: 5 req/30s = 6s.
SLEEP_BETWEEN_REQUESTS = 0.6 if NVD_API_KEY else 6.0


def _headers() -> dict:
    h = {"Accept": "application/json"}
    if NVD_API_KEY:
        h["apiKey"] = NVD_API_KEY
    return h


def _upsert_cve(session: Session, item: dict) -> None:
    """Insert or update a CVE record based on NVD response item."""
    cve_data = item.get("cve", {})
    cve_id = cve_data.get("id", "")
    if not cve_id:
        return

    descriptions = cve_data.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"), ""
    )

    metrics = cve_data.get("metrics", {})
    cvss_v3_score = None
    cvss_v3_severity = None
    cvss_v2_score = None

    for m in metrics.get("cvssMetricV31", []) + metrics.get("cvssMetricV30", []):
        cvss_data = m.get("cvssData", {})
        cvss_v3_score = cvss_data.get("baseScore")
        cvss_v3_severity = cvss_data.get("baseSeverity")
        break

    for m in metrics.get("cvssMetricV2", []):
        cvss_data = m.get("cvssData", {})
        cvss_v2_score = cvss_data.get("baseScore")
        break

    published_str = cve_data.get("published", "")
    last_modified_str = cve_data.get("lastModified", "")

    published = datetime.fromisoformat(published_str.replace("Z", "+00:00")) if published_str else None
    last_modified = datetime.fromisoformat(last_modified_str.replace("Z", "+00:00")) if last_modified_str else None

    import json
    references = json.dumps([r.get("url") for r in cve_data.get("references", [])])
    cpes = json.dumps([
        m.get("criteria", "")
        for config in cve_data.get("configurations", [])
        for node in config.get("nodes", [])
        for m in node.get("cpeMatch", [])
        if m.get("vulnerable")
    ])

    existing = session.exec(select(CVE).where(CVE.cve_id == cve_id)).first()
    if existing:
        existing.description = description
        existing.cvss_v3_score = cvss_v3_score
        existing.cvss_v3_severity = cvss_v3_severity
        existing.cvss_v2_score = cvss_v2_score
        existing.published = published
        existing.last_modified = last_modified
        existing.references = references
        existing.cpes = cpes
        session.add(existing)
    else:
        cve = CVE(
            cve_id=cve_id,
            description=description,
            cvss_v3_score=cvss_v3_score,
            cvss_v3_severity=cvss_v3_severity,
            cvss_v2_score=cvss_v2_score,
            published=published,
            last_modified=last_modified,
            references=references,
            cpes=cpes,
        )
        session.add(cve)


def fetch_nvd(since: datetime | None = None) -> dict:
    """
    Fetch CVEs from NVD. If `since` is provided, only fetch updates since that time.
    Returns a summary dict: {'fetched': N, 'errors': [...]}
    """
    params = {"resultsPerPage": RESULTS_PER_PAGE, "startIndex": 0}
    if since:
        params["lastModStartDate"] = since.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["lastModEndDate"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

    total_fetched = 0
    errors = []

    with Session(engine) as session:
        while True:
            try:
                resp = httpx.get(NVD_BASE_URL, params=params, headers=_headers(), timeout=30)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                errors.append(str(e))
                break

            vulnerabilities = data.get("vulnerabilities", [])
            for i, item in enumerate(vulnerabilities):
                _upsert_cve(session, item)
                
                # Commit every 100 rows to release the SQLite write lock frequently.
                # Otherwise, keeping the write lock for 2000 rows causes "database is locked"
                # errors in the web UI when adding assets.
                if (i + 1) % 100 == 0:
                    session.commit()

            # Final commit for any remainder in the batch
            session.commit()
            total_fetched += len(vulnerabilities)

            total_results = data.get("totalResults", 0)
            params["startIndex"] += len(vulnerabilities)
            if params["startIndex"] >= total_results:
                break

            time.sleep(SLEEP_BETWEEN_REQUESTS)

        # Update fetch log
        log = session.exec(select(FetchLog).where(FetchLog.source == "nvd")).first()
        if log:
            log.last_fetched = datetime.now(timezone.utc)
            log.last_run_status = "success" if not errors else "error"
            log.error_message = "; ".join(errors) if errors else None
        else:
            log = FetchLog(
                source="nvd",
                last_fetched=datetime.now(timezone.utc),
                last_run_status="success" if not errors else "error",
                error_message="; ".join(errors) if errors else None,
            )
        session.add(log)
        session.commit()

    return {"fetched": total_fetched, "errors": errors}

