# ═══════════════════════════════════════════════════════════
# VulnTracker – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# ═══════════════════════════════════════════════════════════

import os
import httpx
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from sqlmodel import Session, select
from ..models import CVE, IoC, FetchLog
from ..database import engine

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

# How many CVEs to query OTX for in parallel
OTX_CVE_WORKERS = 5
# How many pulse detail lookups to run in parallel per CVE
OTX_PULSE_WORKERS = 10


def _headers() -> dict:
    return {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}


def _fetch_pulse_indicators(pulse_id: str, pulse_name: str, cve_id: str) -> list[dict]:
    """
    Fetch full indicator list for a single pulse by its ID.
    Uses the paginated /pulses/{id}/indicators endpoint (requires API key).
    """
    iocs = []
    url = f"{OTX_BASE_URL}/pulses/{pulse_id}/indicators"
    while url:
        try:
            resp = httpx.get(url, headers=_headers(), timeout=20)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            break

        for indicator in data.get("results", []):
            ioc_type = indicator.get("type", "")
            value = indicator.get("indicator", "")
            if ioc_type in ("IPv4", "IPv6", "domain", "hostname",
                            "FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256", "URL"):
                iocs.append({
                    "cve_id": cve_id,
                    "ioc_type": ioc_type,
                    "value": value,
                    "pulse_name": pulse_name,
                })

        url = data.get("next")  # paginate if there are more results

    return iocs



def fetch_otx_for_cve(cve_id: str) -> list[dict]:
    """
    Fetch IoCs from AlienVault OTX for a specific CVE.
    Step 1: Get all pulse IDs from the CVE general endpoint.
    Step 2: Fetch each pulse's full indicator list concurrently.
    """
    if not OTX_API_KEY:
        return []

    url = f"{OTX_BASE_URL}/indicators/cve/{cve_id}/general"
    try:
        resp = httpx.get(url, headers=_headers(), timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return []

    # The general endpoint returns summary pulses â€” no indicators embedded
    pulse_summaries = data.get("pulse_info", {}).get("pulses", [])
    if not pulse_summaries:
        pulse_summaries = data.get("pulses", [])

    if not pulse_summaries:
        return []

    # To avoid starvation from giant spam pulses containing only CVEs instead of IPs,
    # we take up to the top 25 pulses.
    pulse_summaries.sort(key=lambda x: x.get("indicator_count", 0) or 0, reverse=True)
    pulse_summaries = pulse_summaries[:25]

    # Fetch each pulse's full indicators concurrently
    all_iocs = []
    with ThreadPoolExecutor(max_workers=OTX_PULSE_WORKERS) as pool:
        futures = {
            pool.submit(
                _fetch_pulse_indicators,
                p.get("id", ""),
                p.get("name", ""),
                cve_id,
            ): p
            for p in pulse_summaries
            if p.get("id")
        }
        for future in as_completed(futures):
            all_iocs.extend(future.result())

    return all_iocs


def _process_single_cve(cve_id: str) -> list[dict]:
    """Wrapper for thread-pool CVE processing."""
    return fetch_otx_for_cve(cve_id)


def fetch_otx_for_recent_cves(limit: int = 50) -> dict:
    """
    Fetch IoCs for actively exploited (CISA KEV) and the most recently published
    CVEs first. Runs OTX CVE lookups concurrently for maximum speed.
    Returns a summary dict.
    """
    total_iocs = 0
    errors = []

    with Session(engine) as session:
        # Prioritize KEV (Known Exploited Vulnerabilities), then newest Criticals
        cves = session.exec(
            select(CVE)
            .order_by(CVE.is_kev.desc(), CVE.published.desc())
            .limit(limit)
        ).all()

        cve_ids = [cve.cve_id for cve in cves]

    if not cve_ids:
        return {"iocs_added": 0, "errors": ["No CVEs in database yet."]}

    # Fetch all CVEs concurrently
    cve_iocs: dict[str, list] = {}
    with ThreadPoolExecutor(max_workers=OTX_CVE_WORKERS) as pool:
        futures = {pool.submit(_process_single_cve, cve_id): cve_id for cve_id in cve_ids}
        for future in as_completed(futures):
            cve_id = futures[future]
            try:
                cve_iocs[cve_id] = future.result()
            except Exception as e:
                errors.append(f"{cve_id}: {e}")
                cve_iocs[cve_id] = []

    # Write all IoCs to DB in a single session rapidly using a bulk approach
    with Session(engine) as session:
        # Pre-fetch existing IoC unique tuples to avoid 1x1 SELECT overhead
        existing_iocs_query = session.exec(select(IoC.cve_id, IoC.value)).all()
        existing_set = set((r[0], r[1]) for r in existing_iocs_query)

        new_iocs = []
        for cve_id, iocs in cve_iocs.items():
            for ioc_data in iocs:
                identifier = (ioc_data["cve_id"], ioc_data["value"])
                if identifier not in existing_set:
                    existing_set.add(identifier)
                    new_iocs.append(IoC(**ioc_data))

        # Batch commits every 500 rows to bypass SQLite write locks
        for i, idx in enumerate(range(0, len(new_iocs), 500)):
            batch = new_iocs[idx:idx+500]
            session.add_all(batch)
            session.commit()
            total_iocs += len(batch)

        # Update fetch log
        log = session.exec(select(FetchLog).where(FetchLog.source == "otx")).first()
        status = "success" if not errors else "partial"
        if log:
            log.last_fetched = datetime.now(timezone.utc)
            log.last_run_status = status
            log.error_message = "; ".join(errors[:5]) if errors else None
        else:
            log = FetchLog(
                source="otx",
                last_fetched=datetime.now(timezone.utc),
                last_run_status=status,
                error_message="; ".join(errors[:5]) if errors else None,
            )
        session.add(log)
        session.commit()

    print(f"[OTX] Done: {total_iocs} new IoCs from {len(cve_ids)} CVEs. Errors: {len(errors)}")
    return {"iocs_added": total_iocs, "cves_queried": len(cve_ids), "errors": errors[:5]}

