# -----------------------------------------------------------
# VulnForge – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# -----------------------------------------------------------

import os
import time
import httpx
import json
from datetime import datetime, timezone
from sqlmodel import Session, select
from backend.app.models import CVE
from backend.app.database import engine

NVD_API_KEY = os.getenv("NVD_API_KEY", "")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_specific_cve_metadata(cve_id: str):
    """Fetch full metadata (including CPEs) for a single CVE from NVD."""
    params = {"cveId": cve_id}
    headers = {"Accept": "application/json"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        resp = httpx.get(NVD_BASE_URL, params=params, headers=headers, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if vulnerabilities:
                return vulnerabilities[0]
    except Exception as e:
        print(f"Error fetching {cve_id}: {e}")
    return None

def update_kves_metadata():
    """Populate CPEs for top KEVs that are currently missing them."""
    with Session(engine) as session:
        # Get KEVs that have no CPEs populated
        missing_cpes = session.exec(
            select(CVE).where(CVE.is_kev == True).where(CVE.cpes == None)
        ).all()
        
        print(f"Found {len(missing_cpes)} KEVs missing CPE metadata.")
        
        for i, cve in enumerate(missing_cpes[:50]): # Limit to first 50 to be fast
            print(f"[{i+1}/{len(missing_cpes)}] Updating {cve.cve_id}...")
            item = fetch_specific_cve_metadata(cve.cve_id)
            if item:
                cve_data = item.get("cve", {})
                cpes = json.dumps([
                    m.get("criteria", "")
                    for config in cve_data.get("configurations", [])
                    for node in config.get("nodes", [])
                    for m in node.get("cpeMatch", [])
                    if m.get("vulnerable")
                ])
                cve.cpes = cpes
                session.add(cve)
                session.commit()
            
            # Simple rate limiting for NVD
            time.sleep(0.6 if NVD_API_KEY else 6.0)

if __name__ == "__main__":
    update_kves_metadata()

