# ═══════════════════════════════════════════════════════════
# VulnTracker – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# ═══════════════════════════════════════════════════════════

import os
import time
import httpx
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# Load .env manually to avoid import errors in this standalone script
from dotenv import load_dotenv
load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY", "")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DB_PATH = Path("vuln_tracker.db")

def fetch_specific_metadata(cve_id):
    params = {"cveId": cve_id}
    headers = {"Accept": "application/json"}
    if NVD_API_KEY: headers["apiKey"] = NVD_API_KEY

    try:
        resp = httpx.get(NVD_BASE_URL, params=params, headers=headers, timeout=30)
        if resp.status_code == 200:
            vulnerabilities = resp.json().get("vulnerabilities", [])
            if vulnerabilities:
                return vulnerabilities[0].get("cve", {})
    except Exception as e:
        print(f"Error fetching {cve_id}: {e}")
    return None

def update_kev_data():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Get KEVs with NULL/Empty CPEs
    cur.execute("SELECT cve_id FROM cve WHERE is_kev = 1 AND (cpes IS NULL OR cpes = '[]')")
    missing = [row[0] for row in cur.fetchall()]
    print(f"Found {len(missing)} KEVs missing CPE metadata.")

    for i, cve_id in enumerate(missing[:50]):  # Batch of 50
        print(f"[{i+1}/{len(missing)}] Fetching metadata for {cve_id}...")
        data = fetch_specific_metadata(cve_id)
        if data:
            cpes = json.dumps([
                m.get("criteria", "")
                for config in data.get("configurations", [])
                for node in config.get("nodes", [])
                for m in node.get("cpeMatch", [])
                if m.get("vulnerable")
            ])
            cur.execute("UPDATE cve SET cpes = ? WHERE cve_id = ?", (cpes, cve_id))
            conn.commit()
        
        # Rate limit
        time.sleep(0.6 if NVD_API_KEY else 6.0)

    conn.close()

if __name__ == "__main__":
    update_kev_data()

