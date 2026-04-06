# -----------------------------------------------------------
# VulnForge – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# -----------------------------------------------------------

import sqlite3
import json
from pathlib import Path

DB_PATH = Path("vuln_tracker.db")

def find_canonical_log4j_cpe():
    if not DB_PATH.exists():
        print(f"Error: {DB_PATH.resolve()} not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    print("--- Searching for Log4j CPEs in Database ---")
    # Search for CVE-2021-44228 specifically if possible, or any log4j
    cur.execute("SELECT cve_id, cpes FROM cve WHERE cve_id = ?", ('CVE-2021-44228',))
    row = cur.fetchone()
    
    if not row:
        print("CVE-2021-44228 not found. Searching for any log4j record...")
        cur.execute("SELECT cve_id, cpes FROM cve WHERE cpes LIKE ? LIMIT 5", ('%log4j%',))
        rows = cur.fetchall()
    else:
        rows = [row]

    for r in rows:
        cpes = json.loads(r['cpes'])
        # Print first few CPEs to see format
        print(f"CVE: {r['cve_id']}")
        for c in cpes[:10]:
            print(f"  - {c}")
        if len(cpes) > 10:
            print(f"  ... and {len(cpes)-10} more")

    conn.close()

if __name__ == "__main__":
    find_canonical_log4j_cpe()

