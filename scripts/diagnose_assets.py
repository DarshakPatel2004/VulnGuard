# ═══════════════════════════════════════════════════════════
# VulnTracker – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# ═══════════════════════════════════════════════════════════

import sqlite3
import json
from pathlib import Path

# Paths relative to the project root
DB_PATH = Path("vuln_tracker.db")

def diagnose():
    if not DB_PATH.exists():
        print(f"Error: {DB_PATH.resolve()} not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    print("--- 1. Assets in Database ---")
    assets = cur.execute("SELECT id, name, cpe FROM asset").fetchall()
    for a in assets:
        print(f"ID: {a['id']} | Name: {a['name']} | CPE: {a['cpe']}")

    print("\n--- 2. Checking for CPE Data in CVE Table ---")
    total_cve = cur.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
    cve_with_cpe = cur.execute("SELECT COUNT(*) FROM cve WHERE cpes IS NOT NULL AND cpes != '[]'").fetchone()[0]
    print(f"Total CVEs in DB: {total_cve}")
    print(f"CVEs with valid CPE strings: {cve_with_cpe}")

    if assets:
        print("\n--- 3. Testing Logic (LIKE matching) ---")
        for a in assets:
            if not a['cpe']:
                print(f"Asset '{a['name']}' has no CPE string.")
                continue
            
            # Cleanly strip trailing wildcards/colons to build the match string
            search_pattern = a['cpe'].rstrip(":*")
            print(f"Testing asset '{a['name']}' using pattern: '%{search_pattern}%'")
            
            # Use raw SQL to confirm what matches
            results = cur.execute(
                "SELECT cve_id FROM cve WHERE cpes LIKE ?", 
                (f"%{search_pattern}%",)
            ).fetchall()
            
            print(f"Found {len(results)} matches.")
            if results:
                sample_ids = [r['cve_id'] for r in results[:5]]
                print(f"Sample matches: {sample_ids}")

    print("\n--- 4. Specific Audit for CVE-2021-44228 (Log4j) ---")
    log4j_cve = cur.execute("SELECT cve_id, cpes FROM cve WHERE cve_id = 'CVE-2021-44228'").fetchone()
    if log4j_cve:
        print(f"CVE Found: {log4j_cve['cve_id']}")
        print(f"Raw CPE column value: {log4j_cve['cpes']}")
    else:
        print("CVE-2021-44228 is missing from your database entirely index!")

    conn.close()

if __name__ == "__main__":
    diagnose()

