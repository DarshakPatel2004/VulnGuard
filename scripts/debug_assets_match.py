# -----------------------------------------------------------
# VulnForge – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# -----------------------------------------------------------

import sqlite3
import json
from pathlib import Path

DB_PATH = Path("vuln_tracker.db")

def debug_asset_matching():
    if not DB_PATH.exists():
        print(f"Error: {DB_PATH.resolve()} not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # 1. Get Assets
    print("--- 1. Assets in Database ---")
    assets = cur.execute("SELECT id, name, cpe FROM asset").fetchall()
    for a in assets:
        print(f"ID: {a['id']} | Name: {a['name']} | CPE: {a['cpe']}")

    # 2. Search for any CVE that matches "cisco" and "adaptive"
    print("\n--- 2. Sample Cisco CPEs in CVE Table ---")
    rows = cur.execute("SELECT cve_id, cpes FROM cve WHERE cpes LIKE '%cisco%' AND cpes LIKE '%adaptive%' LIMIT 5").fetchall()
    for r in rows:
        print(f"CVE: {r['cve_id']} | CPEs: {r['cpes'][:200]}...")

    # 3. Search for any CVE that matches "apache" and "log4j"
    print("\n--- 3. Sample Log4j CPEs in CVE Table ---")
    rows = cur.execute("SELECT cve_id, cpes FROM cve WHERE cpes LIKE '%apache%' AND cpes LIKE '%log4j%' LIMIT 5").fetchall()
    for r in rows:
        print(f"CVE: {r['cve_id']} | CPEs: {r['cpes'][:200]}...")

    if assets:
        print("\n--- 4. Simulated Backend Match Test ---")
        for a in assets:
            # This replicates the backend's matching logic
            search_cpe = a['cpe'].rstrip(":*")
            print(f"Asset '{a['name']}' -> Search Pattern: '%{search_cpe}%'")
            
            matches = cur.execute(
                "SELECT cve_id FROM cve WHERE cpes LIKE ?", 
                (f"%{search_cpe}%",)
            ).fetchall()
            
            print(f"MATCH COUNT: {len(matches)}")
            if matches:
                ids = [m['cve_id'] for m in matches[:5]]
                print(f"Sample matches: {ids}")

    conn.close()

if __name__ == "__main__":
    debug_asset_matching()

