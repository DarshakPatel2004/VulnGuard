# -----------------------------------------------------------
# VulnForge – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# -----------------------------------------------------------

import sqlite3
import json
from pathlib import Path

DB_PATH = Path("vuln_tracker.db")

def check_matches():
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

    # 2. Check for Log4Shell Metadata
    print("\n--- 2. Checking CVE-2021-44228 CPE Data ---")
    l4j = cur.execute("SELECT cve_id, cpes FROM cve WHERE cve_id = 'CVE-2021-44228'").fetchone()
    if l4j:
        print(f"CVE Found: {l4j['cve_id']}")
        print(f"Stored CPEs: {l4j['cpes']}")
    else:
        print("CVE-2021-44228 not found in database!")

    # 3. Simulate matching logic for asset 1 (Log4j)
    if assets:
        print("\n--- 3. Simulating Matching Logic ---")
        for a in assets:
            search_cpe = a['cpe'].rstrip(":*")
            print(f"Asset '{a['name']}' -> Searching for pattern: '%{search_cpe}%'")
            
            matches = cur.execute(
                "SELECT cve_id FROM cve WHERE cpes LIKE ?", 
                (f"%{search_cpe}%",)
            ).fetchall()
            
            print(f"SQL MATCH COUNT: {len(matches)}")
            if matches:
                sample = [m['cve_id'] for m in matches[:5]]
                print(f"Sample matches: {sample}")
            else:
                # If no matches, check if we have ANY CPEs in the db for comparison
                total_with_cpe = cur.execute("SELECT COUNT(*) FROM cve WHERE cpes IS NOT NULL AND cpes != '[]'").fetchone()[0]
                print(f"Total CVEs in DB with non-empty CPE lists: {total_with_cpe}")
    
    conn.close()

if __name__ == "__main__":
    check_matches()

