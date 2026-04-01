# ═══════════════════════════════════════════════════════════
# VulnTracker – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# ═══════════════════════════════════════════════════════════

import sqlite3
import json
from pathlib import Path

DB_PATH = Path("vuln_tracker.db")

def check_matches():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # 1. Search for any CPE that mentions "cisco" and "adaptive"
    print("--- 1. Searching for Cisco ASA CVEs manually ---")
    cur.execute("SELECT cve_id, cpes FROM cve WHERE cpes LIKE '%cisco%' AND cpes LIKE '%adaptive%' LIMIT 3")
    rows = cur.fetchall()
    for r in rows:
        print(f"CVE: {r['cve_id']} | CPEs: {r['cpes'][:200]}...")

    # 2. Check for Log4j 2.14.0 specifically in any CPE
    print("\n--- 2. Searching for Log4j 2.14.0 CVEs manually ---")
    cur.execute("SELECT cve_id, cpes FROM cve WHERE cpes LIKE '%apache%' AND cpes LIKE '%log4j%' AND cpes LIKE '%2.14.0%' LIMIT 3")
    rows = cur.fetchall()
    for r in rows:
        print(f"CVE: {r['cve_id']} | CPEs: {r['cpes'][:200]}...")

    # 3. List actual asset CPE vs a matching CVE CPE if found
    assets = cur.execute("SELECT * FROM asset").fetchall()
    for a in assets:
        print(f"\nAsset: {a['name']}")
        print(f"CPE String: {a['cpe']}")
        search_pattern = a['cpe'].rstrip(":*")
        print(f"Pattern: {search_pattern}")

    conn.close()

if __name__ == "__main__":
    check_matches()

