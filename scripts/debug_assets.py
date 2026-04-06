# -----------------------------------------------------------
# VulnForge – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# -----------------------------------------------------------

import sqlite3
import json
from pathlib import Path

DB_PATH = Path("vuln_tracker.db")

def find_correct_cpe():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    print("--- 1. Searching for Cisco ASA CVEs manually ---")
    # Search for anything that has cisco and adaptive_security_appliance
    cur.execute("SELECT cve_id, cpes FROM cve WHERE cpes LIKE ? AND cpes LIKE ? LIMIT 5", ('%cisco%', '%adaptive_security%'))
    rows = cur.fetchall()
    if not rows:
        print("No cisco adaptive security appliance matches found in DB with that specific string.")
    for r in rows:
        print(f"CVE: {r['cve_id']} | CPEs: {r['cpes'][:200]}...")

    print("\n--- 2. Searching for Log4j CVEs manually ---")
    cur.execute("SELECT cve_id, cpes FROM cve WHERE cpes LIKE ? AND cpes LIKE ? LIMIT 5", ('%apache%', '%log4j%'))
    rows = cur.fetchall()
    if not rows:
        print("No log4j matches found in DB.")
    for r in rows:
        print(f"CVE: {r['cve_id']} | CPEs: {r['cpes'][:200]}...")

    print("\n--- 3. Checking Assets Currently in DB ---")
    assets = cur.execute("SELECT id, name, cpe FROM asset").fetchall()
    for a in assets:
        print(f"Asset ID: {a['id']} | Name: {a['name']} | Provided CPE: {a['cpe']}")

    conn.close()

if __name__ == "__main__":
    find_correct_cpe()

