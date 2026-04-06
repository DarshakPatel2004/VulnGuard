# -----------------------------------------------------------
# VulnForge – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# -----------------------------------------------------------

import sqlite3
import json
from pathlib import Path

DB_PATH = Path("vuln_tracker.db")

def inspect_log4j():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    print("--- 1. Checking Log4Shell CPEs ---")
    cur.execute("SELECT cve_id, cpes FROM cve WHERE cve_id = 'CVE-2021-44228'")
    row = cur.fetchone()
    if row:
        print(f"CVE: {row['cve_id']}")
        print(f"CPEs: {row['cpes']}")
    else:
        print("CVE-2021-44228 not found!")

    print("\n--- 2. Checking Assets ---")
    cur.execute("SELECT id, name, cpe FROM asset")
    assets = cur.fetchall()
    for a in assets:
        print(f"ID: {a['id']} | Name: {a['name']} | CPE: {a['cpe']}")

    conn.close()

if __name__ == "__main__":
    inspect_log4j()

