# ═══════════════════════════════════════════════════════════
# VulnTracker – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# ═══════════════════════════════════════════════════════════

import sqlite3
import json
from pathlib import Path

DB_PATH = Path("vuln_tracker.db")

def find_correct_cpe_strings():
    if not DB_PATH.exists():
        print(f"Error: {DB_PATH.resolve()} not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Find a valid Cisco ASA CPE
    print("--- 1. Accurate Cisco ASA CPE Lookup ---")
    rows = cur.execute("SELECT cve_id, cpes FROM cve WHERE cpes LIKE '%cisco%' AND cpes LIKE '%adaptive%' LIMIT 1").fetchall()
    for r in rows:
        cpes = json.loads(r['cpes'])
        # Filter for the most relevant ones
        asa_cpes = [c for c in cpes if 'adaptive_security_appliance' in c]
        if asa_cpes:
            print(f"Sample Cisco ASA CPE: {asa_cpes[0]}")

    # Find a valid Apache Log4j CPE
    print("\n--- 2. Accurate Apache Log4j CPE Lookup ---")
    rows = cur.execute("SELECT cve_id, cpes FROM cve WHERE cpes LIKE '%apache%' AND cpes LIKE '%log4j%' LIMIT 1").fetchall()
    for r in rows:
        cpes = json.loads(r['cpes'])
        log4j_cpes = [c for c in cpes if 'log4j' in c]
        if log4j_cpes:
            print(f"Sample Log4j CPE: {log4j_cpes[0]}")

    conn.close()

if __name__ == "__main__":
    find_correct_cpe_strings()

