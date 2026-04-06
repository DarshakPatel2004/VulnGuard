# -----------------------------------------------------------
# VulnForge – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# -----------------------------------------------------------

import sqlite3
from pathlib import Path

DB_PATH = Path("vuln_tracker.db")

def fix_assets():
    if not DB_PATH.exists():
        print(f"Error: {DB_PATH.resolve()} not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # 1. Fix Log4j Asset (Asset ID 1)
    # Most NVD entries use 'cpe:2.3:a:apache:log4j:2.14.0'
    print("Updating Log4j Asset...")
    cur.execute(
        "UPDATE asset SET cpe = ? WHERE id = ?",
        ("cpe:2.3:a:apache:log4j:2.14.0", 1)
    )

    # 2. Fix Cisco ASA Asset (Asset ID 2) 
    # Must use 'o' instead of 'a' for Operating System
    print("Updating Cisco ASA Asset...")
    cur.execute(
        "UPDATE asset SET cpe = ? WHERE id = ?",
        ("cpe:2.3:o:cisco:adaptive_security_appliance_software:9.6.1", 2)
    )

    conn.commit()
    print(f"Successfully updated {cur.rowcount} asset rows.")
    conn.close()

if __name__ == "__main__":
    fix_assets()

