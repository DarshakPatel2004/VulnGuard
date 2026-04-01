import sqlite3
import os

db_path = 'vuln_tracker.db'
if not os.path.exists(db_path):
    print(f"Error: {db_path} not found")
    exit(1)

con = sqlite3.connect(db_path)
cur = con.cursor()
try:
    rows = cur.execute('SELECT source, last_fetched, last_run_status, error_message FROM fetchlog').fetchall()
    print("--- Database Fetch Status ---")
    for r in rows:
        print(f"Source: {r[0]:10} | Status: {r[2]:10} | Last Fetched: {r[1]}")
        if r[3]:
            print(f"  Error: {r[3][:100]}...")
except Exception as e:
    print(f"Error querying database: {e}")
finally:
    con.close()
print("----------------------------")
