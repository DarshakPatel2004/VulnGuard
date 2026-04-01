import sqlite3
con = sqlite3.connect('vuln_tracker.db')
cur = con.cursor()
rows = cur.execute('SELECT source, last_fetched, last_run_status, error_message FROM fetchlog').fetchall()
for r in rows:
    print(f"Source: {r[0]}, Last Fetched: {r[1]}, Status: {r[2]}, Error: {r[3]}")
con.close()
