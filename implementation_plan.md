# Overview

The objective is to create a standalone Python automation script (`scripts/auto_fetch_and_generate.py`) independent of the FastAPI backend. This script will query AlienVault OTX for Indicators of Compromise (IoCs) related to Known Exploited Vulnerabilities (KEVs), populate the local SQLite database seamlessly without locking issues, and generate Snort, Sigma, and JSON security rules.

## User Review Required

> [!NOTE]
> The requested `scripts/run_cron.sh` wrapper script implies a Linux/Unix environment (Cron). Since you are on Windows, I will provide the `.sh` script exactly as requested (which can be run via Git Bash or WSL). I will also include brief instructions on how to set this up using Windows Task Scheduler using a `.bat` or PowerShell equivalent, should you prefer a native Windows scheduling approach.

## Proposed Changes

### `scripts/auto_fetch_and_generate.py`
#### [NEW] `scripts/auto_fetch_and_generate.py`
A new standalone automation script that executes the following logic:

1. **Environment Setup & DB Connection**: Load environment variables from `.env`. Establish a raw `sqlite3` connection enabling WAL journal mode and handling proper timeouts.
2. **CLI Argument Parsing**: Use `argparse` to support flags: `--otx-only`, `--rules-only`, `--limit N`, `--dry-run`, and `--json`.
3. **AlienVault OTX Fetching**:
   - Query the top CISA KEV CVEs limited by the `--limit` argument (default to 50), ordered by `cvss_v3_score DESC`.
   - Query the general `/indicators/cve/{cve_id}/general` endpoint to acquire pulse metadata.
   - Sort internal pulses by `indicator_count` descending and take the top 5 pulses per CVE.
   - Implement nested `ThreadPoolExecutor`s (5 workers for CVEs, 8 workers for pulses) to fetch the paginated indicators.
4. **Resilient Database Insertion**: 
   - Batch commits every 500 rows to prevent `database is locked` scenarios.
   - Insert IoCs using raw `sqlite3` `INSERT OR IGNORE` clauses containing proper ISO-8601 formatted UTC datetimes.
   - Update `fetchlog` on completion.
5. **Rules Generation Sub-Routines**:
   - **Snort Rules**: JOIN `ioc` and `cve` tables for IPv4/IPv6 indicators and format into proper Snort `drop` signatures based on CVSS scoring methodology.
   - **Sigma Rules**: Query the top 100 KEV CVEs and wrap them with Sigma-compliant logging formats.
   - **JSON Alerts**: Query top 200 CVEs (CVSS >= 7), enrich with embedded top 10 IoCs and formatting into unified JSON structure.
6. **Summary Report**: Output a final action summary mapping what was skipped, fetched, or written.

---

### `scripts/run_cron.sh`
#### [NEW] `scripts/run_cron.sh`
A shell script designed for an automated task scheduler:
- Evaluates paths relative to script location.
- Activates the virtual environment appropriately.
- Executes `auto_fetch_and_generate.py` without interactive flags.
- Implements comprehensive log management containing rotation logic (preserves only the last 30 log files).

## Open Questions

None at this moment. Please review the plan. If approved, I will begin implementing the standalone python script and cron scripts immediately.

## Verification Plan

### Automated/Manual Verification
1. Manually invoke the scripts via `python scripts/auto_fetch_and_generate.py --limit 10`, then parse its output summary.
2. Check `output_rules/snort.rules`, `sigma.yml`, and `alerts.json` to confirm structural content has populated gracefully.
3. Validate database logs and tables via SQLite queries (or FastAPI frontend if running alongside) for correctness to ensure `ioc` tables populated with no locks.
