# -----------------------------------------------------------
# VulnForge � Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# -----------------------------------------------------------

#!/usr/bin/env python3
"""
auto_fetch_and_generate.py
==========================
Standalone script — no FastAPI, no SQLModel.
Uses raw sqlite3 + python-dotenv.

Usage:
    python scripts/auto_fetch_and_generate.py [options]

Options:
    --otx-only      Only fetch OTX IoCs, skip rule generation
    --rules-only    Only generate rules (skip OTX fetch)
    --limit N       Number of KEV CVEs to query (default: 50)
    --dry-run       Simulate without writing to DB or files
    --json          Output final summary as JSON instead of table
"""

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# ── Try to load .env from parent dir (project root) ──────────────────────────
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent / ".env"
    load_dotenv(dotenv_path=env_path)
except ImportError:
    pass  # python-dotenv not installed; rely on environment variables

try:
    import httpx
except ImportError:
    print("[ERROR] httpx is not installed. Run: pip install httpx")
    sys.exit(1)

# ── Constants ─────────────────────────────────────────────────────────────────

OTX_BASE_URL    = "https://otx.alienvault.com/api/v1"
OTX_API_KEY     = os.getenv("OTX_API_KEY", "")
OTX_CVE_WORKERS = 5
OTX_PULSE_WORKERS = 8
BATCH_SIZE      = 500
ALLOWED_TYPES   = {"IPv4", "IPv6", "domain", "hostname",
                   "FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256", "URL"}

# DB & output paths relative to the script's parent (project root)
PROJECT_ROOT = Path(__file__).parent.parent
DB_PATH      = PROJECT_ROOT / "vuln_tracker.db"
OUTPUT_DIR   = PROJECT_ROOT / "output_rules"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ── Logging helpers ───────────────────────────────────────────────────────────

def log(msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def log_section(title: str) -> None:
    print(f"\n{'='*60}", flush=True)
    log(f"  {title}")
    print(f"{'='*60}", flush=True)


# ── Database helpers ──────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    """Open a WAL-mode SQLite connection."""
    con = sqlite3.connect(str(DB_PATH), timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def verify_db() -> dict:
    """Check current DB state and return counts."""
    con = get_db()
    cur = con.cursor()
    ioc_count  = cur.execute("SELECT COUNT(*) FROM ioc").fetchone()[0]
    cve_count  = cur.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
    kev_count  = cur.execute("SELECT COUNT(*) FROM cve WHERE is_kev=1").fetchone()[0]
    con.close()
    return {"ioc_count": ioc_count, "cve_count": cve_count, "kev_count": kev_count}


# ── OTX Fetch ─────────────────────────────────────────────────────────────────

def _otx_headers() -> dict:
    return {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}


def _fetch_pulse_indicators(pulse_id: str, pulse_name: str, cve_id: str) -> list[dict]:
    """Fetch all paginated indicators for a single pulse."""
    iocs: list[dict] = []
    url = f"{OTX_BASE_URL}/pulses/{pulse_id}/indicators"
    page_count = 0

    while url:
        try:
            resp = httpx.get(url, headers=_otx_headers(), timeout=25)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            log(f"  [WARN] Pulse {pulse_id} page {page_count+1} error: {exc}")
            break

        for indicator in data.get("results", []):
            ioc_type = indicator.get("type", "")
            value    = indicator.get("indicator", "")
            if ioc_type in ALLOWED_TYPES and value:
                iocs.append({
                    "cve_id":     cve_id,
                    "ioc_type":   ioc_type,
                    "value":      value,
                    "pulse_name": pulse_name[:200] if pulse_name else "",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                })

        url = data.get("next")  # None when last page
        page_count += 1

    return iocs


def fetch_otx_for_cve(cve_id: str, top_pulses: int = 5) -> list[dict]:
    """Fetch IoCs from OTX for a single CVE ID."""
    if not OTX_API_KEY:
        return []

    url = f"{OTX_BASE_URL}/indicators/cve/{cve_id}/general"
    try:
        resp = httpx.get(url, headers=_otx_headers(), timeout=25)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        log(f"  [WARN] CVE {cve_id} general endpoint error: {exc}")
        return []

    pulse_summaries = data.get("pulse_info", {}).get("pulses", [])
    if not pulse_summaries:
        pulse_summaries = data.get("pulses", [])

    if not pulse_summaries:
        return []

    # Sort by indicator_count desc, take top N
    pulse_summaries.sort(key=lambda x: x.get("indicator_count", 0) or 0, reverse=True)
    pulse_summaries = pulse_summaries[:top_pulses]

    all_iocs: list[dict] = []
    with ThreadPoolExecutor(max_workers=OTX_PULSE_WORKERS) as pool:
        futures = {
            pool.submit(
                _fetch_pulse_indicators,
                p.get("id", ""),
                p.get("name", ""),
                cve_id,
            ): p
            for p in pulse_summaries
            if p.get("id")
        }
        for future in as_completed(futures):
            try:
                all_iocs.extend(future.result())
            except Exception as exc:
                log(f"  [WARN] Pulse future error: {exc}")

    return all_iocs


def fetch_otx_iocs(limit: int = 50, dry_run: bool = False) -> dict:
    """
    Main OTX fetch routine.
    Returns summary: {iocs_added, cves_queried, errors}
    """
    log_section(f"Fetching OTX IoCs (limit={limit}, dry_run={dry_run})")

    if not OTX_API_KEY:
        log("[ERROR] OTX_API_KEY is not set. Aborting.")
        return {"iocs_added": 0, "cves_queried": 0, "errors": ["No OTX_API_KEY"]}

    # ── 1. Load target CVEs from DB ──────────────────────────────────────────
    con = get_db()
    cur = con.cursor()
    rows = cur.execute(
        """SELECT cve_id FROM cve
           WHERE is_kev = 1
           ORDER BY cvss_v3_score DESC
           LIMIT ?""",
        (limit,)
    ).fetchall()
    cve_ids = [r["cve_id"] for r in rows]
    con.close()

    if not cve_ids:
        log("[ERROR] No KEV CVEs found in DB.")
        return {"iocs_added": 0, "cves_queried": 0, "errors": ["No KEV CVEs"]}

    log(f"Targeting {len(cve_ids)} KEV CVEs (top by CVSS score)")
    log(f"Sample: {cve_ids[:5]}")

    # ── 2. Concurrent OTX fetch ───────────────────────────────────────────────
    cve_iocs: dict[str, list] = {}
    errors: list[str] = []
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=OTX_CVE_WORKERS) as pool:
        futures = {pool.submit(fetch_otx_for_cve, cve_id): cve_id for cve_id in cve_ids}
        done_count = 0
        for future in as_completed(futures):
            cve_id = futures[future]
            try:
                result = future.result()
                cve_iocs[cve_id] = result
            except Exception as exc:
                errors.append(f"{cve_id}: {exc}")
                cve_iocs[cve_id] = []
            done_count += 1
            log(f"  [{done_count}/{len(cve_ids)}] {cve_id}: {len(cve_iocs[cve_id])} IoCs")

    elapsed = time.time() - start_time
    all_collected = sum(len(v) for v in cve_iocs.values())
    log(f"Collected {all_collected} raw IoCs in {elapsed:.1f}s from {len(cve_ids)} CVEs")

    if dry_run:
        log("[DRY-RUN] Skipping DB insert.")
        return {"iocs_added": all_collected, "cves_queried": len(cve_ids), "errors": errors[:5]}

    # ── 3. Dedup and insert into DB ───────────────────────────────────────────
    log("Inserting IoCs into database (batch mode, INSERT OR IGNORE)...")
    con = get_db()
    cur = con.cursor()

    total_iocs = 0
    batch: list[tuple] = []

    # Flatten all collected IoCs
    flat_iocs: list[dict] = []
    for cve_id, iocs in cve_iocs.items():
        flat_iocs.extend(iocs)

    for ioc in flat_iocs:
        batch.append((
            ioc["cve_id"],
            ioc["ioc_type"],
            ioc["value"],
            ioc.get("pulse_name", ""),
            ioc["created_at"],
        ))

        if len(batch) >= BATCH_SIZE:
            cur.executemany(
                """INSERT OR IGNORE INTO ioc (cve_id, ioc_type, value, pulse_name, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                batch
            )
            con.commit()
            total_iocs += cur.rowcount
            log(f"  Committed batch of {BATCH_SIZE} (inserted: {cur.rowcount})")
            batch = []

    # Final partial batch
    if batch:
        cur.executemany(
            """INSERT OR IGNORE INTO ioc (cve_id, ioc_type, value, pulse_name, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            batch
        )
        con.commit()
        total_iocs += cur.rowcount
        log(f"  Committed final batch of {len(batch)} (inserted: {cur.rowcount})")

    # ── 4. Update fetchlog ────────────────────────────────────────────────────
    status = "success" if not errors else "partial"
    now_iso = datetime.now(timezone.utc).isoformat()
    err_msg = "; ".join(errors[:5]) if errors else None

    existing = cur.execute("SELECT id FROM fetchlog WHERE source='otx'").fetchone()
    if existing:
        cur.execute(
            """UPDATE fetchlog SET last_fetched=?, last_run_status=?, error_message=?
               WHERE source='otx'""",
            (now_iso, status, err_msg)
        )
    else:
        cur.execute(
            """INSERT INTO fetchlog (source, last_fetched, last_run_status, error_message)
               VALUES ('otx', ?, ?, ?)""",
            (now_iso, status, err_msg)
        )
    con.commit()
    con.close()

    log(f"Done: {total_iocs} new IoCs inserted. Status: {status}. Errors: {len(errors)}")
    return {"iocs_added": total_iocs, "cves_queried": len(cve_ids), "errors": errors[:5]}


# ── Rule Generation ───────────────────────────────────────────────────────────

def _snort_sid(ip: str) -> int:
    return int(hashlib.md5(ip.encode()).hexdigest(), 16) % 9_999_999


def generate_snort_rules(dry_run: bool = False) -> int:
    """Generate Snort/Suricata drop rules from IPv4/IPv6 IoCs. Returns rule count."""
    log_section("Generating Snort/Suricata Rules")

    con = get_db()
    cur = con.cursor()

    rows = cur.execute(
        """SELECT i.value, i.ioc_type, i.pulse_name,
                  c.cve_id, c.cvss_v3_score
           FROM ioc i
           JOIN cve c ON c.cve_id = i.cve_id
           WHERE i.ioc_type IN ('IPv4', 'IPv6')
           ORDER BY c.cvss_v3_score DESC, c.cve_id ASC"""
    ).fetchall()
    con.close()

    lines = [
        "# Snort/Suricata rules generated by Vulnerability Tracker",
        f"# Generated at: {datetime.now(timezone.utc).isoformat()}",
        f"# Source: AlienVault OTX / NVD",
        f"# Total rules: {len(rows)}",
        "",
    ]
    
    current_cve = None

    for row in rows:
        ip         = row["value"]
        cve_id     = row["cve_id"]
        
        if cve_id != current_cve:
            if current_cve is not None:
                lines.append("")
            lines.append(f"# {'='*76}")
            lines.append(f"# {cve_id}")
            lines.append(f"# {'='*76}")
            current_cve = cve_id

        score      = row["cvss_v3_score"] or 0
        pulse_name = (row["pulse_name"] or "")[:40]
        priority   = "1" if score >= 9 else "2" if score >= 7 else "3"
        sid        = _snort_sid(ip)
        msg        = f"Malicious IP associated with {cve_id}"
        if pulse_name:
            msg += f" [{pulse_name}]"

        rule = (
            f'drop ip {ip} any -> $HOME_NET any '
            f'(msg:"{msg}"; '
            f'reference:url,nvd.nist.gov/vuln/detail/{cve_id}; '
            f'classtype:trojan-activity; sid:{sid}; '
            f'priority:{priority}; rev:1;)'
        )
        lines.append(rule)

    if not rows:
        lines.append("# No IPv4/IPv6 IoCs available yet. Run OTX fetch first.")

    content = "\n".join(lines)
    log(f"Generated {len(rows)} Snort rules")

    if not dry_run:
        out_path = OUTPUT_DIR / "snort.rules"
        out_path.write_text(content, encoding="utf-8")
        log(f"Written to {out_path}")

    return len(rows)


def generate_sigma_rules(dry_run: bool = False) -> int:
    """Generate Sigma YAML rules for top 100 KEV CVEs. Returns rule count."""
    log_section("Generating Sigma YAML Rules")

    con = get_db()
    cur = con.cursor()

    rows = cur.execute(
        """SELECT cve_id, cvss_v3_score, cvss_v3_severity, description
           FROM cve
           WHERE is_kev = 1
           ORDER BY cvss_v3_score DESC
           LIMIT 100"""
    ).fetchall()
    con.close()

    rule_parts: list[str] = [
        "# Sigma rules generated by Vulnerability Tracker",
        f"# Generated at: {datetime.now(timezone.utc).isoformat()}",
        f"# Total rules: {len(rows)}",
        "",
    ]

    for row in rows:
        cve_id   = row["cve_id"]
        score    = row["cvss_v3_score"] or 0
        desc     = (row["description"] or "")[:300]
        level    = "critical" if score >= 9 else "high"
        rule_id  = f"vuln-tracker-{cve_id.lower().replace('-', '_')}"

        # Build YAML manually (no PyYAML dependency needed for this structure)
        yaml_block = f"""---
title: 'Exploitation attempt for {cve_id}'
id: '{rule_id}'
status: experimental
description: '{desc.replace("'", "''")}'
references:
  - 'https://nvd.nist.gov/vuln/detail/{cve_id}'
tags:
  - attack.initial_access
  - 'cve.{cve_id.lower()}'
logsource:
  category: network
  product: firewall
detection:
  keywords:
    - '{cve_id}'
  condition: keywords
level: {level}"""
        rule_parts.append(yaml_block)

    content = "\n".join(rule_parts)
    log(f"Generated {len(rows)} Sigma rules")

    if not dry_run:
        out_path = OUTPUT_DIR / "sigma.yml"
        out_path.write_text(content, encoding="utf-8")
        log(f"Written to {out_path}")

    return len(rows)


def generate_json_alerts(dry_run: bool = False) -> int:
    """Generate JSON alert feed for top 200 CVEs with CVSS >= 7. Returns alert count."""
    log_section("Generating JSON Alerts")

    con = get_db()
    cur = con.cursor()

    cve_rows = cur.execute(
        """SELECT cve_id, cvss_v3_score, cvss_v3_severity, is_kev, description, published
           FROM cve
           WHERE cvss_v3_score >= 7
           ORDER BY cvss_v3_score DESC
           LIMIT 200"""
    ).fetchall()

    alerts = []
    generated_at = datetime.now(timezone.utc).isoformat()

    for row in cve_rows:
        cve_id = row["cve_id"]
        ioc_rows = cur.execute(
            """SELECT ioc_type, value FROM ioc
               WHERE cve_id = ?
               LIMIT 10""",
            (cve_id,)
        ).fetchall()
        ioc_count_row = cur.execute(
            "SELECT COUNT(*) as cnt FROM ioc WHERE cve_id = ?", (cve_id,)
        ).fetchone()

        alerts.append({
            "cve_id":      cve_id,
            "severity":    row["cvss_v3_severity"],
            "cvss_score":  row["cvss_v3_score"],
            "is_kev":      bool(row["is_kev"]),
            "description": (row["description"] or "")[:300],
            "published":   row["published"],
            "ioc_count":   ioc_count_row["cnt"] if ioc_count_row else 0,
            "iocs":        [{"type": r["ioc_type"], "value": r["value"]} for r in ioc_rows],
            "nvd_url":     f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "generated_at": generated_at,
        })

    con.close()

    payload = {"alerts": alerts, "count": len(alerts), "generated_at": generated_at}
    content = json.dumps(payload, indent=2)
    log(f"Generated {len(alerts)} JSON alerts")

    if not dry_run:
        out_path = OUTPUT_DIR / "alerts.json"
        out_path.write_text(content, encoding="utf-8")
        log(f"Written to {out_path}")

    return len(alerts)


def generate_all_rules(dry_run: bool = False) -> dict:
    snort_count = generate_snort_rules(dry_run=dry_run)
    sigma_count = generate_sigma_rules(dry_run=dry_run)
    alert_count = generate_json_alerts(dry_run=dry_run)
    return {
        "snort_rules":  snort_count,
        "sigma_rules":  sigma_count,
        "json_alerts":  alert_count,
    }


# ── Summary Table ─────────────────────────────────────────────────────────────

def print_summary_table(stats: dict) -> None:
    print("\n" + "="*60)
    print("  FINAL SUMMARY")
    print("="*60)
    rows = [
        ("Total CVEs in DB",      stats.get("cve_count",     "—")),
        ("KEV CVEs in DB",        stats.get("kev_count",     "—")),
        ("CVEs Queried (OTX)",    stats.get("cves_queried",  "—")),
        ("IoCs Added",            stats.get("iocs_added",    "—")),
        ("Total IoCs in DB",      stats.get("ioc_count_after", "—")),
        ("Snort Rules Generated", stats.get("snort_rules",   "—")),
        ("Sigma Rules Generated", stats.get("sigma_rules",   "—")),
        ("JSON Alerts Generated", stats.get("json_alerts",   "—")),
        ("OTX Errors",            stats.get("otx_errors",    "—")),
    ]
    for label, val in rows:
        print(f"  {label:<30} {val}")
    print("="*60)
    print(f"  Output directory: {OUTPUT_DIR.resolve()}")
    print("="*60 + "\n")


# ── CLI Entry Point ───────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch OTX IoCs and generate security rules for the Vulnerability Tracker."
    )
    parser.add_argument("--otx-only",   action="store_true", help="Only fetch OTX IoCs")
    parser.add_argument("--rules-only", action="store_true", help="Only generate rules")
    parser.add_argument("--limit",      type=int, default=50, metavar="N",
                        help="Number of KEV CVEs to target (default: 50)")
    parser.add_argument("--dry-run",    action="store_true",
                        help="Simulate without writing to DB or output files")
    parser.add_argument("--json",       action="store_true",
                        help="Output final summary as JSON")
    args = parser.parse_args()

    log_section("Vulnerability Tracker — OTX Fetch & Rule Generation")
    log(f"DB path:      {DB_PATH}")
    log(f"Output dir:   {OUTPUT_DIR}")
    log(f"OTX API key:  {'SET (' + OTX_API_KEY[:8] + '...)' if OTX_API_KEY else 'NOT SET'}")
    log(f"Dry-run:      {args.dry_run}")

    # ── Step 1: Verify DB state ───────────────────────────────────────────────
    initial_state = verify_db()
    log(f"Initial state → CVEs: {initial_state['cve_count']}, "
        f"KEV: {initial_state['kev_count']}, IoCs: {initial_state['ioc_count']}")

    stats: dict = {**initial_state}
    otx_result: dict = {}
    rule_result: dict = {}

    # ── Step 2: Fetch OTX IoCs ────────────────────────────────────────────────
    if not args.rules_only:
        otx_result = fetch_otx_iocs(limit=args.limit, dry_run=args.dry_run)
        stats["iocs_added"]   = otx_result.get("iocs_added", 0)
        stats["cves_queried"] = otx_result.get("cves_queried", 0)
        stats["otx_errors"]   = len(otx_result.get("errors", []))
        if otx_result.get("errors"):
            log(f"[WARN] OTX errors: {otx_result['errors']}")

    # ── Step 3: Generate Rules ────────────────────────────────────────────────
    if not args.otx_only:
        rule_result = generate_all_rules(dry_run=args.dry_run)
        stats.update(rule_result)

    # ── Final DB state ────────────────────────────────────────────────────────
    final_state = verify_db()
    stats["ioc_count_after"] = final_state["ioc_count"]

    # ── Output ────────────────────────────────────────────────────────────────
    if args.json:
        print(json.dumps(stats, indent=2))
    else:
        print_summary_table(stats)


if __name__ == "__main__":
    main()

