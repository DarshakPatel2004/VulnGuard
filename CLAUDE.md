# Vulnerability Tracker

A self-hosted threat intelligence platform that automatically fetches vulnerability data from multiple sources (NVD, CISA KEV, AlienVault OTX), stores it locally in SQLite, and generates actionable security rules (Snort/Suricata, Sigma, JSON) for network protection.

## Commands

### Running the Application

```bash
# Terminal 1 - Backend (from project root)
.\venv\Scripts\python -m uvicorn backend.app.main:app --reload --port 8000

# Terminal 2 - Frontend (from frontend directory)
cd frontend && npm run dev
```

### Standalone Script

```bash
# Full OTX fetch + rule generation
.\venv\Scripts\python scripts\auto_fetch_and_generate.py

# Options
.\venv\Scripts\python scripts\auto_fetch_and_generate.py --otx-only
.\venv\Scripts\python scripts\auto_fetch_and_generate.py --rules-only
.\venv\Scripts\python scripts\auto_fetch_and_generate.py --limit 100
.\venv\Scripts\python scripts\auto_fetch_and_generate.py --dry-run
.\venv\Scripts\python scripts\auto_fetch_and_generate.py --json
```

### Debug Scripts (available in `scripts/`)

| Script | Purpose |
|--------|---------|
| `diagnose_assets.py` | Asset troubleshooting |
| `update_kev_metadata.py` | Sync CISA KEV data |
| `debug_matches.py`, `debug_matches_v2.py` | CPE matching debug |
| `debug_assets.py`, `debug_assets_match.py` | Asset validation |
| `find_correct_cpes.py` | CPE discovery |
| `fix_asset_cpes.py` | CPE correction |
| `final_data_sync.py` | Bulk data sync |
| `inspect_data.py` | Database inspection |
| `find_log4j_format.py` | Specific CVE pattern search |

## Architecture Overview

### Backend Structure (`backend/app/`)

```
backend/app/
├── main.py              # FastAPI app, CORS, lifespan (DB + scheduler)
├── models.py            # SQLModel schemas: CVE, IoC, Asset, FetchLog, GeneratedRule
├── database.py          # SQLite engine with WAL mode, get_session()
├── auth.py              # HTTP Basic Auth via verify_credentials()
├── scheduler.py         # APScheduler: daily 02:00 UTC full sync, hourly incremental
├── rule_generator.py    # Generates Snort, Sigma, JSON rules from DB
├── routers/
│   ├── cves.py          # GET /cves, /cves/{id}, /cves/stats
│   ├── fetcher.py       # GET /fetch/{all|nvd|cisa-kev|otx|status}
│   ├── rules.py         # GET /rules/{snort|sigma|json}[/download]
│   └── assets.py        # CRUD + /assets/{id}/cves (CPE matching)
└── services/
    ├── nvd_service.py       # NVD API 2.0 fetcher (paginated, rate-limited)
    ├── cisa_kev_service.py  # CISA KEV catalog fetcher
    └── otx_service.py       # AlienVault OTX IoC fetcher (concurrent)
```

### Data Flow

1. **Scheduled/Manual Sync** → `scheduler.py` or `/fetch/all` endpoint
2. **Parallel Fetch**:
   - Thread 1: `fetch_nvd()` - CVEs from NVD (slow, rate-limited)
   - Thread 2: `fetch_cisa_kev()` + `fetch_otx_for_recent_cves()` + `generate_all_rules()`
3. **Data Storage**: SQLite `vuln_tracker.db` (WAL mode for concurrency)
4. **Rule Generation**: `rule_generator.py` queries DB, writes to `output_rules/`

### Database Schema

| Table | Purpose |
|-------|---------|
| `cve` | CVE records (CVSS scores, CPEs, references, KEV flag) |
| `ioc` | Indicators of Compromise (IP, domain, hash) linked to CVE |
| `asset` | User-tracked devices with CPE for vulnerability matching |
| `fetchlog` | Last successful fetch timestamp per source (nvd, cisa_kev, otx) |
| `generated_rule` | Cached security rules |

### Key Design Decisions

- **Parallel sync threads**: NVD runs separately from KEV/OTX/rules to avoid blocking rule generation on the slow NVD crawl (200k+ CVEs)
- **SQLite WAL mode**: Enables concurrent reads while scheduler writes (configured in `database.py` with `PRAGMA journal_mode=WAL`)
- **Batch commits**: NVD service commits every 100 rows; OTX script every 500 rows to release write locks
- **Rate limiting**: NVD uses 0.6s delay (with API key) or 6s (without); OTX uses ThreadPoolExecutor (5 CVE workers, 8-10 pulse workers)
- **CPE matching**: `assets.py` parses CPE 2.3 format (`cpe:2.3:part:vendor:product:version:...`) and matches wildcards across 8 components

### Frontend Structure (`frontend/src/`)

- `main.jsx` - React entry point
- `App.jsx` - Main router with 4 pages (Dashboard, CVE Database, Security Rules, Asset Inventory), handles auth state
- `api.js` - HTTP client with sessionStorage-based Basic Auth
- `components/`:
  - `Login.jsx` - Auth form with credential verification
  - `Dashboard.jsx` - Stats cards, severity charts, manual sync, recent CVE table
  - `CveList.jsx` - CVE browser with search, severity filter, KEV toggle, pagination
  - `AssetTable.jsx` - Asset CRUD with CPE input, matches modal showing CVEs for selected asset
  - `RuleList.jsx` - Tabbed view for Snort/Sigma/JSON rules with regenerate/download
- `styles/design.css` - Dark mode theme with glassmorphism, gradients, micro-animations
- `vite.config.js` - Vite config with proxy to `localhost:8000`, build outputs to `backend/static`

### Configuration

Environment variables from `.env`:
- `NVD_API_KEY` - NVD API key (recommended for higher rate limits: 50 req/30s vs 5 req/30s)
- `OTX_API_KEY` - AlienVault OTX API key (required for IoC fetch)
- `BASIC_AUTH_USERNAME` / `BASIC_AUTH_PASSWORD` - Dashboard login (default: admin/changeme)
- `DATABASE_URL` - SQLite connection (default: `sqlite:///./vuln_tracker.db`)
- `OUTPUT_DIR` - Rules output directory (default: `output_rules/`)

### Output Files

Rules generated in `output_rules/`:
- `snort.rules` - Snort/Suricata drop rules with priority (1-3), SID from MD5 hash
- `sigma.yml` - Sigma YAML rules with title, ID, description, references, tags, detection keywords
- `alerts.json` - JSON alert feed with CVE details, severity, CVSS score, IoC count and list, NVD URL

### Tech Stack

- **Backend**: Python 3.11+, FastAPI, SQLModel, SQLite (WAL mode), APScheduler, httpx
- **Frontend**: React 18+, Vite, Chart.js (doughnut/bar charts), Vanilla CSS with CSS variables
- **Deployment**: Self-hosted, no external dependencies beyond API keys
