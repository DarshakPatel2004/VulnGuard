# Vulnerability Tracker

Vulnerability Tracker is a local threat intelligence and rule generation app. It pulls vulnerability data from multiple sources, stores it in SQLite, exposes it through a FastAPI API, and provides a React dashboard for browsing CVEs, managing assets, and exporting detection rules.

## What it does

- Aggregates vulnerability data from NVD, CISA KEV, and AlienVault OTX
- Stores CVEs, IoCs, fetch logs, and assets in a local SQLite database
- Generates Snort/Suricata, Sigma, and JSON rule outputs
- Exposes authenticated API endpoints for CVEs, assets, fetch jobs, and rules
- Runs scheduled sync jobs in the background while the backend is running
- Includes a frontend dashboard for login, stats, CVE browsing, rules, and asset tracking

## Tech stack

- Backend: Python, FastAPI, SQLModel, SQLite, APScheduler, httpx
- Frontend: React 18, Vite, Chart.js, Axios
- Auth: HTTP Basic auth backed by environment variables

## Project structure

```text
backend/
  app/
    routers/      API routes for CVEs, assets, fetch jobs, and rules
    services/     Integrations for NVD, CISA KEV, and OTX
    main.py       FastAPI app entry point
    scheduler.py  Daily and hourly background sync jobs
frontend/
  src/            React application source
scripts/          Utility and maintenance scripts
output_rules/     Generated rule files at the repo root
public/           Static frontend assets
requirements.txt  Python dependencies
```

## Prerequisites

- Python 3.11+
- Node.js 18+ with npm

## Environment variables

Create a `.env` file in the project root. The app reads configuration from there at startup.

```env
NVD_API_KEY=your_nvd_api_key
OTX_API_KEY=your_otx_api_key
BASIC_AUTH_USERNAME=admin
BASIC_AUTH_PASSWORD=changeme
DATABASE_URL=sqlite:///./vuln_tracker.db
APP_HOST=0.0.0.0
APP_PORT=8000
DEBUG=true
```

Notes:

- `NVD_API_KEY` is strongly recommended for better rate limits.
- `OTX_API_KEY` is needed for OTX enrichment and rule generation coverage.
- If `DATABASE_URL` is omitted, the backend defaults to `sqlite:///./vuln_tracker.db`.

## Installation

### Backend

```powershell
cd D:\sideproject\vulnerability-tracker
python -m venv venv
.\venv\Scripts\pip install -r requirements.txt
```

### Frontend

```powershell
cd D:\sideproject\vulnerability-tracker\frontend
npm install
```

## Running locally

Start the backend in one terminal:

```powershell
cd D:\sideproject\vulnerability-tracker
.\venv\Scripts\python -m uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

Start the frontend in a second terminal:

```powershell
cd D:\sideproject\vulnerability-tracker\frontend
npm run dev
```

Open:

- Frontend: `http://localhost:5173`
- API: `http://localhost:8000`
- Swagger docs: `http://localhost:8000/docs`

Log in with `BASIC_AUTH_USERNAME` and `BASIC_AUTH_PASSWORD` from your `.env` file.

## Scheduled jobs

The backend scheduler starts automatically with the FastAPI app.

- Daily full sync at `02:00 UTC`
- Hourly incremental sync at the top of each hour

## Main API routes

All routes except the health check require HTTP Basic auth.

### Health and auth

- `GET /` - service status
- `GET /auth/verify` - validate credentials

### CVEs

- `GET /cves/` - list CVEs with filtering and pagination
- `GET /cves/stats` - dashboard summary stats
- `GET /cves/{cve_id}` - CVE details with IoCs

### Fetch jobs

- `GET /fetch/all` - start a full sync
- `GET /fetch/nvd` - start an NVD fetch
- `GET /fetch/cisa-kev` - sync the KEV catalog
- `GET /fetch/otx` - fetch OTX data for recent CVEs
- `GET /fetch/status` - inspect last fetch status by source

### Assets

- `GET /assets/` - list assets
- `POST /assets/` - create an asset
- `GET /assets/{asset_id}` - get one asset
- `DELETE /assets/{asset_id}` - delete an asset
- `GET /assets/{asset_id}/cves` - find CVEs matching an asset CPE

### Rules

- `GET /rules/snort` - generate or return Snort rules
- `GET /rules/snort/download` - download `snort.rules`
- `GET /rules/sigma` - generate or return Sigma rules
- `GET /rules/sigma/download` - download `sigma.yml`
- `GET /rules/json` - generate or return JSON alerts
- `GET /rules/json/download` - download `alerts.json`

## Generated outputs

Generated rule files are written to `output_rules/` by default, relative to the directory where you start the backend process:

- `snort.rules`
- `sigma.yml`
- `alerts.json`

## Data sources

- [NVD API](https://nvd.nist.gov/developers/vulnerabilities)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [AlienVault OTX](https://otx.alienvault.com/)

## Helpful scripts

The `scripts/` folder contains utility scripts for syncing, diagnostics, data inspection, and CPE correction work. These are useful for maintenance but are not required to run the main app.

