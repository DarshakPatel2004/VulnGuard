# Vulnerability Tracker

**A local threat intelligence platform for aggregating CVEs, managing assets, and auto-generating detection rules.**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![SQLite](https://img.shields.io/badge/SQLite-Local_DB-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/License-Proprietary-red?style=for-the-badge)](./key)

</div>

---

## ✨ Overview

Vulnerability Tracker is a **self-hosted threat intelligence and detection-rule generation platform**. It pulls vulnerability data from multiple public feeds, enriches it with IoC data, stores everything locally in SQLite, and surfaces it through a FastAPI backend and a React dashboard.

> **No cloud dependency. No data leaves your machine. Runs fully offline after the initial sync.**

---

## 🚀 Features

| Feature | Description |
|---|---|
| 📡 **Multi-source Aggregation** | Pulls from NVD, CISA KEV, and AlienVault OTX automatically |
| 🗄️ **Local Storage** | All CVEs, IoCs, fetch logs, and assets stored in a local SQLite database |
| 🔁 **Scheduled Syncs** | Daily full sync + hourly incremental sync running in the background |
| 🧠 **Asset Intelligence** | Map assets to CPE strings and auto-discover matching CVEs |
| 📜 **Rule Generation** | One-click export of Snort/Suricata, Sigma, and JSON alert rules |
| 🔐 **Auth Protected** | HTTP Basic auth on all sensitive API routes |
| 📊 **React Dashboard** | Login, CVE browsing, stats charts, asset management, rule exports |

---

## 🏗️ Tech Stack

```
Backend   │  Python 3.11 · FastAPI · SQLModel · APScheduler · httpx
Frontend  │  React 18 · Vite · Chart.js · Axios
Database  │  SQLite (local, zero-config)
Auth      │  HTTP Basic auth via environment variables
Rules     │  Snort / Suricata · Sigma · JSON
```

---

## 📁 Project Structure

```
vulnerability-tracker/
├── backend/
│   └── app/
│       ├── routers/        # API routes: CVEs, assets, fetch jobs, rules
│       ├── services/       # Source integrations: NVD, CISA KEV, OTX
│       ├── main.py         # FastAPI app entry point
│       └── scheduler.py    # Background sync job definitions
├── frontend/
│   └── src/                # React 18 application source
├── scripts/                # Maintenance & utility scripts
├── output_rules/           # Generated rule files (snort.rules, sigma.yml, alerts.json)
├── public/                 # Static frontend assets
├── requirements.txt        # Python dependencies
└── .env                    # Local config (not committed)
```

---

## ⚙️ Prerequisites

- **Python** `3.11+`
- **Node.js** `18+` with `npm`

---

## 🔑 Environment Setup

Create a `.env` file at the **project root** before running anything:

```env
# --- Data Sources ---
NVD_API_KEY=your_nvd_api_key          # Strongly recommended for higher rate limits
OTX_API_KEY=your_otx_api_key          # Required for OTX enrichment & rule coverage

# --- Auth ---
BASIC_AUTH_USERNAME=admin
BASIC_AUTH_PASSWORD=changeme           # Change this!

# --- Database ---
DATABASE_URL=sqlite:///./vuln_tracker.db   # Defaults to this if omitted

# --- Server ---
APP_HOST=0.0.0.0
APP_PORT=8000
DEBUG=true
```

> [!TIP]
> Get your free NVD API key at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key). Without it, requests are rate-limited to 5 req/30s.

---

## 🛠️ Installation

### 1 · Backend

```powershell
cd D:\sideproject\vulnerability-tracker
python -m venv venv
.\venv\Scripts\pip install -r requirements.txt
```

### 2 · Frontend

```powershell
cd D:\sideproject\vulnerability-tracker\frontend
npm install
```

---

## ▶️ Running Locally

Open **two terminals** side by side:

**Terminal 1 — Backend**
```powershell
cd D:\sideproject\vulnerability-tracker
.\venv\Scripts\python -m uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 — Frontend**
```powershell
cd D:\sideproject\vulnerability-tracker\frontend
npm run dev
```

Then open your browser:

| Service | URL |
|---|---|
| 🖥️ Dashboard | http://localhost:5173 |
| ⚡ API | http://localhost:8000 |
| 📖 Swagger Docs | http://localhost:8000/docs |

Log in with the `BASIC_AUTH_USERNAME` / `BASIC_AUTH_PASSWORD` values from your `.env` file.

---

## ⏰ Scheduled Jobs

The scheduler starts automatically with FastAPI. No extra configuration needed.

| Job | Schedule | Description |
|---|---|---|
| Full Sync | Daily at `02:00 UTC` | Fetches all data from NVD, CISA KEV, and OTX |
| Incremental Sync | Every hour (`:00`) | Pulls only recent changes since last sync |

---

## 🔌 API Reference

> All routes except `GET /` require **HTTP Basic auth**.

<details>
<summary><strong>🩺 Health &amp; Auth</strong></summary>

| Method | Route | Description |
|---|---|---|
| `GET` | `/` | Service status / health check |
| `GET` | `/auth/verify` | Validate credentials |

</details>

<details>
<summary><strong>🐛 CVEs</strong></summary>

| Method | Route | Description |
|---|---|---|
| `GET` | `/cves/` | List CVEs with filtering & pagination |
| `GET` | `/cves/stats` | Dashboard summary statistics |
| `GET` | `/cves/{cve_id}` | CVE detail with associated IoCs |

</details>

<details>
<summary><strong>🔄 Fetch Jobs</strong></summary>

| Method | Route | Description |
|---|---|---|
| `GET` | `/fetch/all` | Trigger a full sync from all sources |
| `GET` | `/fetch/nvd` | Trigger NVD fetch only |
| `GET` | `/fetch/cisa-kev` | Sync the CISA KEV catalog |
| `GET` | `/fetch/otx` | Fetch OTX data for recent CVEs |
| `GET` | `/fetch/status` | Inspect last fetch status per source |

</details>

<details>
<summary><strong>🖥️ Assets</strong></summary>

| Method | Route | Description |
|---|---|---|
| `GET` | `/assets/` | List all tracked assets |
| `POST` | `/assets/` | Create a new asset |
| `GET` | `/assets/{asset_id}` | Get a single asset |
| `DELETE` | `/assets/{asset_id}` | Delete an asset |
| `GET` | `/assets/{asset_id}/cves` | Find CVEs matching the asset's CPE |

</details>

<details>
<summary><strong>📜 Rules</strong></summary>

| Method | Route | Description |
|---|---|---|
| `GET` | `/rules/snort` | Generate / return Snort rules |
| `GET` | `/rules/snort/download` | Download `snort.rules` |
| `GET` | `/rules/sigma` | Generate / return Sigma rules |
| `GET` | `/rules/sigma/download` | Download `sigma.yml` |
| `GET` | `/rules/json` | Generate / return JSON alerts |
| `GET` | `/rules/json/download` | Download `alerts.json` |

</details>

---

## 📤 Generated Outputs

Rule files are written to `output_rules/` (relative to where you launch the backend):

```
output_rules/
├── snort.rules      # Snort / Suricata IDS rules
├── sigma.yml        # Sigma SIEM detection rules
└── alerts.json      # JSON-formatted alert payloads
```

---

## 🌐 Data Sources

| Source | Description | Link |
|---|---|---|
| **NVD** | National Vulnerability Database (NIST) | [nvd.nist.gov](https://nvd.nist.gov/developers/vulnerabilities) |
| **CISA KEV** | Known Exploited Vulnerabilities Catalog | [cisa.gov/kev](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| **AlienVault OTX** | Open Threat Exchange IoC feeds | [otx.alienvault.com](https://otx.alienvault.com/) |

---

## 🧰 Utility Scripts

The `scripts/` directory contains maintenance tools for syncing, diagnostics, data inspection, and CPE correction. These are **not required** to run the main app but are helpful for day-to-day operations.

---

<div align="center">

Made with 🔐 for defenders who prefer their data local.

