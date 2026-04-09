<div align="center">

<img src="docs/images/logo.png" alt="VulnForge Logo" width="80" />

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=32&duration=3000&pause=1000&color=F59E0B&center=true&vCenter=true&width=600&height=60&lines=%E2%9A%A1+VulnForge;Local+Threat+Intelligence;CVE+%7C+IoC+%7C+Detection+Rules" alt="VulnForge" />

<p align="center">
  <strong>A self-hosted threat intelligence platform — aggregate CVEs, manage assets, and auto-generate detection rules. Fully local. Zero cloud dependency.</strong>
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/></a>
  <a href="https://fastapi.tiangolo.com/"><img src="https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI"/></a>
  <a href="https://react.dev/"><img src="https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React"/></a>
  <a href="https://www.sqlite.org/"><img src="https://img.shields.io/badge/SQLite-Local_DB-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite"/></a>

</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#%EF%B8%8F-architecture">Architecture</a> •
  <a href="#-api-reference">API Reference</a> •
  <a href="#-data-sources">Data Sources</a>
</p>

</div>

---

## 📸 Screenshots

<div align="center">

| Dashboard | CVE Browser |
|:---:|:---:|
| <img src="docs/images/dashboard.png" alt="Dashboard" width="480" /> | <img src="docs/images/cve-browser.png" alt="CVE Browser" width="480" /> |

</div>

---

## ⚡ Quick Start

> [!IMPORTANT]
> Make sure Python 3.11+ and Node.js 18+ are installed, and your `.env` is configured before running.

```powershell
# 1. Clone and enter the project
cd VulnForge

# 2. Set up the backend
python -m venv venv
.\venv\Scripts\pip install -r requirements.txt

# 3. Set up the frontend
cd frontend && npm install && cd ..

# 4. Start the backend
.\venv\Scripts\python -m uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000

# 5. Start the frontend (in a new terminal)
cd frontend
npm run dev
```

| 🖥️ Dashboard | ⚡ REST API | 📖 Swagger UI |
|:---:|:---:|:---:|
| [localhost:5173](http://localhost:5173) | [localhost:8000](http://localhost:8000) | [localhost:8000/docs](http://localhost:8000/docs) |

---

## ✨ Features

<table>
  <tr>
    <td>📡</td>
    <td><strong>Multi-source Aggregation</strong></td>
    <td>Automatically pulls from NVD, CISA KEV, and AlienVault OTX on a schedule</td>
  </tr>
  <tr>
    <td>🗄️</td>
    <td><strong>Fully Local Storage</strong></td>
    <td>CVEs, IoCs, fetch logs, and assets stored in a zero-config local SQLite database</td>
  </tr>
  <tr>
    <td>🔁</td>
    <td><strong>Automated Scheduled Syncs</strong></td>
    <td>Daily full sync at 02:00 UTC + hourly incremental sync — hands-free</td>
  </tr>
  <tr>
    <td>🧠</td>
    <td><strong>Asset Intelligence</strong></td>
    <td>Map assets to CPE strings; auto-discover all CVEs that match your environment</td>
  </tr>
  <tr>
    <td>📜</td>
    <td><strong>One-click Rule Generation</strong></td>
    <td>Export Snort/Suricata, Sigma SIEM, and JSON alert rules directly from the dashboard</td>
  </tr>
  <tr>
    <td>🔐</td>
    <td><strong>Auth-Protected API</strong></td>
    <td>HTTP Basic auth guards all sensitive routes via environment variables</td>
  </tr>
  <tr>
    <td>🛡️</td>
    <td><strong>Automated Obfuscation</strong></td>
    <td>Built-in security layer that automatically encodes plain-text API keys in .env on startup</td>
  </tr>
  <tr>
    <td>🎨</td>
    <td><strong>Dark-First Design System</strong></td>
    <td>Amber-accented cybersecurity dashboard with Inter + JetBrains Mono typography, glassmorphism, and micro-animations</td>
  </tr>
  <tr>
    <td>📊</td>
    <td><strong>React Dashboard</strong></td>
    <td>CVE browsing, severity charts, asset tracking, rule exports — all in one UI</td>
  </tr>
</table>

---

## 🏗️ Architecture

```mermaid
flowchart TD
    subgraph Sources["External Data Sources"]
        NVD["NVD API (NIST)"]
        KEV["CISA KEV Catalog"]
        OTX["AlienVault OTX"]
    end

    subgraph Backend["FastAPI Backend"]
        SCH["APScheduler (Hourly + Daily)"]
        SVC["Services Layer"]
        API["REST API"]
        DB["SQLite DB"]
        RUL["Rule Generator"]
    end

    subgraph Frontend["React Dashboard"]
        UI["Vite + React 18"]
    end

    subgraph Outputs["Generated Outputs"]
        SR["snort.rules"]
        SG["sigma.yml"]
        JS["alerts.json"]
    end

    NVD --> SVC
    KEV --> SVC
    OTX --> SVC
    SCH --> SVC
    SVC --> DB
    DB --> API
    API --> RUL
    RUL --> SR
    RUL --> SG
    RUL --> JS
    API <--> UI
```

---

## 🧰 Tech Stack

<div align="center">

| Layer | Technology |
|:---:|:---|
| **Backend** | Python 3.11 · FastAPI · SQLModel · APScheduler · httpx |
| **Frontend** | React 18 · Vite · Chart.js · react-chartjs-2 |
| **Database** | SQLite — local, zero-config, WAL mode for concurrency |
| **Auth** | HTTP Basic auth — credentials from `.env` |
| **Design** | Inter + JetBrains Mono · CSS Variables · Dark-first amber accent system |
| **Rule Formats** | Snort / Suricata · Sigma YAML · JSON Alerts |

</div>

---

## 📁 Project Structure

```
vulnforge/
│
├── backend/
│   └── app/
│       ├── main.py              ← FastAPI app entry point
│       ├── models.py            ← SQLModel schemas (CVE, IoC, Asset, FetchLog, GeneratedRule)
│       ├── database.py          ← SQLite engine with WAL mode
│       ├── auth.py              ← HTTP Basic Auth
│       ├── config.py            ← Environment config + auto-obfuscation
│       ├── scheduler.py         ← Background sync job definitions
│       ├── rule_generator.py    ← Snort, Sigma, JSON rule generation
│       ├── routers/
│       │   ├── cves.py          ← /cves, /cves/{id}, /cves/stats
│       │   ├── fetcher.py       ← /fetch/{all|nvd|cisa-kev|otx|status}
│       │   ├── rules.py         ← /rules/{snort|sigma|json}[/download]
│       │   └── assets.py        ← CRUD + /assets/{id}/cves (CPE matching)
│       └── services/
│           ├── nvd_service.py       ← NVD API 2.0 fetcher
│           ├── cisa_kev_service.py  ← CISA KEV catalog fetcher
│           └── otx_service.py       ← AlienVault OTX IoC fetcher
│
├── frontend/
│   └── src/
│       ├── main.jsx             ← React entry point
│       ├── App.jsx              ← App shell: sidebar, topbar, routing, toasts
│       ├── api.js               ← HTTP client with Basic Auth
│       ├── components/
│       │   ├── Login.jsx        ← Split-layout auth with feature cards
│       │   ├── Dashboard.jsx    ← Stat cards, severity charts, source health
│       │   ├── CveList.jsx      ← CVE browser with search, filters, pagination
│       │   ├── AssetTable.jsx   ← Asset CRUD with CPE input, match drawer
│       │   └── RuleList.jsx     ← Tabbed view for Snort/Sigma/JSON rules
│       └── styles/
│           └── design.css       ← Design system (tokens, components, animations)
│
├── scripts/                ← Maintenance & utility scripts
├── output_rules/           ← 📜 Generated: snort.rules · sigma.yml · alerts.json
├── docs/images/            ← README screenshots and logo
├── design.md               ← Full design system specification
├── requirements.txt        ← Python dependencies
└── .env                    ← 🔒 Local config (not committed)
```

---

## 🔑 Environment Setup

To get started, create a `.env` file in the project root (you can use `.env.example` as a template) and add your plain-text API keys. 

> [!TIP]
> **Automatic Obfuscation**: The project features a built-in security layer. The first time you start the backend, it will automatically detect any plain-text keys in your `.env` file and encode them to Base64 (prefixed with `b64:`) to prevent accidental "over-the-shoulder" exposure.

### Obtaining API Keys

| Source | How to Get a Key | Benefit |
|:---:|---|---|
| **NVD (NIST)** | [Request at nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) | Increases rate limits (50 req/30s vs 5 req/30s) |
| **AlienVault OTX** | [Sign up at otx.alienvault.com](https://otx.alienvault.com/) | **Required** for IoC enrichment and threat intelligence pulse data |

---

## 🛠️ Installation

<details>
<summary><strong>🐍 Backend Setup</strong></summary>
<br>

```powershell
cd VulnForge
python -m venv venv
.\venv\Scripts\pip install -r requirements.txt
```

</details>

<details>
<summary><strong>⚛️ Frontend Setup</strong></summary>
<br>

```powershell
cd VulnForge\frontend
npm install
```

</details>

---

## ▶️ Running Locally

**Terminal 1 — Backend API**

```powershell
cd VulnForge
.\venv\Scripts\python -m uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 — Frontend Dev Server**

```powershell
cd VulnForge\frontend
npm run dev
```

Log in with the `BASIC_AUTH_USERNAME` / `BASIC_AUTH_PASSWORD` values from your `.env`.

---

## ⏰ Scheduled Jobs

The scheduler starts **automatically** with the FastAPI app. No extra setup needed.

| 🕐 Job | ⏱️ Schedule | 📋 Description |
|---|---|---|
| **Full Sync** | Daily at `02:00 UTC` | Complete fetch from NVD, CISA KEV, and OTX |
| **Incremental Sync** | Every hour `(:00)` | Pulls only recent changes since last run |

---

## 🔌 API Reference

> [!NOTE]
> All routes except `GET /` require **HTTP Basic auth**.

<details>
<summary><strong>🩺 Health &amp; Auth</strong></summary>
<br>

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Service health check |
| `GET` | `/auth/verify` | Validate credentials |

</details>

<details>
<summary><strong>🐛 CVEs</strong></summary>
<br>

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/cves/` | List CVEs with filtering & pagination |
| `GET` | `/cves/stats` | Dashboard summary statistics |
| `GET` | `/cves/{cve_id}` | CVE detail view with associated IoCs |

</details>

<details>
<summary><strong>🔄 Fetch Jobs</strong></summary>
<br>

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/fetch/all` | Trigger a full sync from all sources |
| `GET` | `/fetch/nvd` | Trigger NVD fetch only |
| `GET` | `/fetch/cisa-kev` | Sync the CISA KEV catalog |
| `GET` | `/fetch/otx` | Fetch OTX data for recent CVEs |
| `GET` | `/fetch/status` | Inspect last fetch status per source |

</details>

<details>
<summary><strong>🖥️ Assets</strong></summary>
<br>

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/assets/` | List all tracked assets |
| `POST` | `/assets/` | Add a new asset |
| `GET` | `/assets/{asset_id}` | Get a single asset |
| `DELETE` | `/assets/{asset_id}` | Remove an asset |
| `GET` | `/assets/{asset_id}/cves` | Find CVEs matching the asset's CPE |

</details>

<details>
<summary><strong>📜 Detection Rules</strong></summary>
<br>

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/rules/snort` | Generate or return Snort/Suricata rules |
| `GET` | `/rules/snort/download` | Download `snort.rules` |
| `GET` | `/rules/sigma` | Generate or return Sigma rules |
| `GET` | `/rules/sigma/download` | Download `sigma.yml` |
| `GET` | `/rules/json` | Generate or return JSON alert payloads |
| `GET` | `/rules/json/download` | Download `alerts.json` |

</details>

---

## 📤 Generated Outputs

All rule files are written to `output_rules/` relative to where the backend process starts:

```
output_rules/
├── snort.rules     # Snort / Suricata network IDS rules
├── sigma.yml       # Sigma SIEM detection rules
└── alerts.json     # Structured JSON alert payloads
```

---

## 🌐 Data Sources

<div align="center">

| Source | What It Provides | Link |
|:---:|---|:---:|
| <img src="https://img.shields.io/badge/NVD-NIST-1A73E8?style=flat-square" /> | National Vulnerability Database — full CVE catalog with CVSS scores | [Visit →](https://nvd.nist.gov/developers/vulnerabilities) |
| <img src="https://img.shields.io/badge/CISA-KEV-CC0000?style=flat-square" /> | Known Exploited Vulnerabilities Catalog — actively exploited CVEs | [Visit →](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| <img src="https://img.shields.io/badge/AlienVault-OTX-E65100?style=flat-square" /> | Open Threat Exchange — IoC enrichment from the community | [Visit →](https://otx.alienvault.com/) |

</div>

---

## 🧪 Utility Scripts

The `scripts/` directory contains maintenance tools for manual syncing, diagnostics, data inspection, and CPE string correction. **Not required** to run the main app — useful for day-to-day maintenance.

---

## ⚙️ Prerequisites

| Requirement | Version |
|---|---|
| Python | `3.11+` |
| Node.js | `18+` |
| npm | bundled with Node.js |
| NVD API Key | optional but strongly recommended |
| OTX API Key | required for IoC enrichment |

---

<div align="center">

---

**VulnForge — built for blue teamers who believe their threat data belongs to them.**

*No telemetry. No SaaS. No subscriptions. Just your data, your rules, your machine.*

[![Made with FastAPI](https://img.shields.io/badge/Made%20with-FastAPI-009688?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com)
[![Powered by React](https://img.shields.io/badge/Powered%20by-React-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)

</div>
