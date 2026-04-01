# 🚀 How to Run VulnTracker

Follow these steps in order the first time. After setup, only Steps 4 and 5 are needed on every subsequent run.

---

## ✅ Prerequisites — Install These First

| Tool | Purpose | Download |
|------|---------|----------|
| Python 3.11+ | Runs the back-end | https://www.python.org/downloads/ |
| Node.js 24 LTS | Runs the front-end | https://nodejs.org/dist/v24.14.1/node-v24.14.1-x64.msi |

After installing, **close and reopen PowerShell** so PATH updates take effect.

---

## 🔧 One-Time Setup (Do This Once)

### Step 1 — Get Your API Keys

| Key | Where to Get It | Required? |
|-----|----------------|-----------|
| NVD API Key | https://nvd.nist.gov/developers/request-an-api-key | Strongly recommended (higher rate limits) |
| OTX API Key | https://otx.alienvault.com → Account → Settings → API Key | Required for Snort rules |

### Step 2 — Configure `.env`

Open `d:\sideproject\vulnerability-tracker\.env` and fill in:

```env
NVD_API_KEY=your_nvd_key_here
OTX_API_KEY=your_otx_key_here

BASIC_AUTH_USERNAME=admin
BASIC_AUTH_PASSWORD=yourpassword   ← change this!

DATABASE_URL=sqlite:///./vuln_tracker.db
APP_HOST=0.0.0.0
APP_PORT=8000
DEBUG=true
```

### Step 3 — Create Python Virtual Environment

Open PowerShell in `d:\sideproject\vulnerability-tracker`:

```powershell
python -m venv venv
.\venv\Scripts\pip install -r requirements.txt
```

> ⚠️ This only needs to be done once. It installs all Python dependencies inside the `venv/` folder.

### Step 4 — Install Front-end Dependencies

```powershell
cd frontend
npm install
cd ..
```

> ⚠️ This only needs to be done once. It installs React, Vite, and Chart.js into `frontend/node_modules/`.

---

## ▶️ Running the App (Every Time)

You need **two separate PowerShell windows** open at the same time.

### Terminal 1 — Start the Back-end

```powershell
cd d:\sideproject\vulnerability-tracker
.\venv\Scripts\python -m uvicorn backend.app.main:app --reload --port 8000
```

You should see:
```
[Scheduler] APScheduler started. Jobs: daily (02:00 UTC) + hourly incremental.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

✅ Back-end is live at: http://localhost:8000
📘 API docs (Swagger UI): http://localhost:8000/docs

### Terminal 2 — Start the Front-end

```powershell
cd d:\sideproject\vulnerability-tracker\frontend
npm run dev
```

You should see:
```
  ➜  Local:   http://localhost:5173/
```

✅ Dashboard is live at: http://localhost:5173

---

## 🌐 Using the Dashboard

1. Open **http://localhost:5173** in your browser
2. Log in with the username and password you set in `.env`
3. Click **🔄 Manual Sync All** on the Dashboard to pull the first batch of data
   - This fetches CVEs from NVD, CISA KEV, and AlienVault OTX
   - ⏳ First sync may take **5–15 minutes** due to NVD API rate limits
4. Once sync completes, navigate to:
   - **CVE Database** — browse and search all vulnerabilities
   - **Security Rules** → click **Load Rules** to view/download Snort, Sigma, and JSON outputs
   - **Asset Inventory** — add your on-premises devices for CVE matching

---

## 📡 API Endpoints (Back-end Only)

All endpoints require Basic Auth (username/password from `.env`).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Health check |
| GET | `/cves/` | List all CVEs |
| GET | `/cves/stats` | Dashboard statistics |
| GET | `/cves/{cve_id}` | CVE detail + IoCs |
| GET | `/fetch/all` | Trigger full sync (all sources) |
| GET | `/fetch/nvd` | Trigger NVD fetch only |
| GET | `/fetch/cisa-kev` | Trigger CISA KEV sync only |
| GET | `/fetch/otx` | Trigger OTX IoC fetch only |
| GET | `/fetch/status` | View last fetch timestamps |
| GET | `/rules/snort` | View Snort/Suricata rules |
| GET | `/rules/snort/download` | Download `snort.rules` file |
| GET | `/rules/sigma` | View Sigma YAML rules |
| GET | `/rules/sigma/download` | Download `sigma.yml` file |
| GET | `/rules/json` | View JSON alert feed |
| GET | `/rules/json/download` | Download `alerts.json` file |
| GET | `/assets/` | List tracked assets |
| POST | `/assets/` | Add a new asset |
| DELETE | `/assets/{id}` | Delete an asset |
| GET | `/assets/{id}/cves` | CVEs matching an asset's CPE |

---

## 📂 Where Generated Rules Are Saved

After a sync completes, rule files are written to:

```
d:\sideproject\vulnerability-tracker\output_rules\
    snort.rules     ← Snort / Suricata network block rules
    sigma.yml       ← Sigma SIEM detection rules
    alerts.json     ← Generic JSON alert feed
```

---

## 🔁 Automatic Scheduling

The back-end automatically runs syncs in the background while it is running:

| Job | Schedule |
|-----|----------|
| Full sync (NVD + KEV + OTX + rules) | Every day at **02:00 AM UTC** |
| Incremental NVD check | Every hour |

No manual action needed after the first sync.

---

## 🛑 Stopping the App

In each terminal, press **Ctrl + C** to stop the server.

---

## ❓ Troubleshooting

| Problem | Fix |
|---------|-----|
| `npm` not recognized | Install Node.js from https://nodejs.org and reopen PowerShell |
| `python` not recognized | Install Python from https://python.org, check "Add to PATH" during install |
| No Snort rules generated | Make sure `OTX_API_KEY` is set in `.env`, then run a Manual Sync |
| Login fails on dashboard | Check `BASIC_AUTH_USERNAME` and `BASIC_AUTH_PASSWORD` in `.env` match what you're typing |
| Port 8000 already in use | Change `APP_PORT` in `.env` and add `--port XXXX` to the uvicorn command |
| First sync is slow | Normal — NVD rate limits require a 6-second pause between page requests |
