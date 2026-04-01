/*
   VulnTracker - Precision Threat Intelligence Platform
   Made by Darshak Patel
   [dp-watermark-2026]
*/

import React, { useState, useEffect, useCallback } from 'react';
import { api } from './api.js';
import Login from './components/Login.jsx';
import Dashboard from './components/Dashboard.jsx';
import CveList from './components/CveList.jsx';
import RuleList from './components/RuleList.jsx';
import AssetTable from './components/AssetTable.jsx';
import './styles/design.css';

const PAGES = [
  { id: 'dashboard', label: 'Dashboard', meta: 'Ops overview' },
  { id: 'cves', label: 'CVE Database', meta: 'Search and triage' },
  { id: 'rules', label: 'Detection Rules', meta: 'Generated outputs' },
  { id: 'assets', label: 'Asset Inventory', meta: 'Coverage and matches' },
];

function formatRelative(iso) {
  if (!iso) return 'No sync data yet';
  const diffMs = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(diffMs) || diffMs < 0) return 'Updated recently';
  const minutes = Math.floor(diffMs / 60000);
  if (minutes < 1) return 'Updated just now';
  if (minutes < 60) return `Updated ${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `Updated ${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `Updated ${days}d ago`;
}

function Toast({ toasts }) {
  return (
    <div className="toast-container" aria-live="polite" aria-atomic="true">
      {toasts.map((t) => (
        <div key={t.id} className={`toast ${t.type}`}>
          <div className="toast-title">{t.type === 'success' ? 'Success' : 'Notice'}</div>
          <div>{t.message}</div>
        </div>
      ))}
    </div>
  );
}

export default function App() {
  const [loggedIn, setLoggedIn] = useState(api.isLoggedIn());
  const [page, setPage] = useState('dashboard');
  const [toasts, setToasts] = useState([]);
  const [fetchStatus, setFetchStatus] = useState(null);

  const addToast = useCallback((message, type = 'success') => {
    const id = Date.now();
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 4000);
  }, []);

  const loadStatus = useCallback(async () => {
    if (!api.isLoggedIn()) return;
    try {
      const data = await api.get('/fetch/status');
      setFetchStatus(data);
    } catch {
      setFetchStatus(null);
    }
  }, []);

  useEffect(() => {
    if (!loggedIn) return undefined;
    loadStatus();
    const timer = setInterval(loadStatus, 60000);
    return () => clearInterval(timer);
  }, [loggedIn, loadStatus]);

  function handleLogout() {
    api.clearCredentials();
    setLoggedIn(false);
  }

  if (!loggedIn) {
    return (
      <>
        <Login onLogin={() => setLoggedIn(true)} />
        <Toast toasts={toasts} />
      </>
    );
  }

  const activePage = PAGES.find((item) => item.id === page) || PAGES[0];
  const latestSync = fetchStatus
    ? Object.values(fetchStatus)
        .map((item) => item?.last_fetched)
        .filter(Boolean)
        .sort()
        .at(-1)
    : null;

  function renderPage() {
    if (page === 'dashboard') return <Dashboard onToast={addToast} onStatusRefresh={loadStatus} />;
    if (page === 'cves') return <CveList onToast={addToast} />;
    if (page === 'rules') return <RuleList onToast={addToast} />;
    if (page === 'assets') return <AssetTable onToast={addToast} />;
    return null;
  }

  return (
    <>
      <div className="shell-bg" />
      <div className="app-shell">
        <aside className="sidebar">
          <div className="sidebar-brand-block">
            <div className="eyebrow">Security operations</div>
            <div className="brand-title">VulnTracker</div>
            <p className="brand-copy">Threat visibility, asset coverage, and rule generation in one local workspace.</p>
          </div>

          <div className="sidebar-section-label">Workspace</div>
          <div className="status-panel">
            <div>
              <div className="status-kicker">Sync posture</div>
              <div className="status-headline">{formatRelative(latestSync)}</div>
            </div>
            <div className="status-indicator ok">
              <span className="status-dot" />
              Connected
            </div>
          </div>

          <div className="sidebar-section-label">Navigation</div>
          <nav className="sidebar-nav">
            {PAGES.map((item, index) => (
              <button
                key={item.id}
                type="button"
                className={`sidebar-item ${page === item.id ? 'active' : ''}`}
                onClick={() => setPage(item.id)}
              >
                <span className="nav-index">0{index + 1}</span>
                <span>
                  <span className="nav-label">{item.label}</span>
                  <span className="nav-meta">{item.meta}</span>
                </span>
              </button>
            ))}
          </nav>

          <div className="sidebar-section-label">Sources</div>
          <div className="source-list">
            <a className="source-link" href="https://nvd.nist.gov" target="_blank" rel="noopener noreferrer">NVD</a>
            <a className="source-link" href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer">CISA KEV</a>
            <a className="source-link" href="https://otx.alienvault.com" target="_blank" rel="noopener noreferrer">AlienVault OTX</a>
          </div>

          <div className="sidebar-footer">
            <div className="brand-copyright">Made by Darshak Patel</div>
            <div className="app-version">VulnTracker v1.0.0</div>
          </div>
        </aside>

        <section className="content-shell">
          <header className="topbar">
            <div>
              <div className="eyebrow">{activePage.meta}</div>
              <div className="topbar-title">{activePage.label}</div>
            </div>
            <div className="topbar-right">
              <div className="topbar-pill">
                <span className="pill-label">Last sync</span>
                <span className="pill-value">{latestSync ? new Date(latestSync).toLocaleString() : 'Unavailable'}</span>
              </div>
              <button id="btn-logout" className="btn btn-ghost" onClick={handleLogout}>Sign out</button>
            </div>
          </header>

          <main className="main-content">{renderPage()}</main>

          <nav className="mobile-nav">
            {PAGES.map((item) => (
              <button
                key={item.id}
                type="button"
                className={`mobile-nav-item ${page === item.id ? 'active' : ''}`}
                onClick={() => setPage(item.id)}
              >
                <span className="mobile-nav-label">{item.label}</span>
              </button>
            ))}
          </nav>
        </section>
      </div>

      <Toast toasts={toasts} />
    </>
  );
}
