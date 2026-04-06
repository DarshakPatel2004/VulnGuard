/*
   VulnForge - Precision Threat Intelligence Platform
   Made by Darshak Patel
   [dp-watermark-2026]
*/

import React, { useEffect, useState } from 'react';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
} from 'chart.js';
import { Doughnut, Bar } from 'react-chartjs-2';
import { api } from '../api.js';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement);

const CHART_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f59e0b',
  MEDIUM: '#22c55e',
  LOW: '#38bdf8',
};

function formatDateTime(value) {
  return value ? new Date(value).toLocaleString() : 'Not available';
}

function StatCard({ label, value, tone = '', detail }) {
  return (
    <div className={`stat-card ${tone}`}>
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value ?? '--'}</span>
      {detail ? <span className="stat-detail">{detail}</span> : null}
    </div>
  );
}

function SourceStatusCard({ source, data }) {
  const tone = data?.status === 'success' ? 'success' : data?.status === 'error' ? 'danger' : 'neutral';
  return (
    <div className="source-status-card">
      <div className="source-status-top">
        <div>
          <div className="source-name">{source.toUpperCase()}</div>
          <div className="source-time">{formatDateTime(data?.last_fetched)}</div>
        </div>
        <span className={`source-badge ${tone}`}>{data?.status || 'unknown'}</span>
      </div>
      <div className="source-footnote">{data?.error || 'Feed healthy or waiting for the first run.'}</div>
    </div>
  );
}

export default function Dashboard({ onToast, onStatusRefresh }) {
  const [stats, setStats] = useState(null);
  const [recentCves, setRecentCves] = useState([]);
  const [fetchStatus, setFetchStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    setLoading(true);
    try {
      const [s, cves, status] = await Promise.all([
        api.get('/cves/stats'),
        api.get('/cves/?limit=8&skip=0'),
        api.get('/fetch/status'),
      ]);
      setStats(s);
      setRecentCves(cves);
      setFetchStatus(status);
    } catch (e) {
      onToast('Failed to load dashboard data', 'error');
    }
    setLoading(false);
  }

  async function triggerSync() {
    setSyncing(true);
    try {
      await api.get('/fetch/all');
      onToast('Full sync started in the background. Refresh in a moment for updated results.', 'success');
      if (onStatusRefresh) onStatusRefresh();
    } catch (e) {
      onToast(`Failed to start sync: ${e.message}`, 'error');
    }
    setSyncing(false);
  }

  const doughnutData = stats
    ? {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [
          {
            data: [stats.critical, stats.high, stats.medium, stats.low],
            backgroundColor: [CHART_COLORS.CRITICAL, CHART_COLORS.HIGH, CHART_COLORS.MEDIUM, CHART_COLORS.LOW],
            borderWidth: 0,
            spacing: 4,
            hoverOffset: 4,
          },
        ],
      }
    : null;

  const barData = stats
    ? {
        labels: ['Critical', 'High', 'Medium', 'Low', 'KEV'],
        datasets: [
          {
            data: [stats.critical, stats.high, stats.medium, stats.low, stats.kev_count],
            backgroundColor: ['#ef4444', '#f59e0b', '#22c55e', '#38bdf8', '#f97316'],
            borderRadius: 10,
          },
        ],
      }
    : null;

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: {
          color: '#94a3b8',
          font: { family: 'system-ui', size: 11 },
          usePointStyle: true,
        },
      },
    },
    scales: {
      x: {
        ticks: { color: '#94a3b8' },
        grid: { display: false },
      },
      y: {
        ticks: { color: '#64748b' },
        grid: { color: 'rgba(148, 163, 184, 0.12)' },
      },
    },
  };

  if (loading) return <div className="spinner" />;

  return (
    <div className="page-stack fade-in">
      <section className="hero-panel">
        <div>
          <div className="eyebrow">Operations summary</div>
          <h1 className="hero-title">Threat posture at a glance</h1>
          <p className="hero-copy">
            Review the risk that matters most, check source health at a glance, and kick off a fresh sync without leaving the dashboard.
          </p>
        </div>
        <div className="hero-actions">
          <button id="btn-manual-sync" className="btn btn-primary" onClick={triggerSync} disabled={syncing}>
            {syncing ? 'Starting sync...' : 'Start full sync'}
          </button>
          <button className="btn btn-ghost" onClick={loadData}>Refresh view</button>
        </div>
      </section>

      <div className="stats-grid stats-grid-wide">
        <StatCard label="Total CVEs" value={stats?.total_cves} detail="Current database inventory" />
        <StatCard label="Critical" value={stats?.critical} tone="critical" detail="Immediate remediation candidates" />
        <StatCard label="High" value={stats?.high} tone="high" detail="Needs active prioritization" />
        <StatCard label="KEV" value={stats?.kev_count} tone="kev" detail="Known exploited vulnerabilities" />
        <StatCard label="IoCs" value={stats?.total_iocs} tone="ioc" detail="Indicators available for detection" />
      </div>

      <div className="grid-2 dashboard-grid">
        <div className="card insight-card">
          <div className="card-header card-header-stack">
            <div>
              <div className="eyebrow">Distribution</div>
              <h2>Severity mix</h2>
            </div>
            <p className="section-note">A quick read on where exposure is clustering right now.</p>
          </div>
          <div className="card-body chart-body split-chart">
            <div className="chart-container tall-chart">
              {doughnutData ? <Doughnut data={doughnutData} options={chartOptions} /> : null}
            </div>
            <div className="chart-container short-chart">
              {barData ? <Bar data={barData} options={chartOptions} /> : null}
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header card-header-stack">
            <div>
              <div className="eyebrow">Feed health</div>
              <h2>Source status</h2>
            </div>
            <p className="section-note">Latest fetch timestamps with source-specific health notes.</p>
          </div>
          <div className="card-body source-status-grid">
            {['nvd', 'cisa_kev', 'otx'].map((source) => (
              <SourceStatusCard key={source} source={source.replace('_', ' ')} data={fetchStatus?.[source]} />
            ))}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header card-header-stack horizontal-between">
          <div>
            <div className="eyebrow">Priority queue</div>
            <h2>Recent high-severity CVEs</h2>
          </div>
          <p className="section-note">Open any row to inspect the record and attached indicators.</p>
        </div>
        <div className="table-shell">
          {recentCves.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">No data yet</div>
              Run a sync to populate the dashboard with vulnerabilities and detections.
            </div>
          ) : (
            <table className="vuln-table">
              <thead>
                <tr>
                  <th>CVE ID</th>
                  <th>Severity</th>
                  <th>CVSS</th>
                  <th>KEV</th>
                  <th>Published</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                {recentCves.map((cve) => (
                  <tr key={cve.cve_id} onClick={() => setSelected(cve)}>
                    <td><span className="mono cve-id">{cve.cve_id}</span></td>
                    <td>{cve.cvss_v3_severity ? <span className={`badge badge-${cve.cvss_v3_severity}`}>{cve.cvss_v3_severity}</span> : '--'}</td>
                    <td className="score-cell">{cve.cvss_v3_score ?? '--'}</td>
                    <td>{cve.is_kev ? <span className="badge badge-kev">KEV</span> : '--'}</td>
                    <td className="muted-cell">{cve.published ? new Date(cve.published).toLocaleDateString() : '--'}</td>
                    <td className="description-cell">{cve.description || '--'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {selected ? <CveDrawer cve={selected} onClose={() => setSelected(null)} /> : null}
    </div>
  );
}

function CveDrawer({ cve, onClose }) {
  const [detail, setDetail] = useState(null);

  useEffect(() => {
    api.get(`/cves/${cve.cve_id}`).then(setDetail).catch(() => {});
  }, [cve.cve_id]);

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <div className="drawer">
        <div className="drawer-header">
          <div>
            <div className="eyebrow">CVE detail</div>
            <h2>{cve.cve_id}</h2>
            <div className="drawer-badges">
              {cve.cvss_v3_severity ? <span className={`badge badge-${cve.cvss_v3_severity}`}>{cve.cvss_v3_severity} {cve.cvss_v3_score}</span> : null}
              {cve.is_kev ? <span className="badge badge-kev">CISA KEV</span> : null}
            </div>
          </div>
          <button className="drawer-close" onClick={onClose}>Close</button>
        </div>

        <div className="drawer-section">
          <h3>Description</h3>
          <p>{cve.description || 'No description available.'}</p>
        </div>

        <div className="drawer-section key-value-list">
          <h3>Details</h3>
          <div className="key-value-row"><span>Published</span><strong>{formatDateTime(cve.published)}</strong></div>
          <div className="key-value-row"><span>Last modified</span><strong>{formatDateTime(cve.last_modified)}</strong></div>
          <div className="key-value-row"><span>CVSS v3</span><strong>{cve.cvss_v3_score ?? '--'}</strong></div>
          <div className="key-value-row"><span>CVSS v2</span><strong>{cve.cvss_v2_score ?? '--'}</strong></div>
        </div>

        <div className="drawer-section">
          <h3>Indicators of compromise ({detail?.iocs?.length ?? 0})</h3>
          {detail?.iocs?.length > 0 ? (
            <div className="ioc-list">
              {detail.iocs.map((ioc, index) => (
                <div key={index} className="ioc-item">
                  <span className="ioc-type">{ioc.ioc_type}</span>
                  <span className="ioc-value">{ioc.value}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="muted-copy">No IoCs found for this CVE.</p>
          )}
        </div>

        <div className="drawer-section">
          <a
            href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-ghost"
          >
            Open in NVD
          </a>
        </div>
      </div>
    </>
  );
}
