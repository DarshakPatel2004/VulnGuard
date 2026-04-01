/*
   VulnTracker - Precision Threat Intelligence Platform
   Made by Darshak Patel
   [dp-watermark-2026]
*/

import React, { useEffect, useState, useCallback } from 'react';
import { api } from '../api.js';

const SEVERITIES = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const SORTS = ['Highest score', 'Newest published', 'Oldest published'];

export default function CveList({ onToast }) {
  const [cves, setCves] = useState([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [kevOnly, setKevOnly] = useState(false);
  const [skip, setSkip] = useState(0);
  const [selected, setSelected] = useState(null);
  const [sortMode, setSortMode] = useState('Highest score');
  const LIMIT = 50;

  const load = useCallback(async (s = skip, sev = severity, kev = kevOnly, q = search) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ skip: String(s), limit: String(LIMIT) });
      if (sev) params.set('severity', sev);
      if (kev) params.set('kev_only', 'true');
      if (q) params.set('search', q);
      const data = await api.get(`/cves/?${params}`);
      setCves(data);
    } catch (e) {
      onToast(`Failed to fetch CVEs: ${e.message}`, 'error');
    }
    setLoading(false);
  }, [skip, severity, kevOnly, search, onToast]);

  useEffect(() => {
    load(0, severity, kevOnly, search);
  }, [severity, kevOnly]);

  function handleSearch(e) {
    e.preventDefault();
    setSkip(0);
    load(0, severity, kevOnly, search);
  }

  function clearFilters() {
    setSearch('');
    setSeverity('');
    setKevOnly(false);
    setSkip(0);
    load(0, '', false, '');
  }

  const sortedCves = [...cves].sort((a, b) => {
    if (sortMode === 'Newest published') {
      return new Date(b.published || 0) - new Date(a.published || 0);
    }
    if (sortMode === 'Oldest published') {
      return new Date(a.published || 0) - new Date(b.published || 0);
    }
    return (b.cvss_v3_score || 0) - (a.cvss_v3_score || 0);
  });

  const activeFilters = [severity || null, kevOnly ? 'KEV only' : null, search ? `Search: ${search}` : null].filter(Boolean);

  return (
    <div className="page-stack fade-in">
      <section className="hero-panel compact-hero">
        <div>
          <div className="eyebrow">Search and triage</div>
          <h1 className="hero-title">CVE database</h1>
          <p className="hero-copy">Filter the vulnerability inventory, sort for review, and drill into the records that need action first.</p>
        </div>
        <div className="hero-metrics">
          <div className="metric-chip"><span className="metric-value">{skip / LIMIT + 1}</span><span className="metric-label">Page</span></div>
          <div className="metric-chip"><span className="metric-value">{cves.length}</span><span className="metric-label">Shown</span></div>
          <div className="metric-chip"><span className="metric-value">{activeFilters.length}</span><span className="metric-label">Filters</span></div>
        </div>
      </section>

      <div className="card">
        <div className="card-header card-header-stack">
          <div>
            <div className="eyebrow">Query controls</div>
            <h2>Refine results</h2>
          </div>
          <p className="section-note">Combine severity, KEV, and free-text search to narrow the list.</p>
        </div>
        <div className="card-body">
          <form className="filter-bar" onSubmit={handleSearch}>
            <input
              id="cve-search"
              className="input-search"
              type="text"
              placeholder="Search by CVE ID or description"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <select
              id="severity-filter"
              className="select-filter"
              value={severity}
              onChange={(e) => { setSeverity(e.target.value); setSkip(0); }}
            >
              {SEVERITIES.map((item) => (
                <option key={item} value={item}>{item || 'All severities'}</option>
              ))}
            </select>
            <select className="select-filter" value={sortMode} onChange={(e) => setSortMode(e.target.value)}>
              {SORTS.map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
            <label className="checkbox-filter">
              <input type="checkbox" checked={kevOnly} onChange={(e) => { setKevOnly(e.target.checked); setSkip(0); }} />
              Known exploited only
            </label>
            <button id="btn-search" type="submit" className="btn btn-primary">Apply</button>
            <button type="button" className="btn btn-ghost" onClick={clearFilters}>Clear</button>
          </form>

          {activeFilters.length > 0 ? (
            <div className="chip-row">
              {activeFilters.map((item) => <span key={item} className="filter-chip">{item}</span>)}
            </div>
          ) : null}
        </div>
      </div>

      <div className="card">
        <div className="card-header horizontal-between">
          <div>
            <div className="eyebrow">Results</div>
            <h2>{sortedCves.length ? `${sortedCves.length} records on this page` : 'No records found'}</h2>
          </div>
          <button className="btn btn-ghost" onClick={() => load(skip)}>Refresh</button>
        </div>
        <div className="table-shell">
          {loading ? <div className="spinner" /> : null}
          {!loading && sortedCves.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">No matches</div>
              Try broadening the search or clearing the active filters.
            </div>
          ) : null}
          {!loading && sortedCves.length > 0 ? (
            <table className="vuln-table">
              <thead>
                <tr>
                  <th>CVE ID</th>
                  <th>Severity</th>
                  <th>CVSS v3</th>
                  <th>KEV</th>
                  <th>Published</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                {sortedCves.map((cve) => (
                  <tr key={cve.cve_id} onClick={() => setSelected(cve)}>
                    <td><span className="mono cve-id">{cve.cve_id}</span></td>
                    <td>{cve.cvss_v3_severity ? <span className={`badge badge-${cve.cvss_v3_severity}`}>{cve.cvss_v3_severity}</span> : <span className="muted-cell">--</span>}</td>
                    <td className="score-cell" style={{ color: scoreColor(cve.cvss_v3_score) }}>{cve.cvss_v3_score ?? '--'}</td>
                    <td>{cve.is_kev ? <span className="badge badge-kev">KEV</span> : '--'}</td>
                    <td className="muted-cell">{cve.published ? new Date(cve.published).toLocaleDateString() : '--'}</td>
                    <td className="description-cell">{cve.description || '--'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : null}
        </div>

        <div className="card-footer pagination-bar">
          <button
            className="btn btn-ghost"
            disabled={skip === 0}
            onClick={() => {
              const next = Math.max(0, skip - LIMIT);
              setSkip(next);
              load(next);
            }}
          >
            Previous
          </button>
          <span className="pagination-label">Page {Math.floor(skip / LIMIT) + 1}</span>
          <button
            className="btn btn-ghost"
            disabled={cves.length < LIMIT}
            onClick={() => {
              const next = skip + LIMIT;
              setSkip(next);
              load(next);
            }}
          >
            Next
          </button>
        </div>
      </div>

      {selected ? <CveDrawerInline cve={selected} onClose={() => setSelected(null)} /> : null}
    </div>
  );
}

function scoreColor(score) {
  if (!score) return 'var(--text-muted)';
  if (score >= 9) return 'var(--critical)';
  if (score >= 7) return 'var(--high)';
  if (score >= 4) return 'var(--medium)';
  return 'var(--low)';
}

function CveDrawerInline({ cve, onClose }) {
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
            <div className="eyebrow">Record detail</div>
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
          ) : <p className="muted-copy">No IoCs found for this CVE.</p>}
        </div>
        <a href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`} target="_blank" rel="noopener noreferrer" className="btn btn-ghost">
          Open in NVD
        </a>
      </div>
    </>
  );
}
