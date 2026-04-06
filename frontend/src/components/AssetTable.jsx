/*
   VulnForge - Precision Threat Intelligence Platform
   Made by Darshak Patel
   [dp-watermark-2026]
*/

import React, { useEffect, useState } from 'react';
import { api } from '../api.js';

export default function AssetTable({ onToast }) {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: '', ip_address: '', cpe: '', description: '', tags: '' });
  const [saving, setSaving] = useState(false);
  const [selectedAsset, setSelectedAsset] = useState(null);

  useEffect(() => {
    loadAssets();
  }, []);

  async function loadAssets() {
    setLoading(true);
    try {
      const data = await api.get('/assets/');
      setAssets(data);
    } catch (e) {
      onToast(`Failed to load assets: ${e.message}`, 'error');
    }
    setLoading(false);
  }

  async function handleAdd(e) {
    e.preventDefault();
    setSaving(true);
    try {
      await api.post('/assets/', { ...form, tags: form.tags || null });
      onToast('Asset added successfully.', 'success');
      setForm({ name: '', ip_address: '', cpe: '', description: '', tags: '' });
      setShowForm(false);
      loadAssets();
    } catch (e) {
      onToast(`Failed to add asset: ${e.message}`, 'error');
    }
    setSaving(false);
  }

  async function handleDelete(id, name) {
    if (!window.confirm(`Delete asset "${name}"?`)) return;
    try {
      await api.delete(`/assets/${id}`);
      onToast(`Asset "${name}" deleted.`, 'success');
      loadAssets();
    } catch (e) {
      onToast(`Failed to delete asset: ${e.message}`, 'error');
    }
  }

  const assetsWithCpe = assets.filter((asset) => asset.cpe).length;
  const assetsWithIp = assets.filter((asset) => asset.ip_address).length;

  return (
    <div className="page-stack fade-in">
      <section className="hero-panel compact-hero">
        <div>
          <div className="eyebrow">Coverage management</div>
          <h1 className="hero-title">Asset inventory</h1>
          <p className="hero-copy">Track systems, attach CPEs, and see which known vulnerabilities map back to your environment.</p>
        </div>
        <div className="hero-metrics">
          <div className="metric-chip"><span className="metric-value">{assets.length}</span><span className="metric-label">Assets</span></div>
          <div className="metric-chip"><span className="metric-value">{assetsWithCpe}</span><span className="metric-label">With CPE</span></div>
          <div className="metric-chip"><span className="metric-value">{assetsWithIp}</span><span className="metric-label">With IP</span></div>
        </div>
      </section>

      <div className="section-actions">
        <button id="btn-add-asset" className="btn btn-primary" onClick={() => setShowForm((prev) => !prev)}>
          {showForm ? 'Close form' : 'Add asset'}
        </button>
        <button className="btn btn-ghost" onClick={loadAssets}>Refresh inventory</button>
      </div>

      {showForm ? (
        <div className="card fade-in">
          <div className="card-header card-header-stack">
            <div>
              <div className="eyebrow">New asset</div>
              <h2>Capture a tracked system</h2>
            </div>
            <p className="section-note">CPE is optional, but adding it unlocks direct CVE matching.</p>
          </div>
          <div className="card-body">
            <form onSubmit={handleAdd} className="asset-form-grid">
              <div className="form-group">
                <label htmlFor="asset-name">Name</label>
                <input id="asset-name" className="input-search" type="text" required placeholder="Core firewall" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
              </div>
              <div className="form-group">
                <label htmlFor="asset-ip">IP address</label>
                <input id="asset-ip" className="input-search" type="text" placeholder="192.168.1.1" value={form.ip_address} onChange={(e) => setForm({ ...form, ip_address: e.target.value })} />
              </div>
              <div className="form-group form-group-wide">
                <label htmlFor="asset-cpe">CPE string</label>
                <input id="asset-cpe" className="input-search mono" type="text" placeholder="cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*" value={form.cpe} onChange={(e) => setForm({ ...form, cpe: e.target.value })} />
              </div>
              <div className="form-group form-group-wide">
                <label htmlFor="asset-desc">Description</label>
                <input id="asset-desc" className="input-search" type="text" placeholder="Edge firewall for branch office traffic" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
              </div>
              <div className="form-actions form-group-wide">
                <button id="btn-save-asset" type="submit" className="btn btn-primary" disabled={saving}>
                  {saving ? 'Saving...' : 'Save asset'}
                </button>
              </div>
            </form>
          </div>
        </div>
      ) : null}

      <div className="card asset-table-card">
        <div className="card-header horizontal-between">
          <div>
            <div className="eyebrow">Tracked systems</div>
            <h2>{assets.length} assets in inventory</h2>
          </div>
          <span className="section-note">View vulnerability matches from the right-side drawer.</span>
        </div>
        <div className="table-shell asset-table-shell">
          {loading ? <div className="spinner" /> : null}
          {!loading && assets.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">Inventory empty</div>
              Add your first asset to begin matching systems against known vulnerabilities.
            </div>
          ) : null}
          {!loading && assets.length > 0 ? (
            <table className="vuln-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>IP</th>
                  <th>CPE</th>
                  <th>Description</th>
                  <th>Added</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((asset) => (
                  <tr key={asset.id}>
                    <td className="strong-cell">{asset.name}</td>
                    <td><span className="mono">{asset.ip_address || '--'}</span></td>
                    <td><span className="mono cpe-cell">{asset.cpe || '--'}</span></td>
                    <td className="description-cell">{asset.description || '--'}</td>
                    <td className="muted-cell">{asset.created_at ? new Date(asset.created_at).toLocaleDateString() : '--'}</td>
                    <td>
                      <div className="action-group">
                        <button className="btn btn-ghost btn-small" onClick={() => setSelectedAsset(asset)}>View matches</button>
                        <button className="btn btn-danger btn-small" onClick={() => handleDelete(asset.id, asset.name)}>Delete</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : null}
        </div>
      </div>

      {selectedAsset ? <AssetCveDrawer asset={selectedAsset} onClose={() => setSelectedAsset(null)} /> : null}
    </div>
  );
}

function AssetCveDrawer({ asset, onClose }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get(`/assets/${asset.id}/cves`)
      .then((response) => { setData(response); setLoading(false); })
      .catch(() => setLoading(false));
  }, [asset.id]);

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <div className="drawer">
        <div className="drawer-header">
          <div>
            <div className="eyebrow">Asset match view</div>
            <h2>{asset.name}</h2>
            <div className="muted-copy mono">{asset.cpe || 'No CPE string configured'}</div>
          </div>
          <button className="drawer-close" onClick={onClose}>Close</button>
        </div>

        <div className="drawer-section">
          <h3>Vulnerability matches {data?.cves?.length !== undefined ? `(${data.cves.length})` : ''}</h3>

          {loading ? <div className="spinner" /> : null}
          {!loading && data?.cves?.length === 0 ? (
            <div className="empty-state compact-empty-state">
              <div className="empty-icon">No matches</div>
              No known CVEs in the database currently match this asset CPE.
            </div>
          ) : null}

          {!loading && data?.cves?.length > 0 ? (
            <div className="ioc-list asset-match-list">
              {data.cves.map((cve) => (
                <div key={cve.cve_id} className="ioc-item asset-match-item">
                  <div className="asset-match-top">
                    <strong className="cve-id">{cve.cve_id}</strong>
                    <div className="drawer-badges">
                      {cve.cvss_v3_severity ? <span className={`badge badge-${cve.cvss_v3_severity}`}>{cve.cvss_v3_severity} {cve.cvss_v3_score}</span> : null}
                      {cve.is_kev ? <span className="badge badge-kev">CISA KEV</span> : null}
                    </div>
                  </div>
                  <span className="description-cell">{cve.description}</span>
                </div>
              ))}
            </div>
          ) : null}
        </div>
      </div>
    </>
  );
}
