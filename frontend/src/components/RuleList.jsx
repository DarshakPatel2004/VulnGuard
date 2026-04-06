/*
   VulnForge - Precision Threat Intelligence Platform
   Made by Darshak Patel
   [dp-watermark-2026]
*/

import React, { useState } from 'react';
import { api } from '../api.js';

const TABS = [
  { id: 'snort', label: 'Snort / Suricata', endpoint: '/rules/snort', description: 'Network-facing block and detection rules.' },
  { id: 'sigma', label: 'Sigma YAML', endpoint: '/rules/sigma', description: 'Portable SIEM detections for analytics pipelines.' },
  { id: 'json', label: 'JSON Alerts', endpoint: '/rules/json', description: 'Machine-readable alert feed for integrations.' },
];

export default function RuleList({ onToast }) {
  const [activeTab, setActiveTab] = useState('snort');
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);

  async function loadRules(tabId = activeTab) {
    setLoading(true);
    const tab = TABS.find((item) => item.id === tabId);
    try {
      const result = await api.get(tab.endpoint);
      setContent(typeof result === 'object' ? JSON.stringify(result, null, 2) : result || '# No rules generated yet.');
    } catch (e) {
      onToast(`Failed to load rules: ${e.message}`, 'error');
      setContent('# Error loading rules.');
    }
    setLoading(false);
  }

  function handleTabChange(tabId) {
    setActiveTab(tabId);
    setContent('');
  }

  function downloadRules() {
    const tab = TABS.find((item) => item.id === activeTab);
    window.open(`${tab.endpoint}/download`, '_blank');
  }

  async function regenerateAll() {
    setGenerating(true);
    try {
      await api.get('/fetch/all');
      onToast('Rule regeneration started in the background.', 'success');
    } catch (e) {
      onToast(`Failed to start regeneration: ${e.message}`, 'error');
    }
    setGenerating(false);
  }

  const active = TABS.find((item) => item.id === activeTab);

  return (
    <div className="page-stack fade-in">
      <section className="hero-panel compact-hero">
        <div>
          <div className="eyebrow">Detection outputs</div>
          <h1 className="hero-title">Security rules</h1>
          <p className="hero-copy">Inspect generated detections, refresh them on demand, and export the format your tooling needs.</p>
        </div>
        <div className="hero-actions">
          <button id="btn-regenerate-rules" className="btn btn-primary" onClick={regenerateAll} disabled={generating}>
            {generating ? 'Starting job...' : 'Regenerate all'}
          </button>
          <button id="btn-download-rules" className="btn btn-ghost" onClick={downloadRules} disabled={!content}>Download current file</button>
        </div>
      </section>

      <div className="rule-card-grid">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={`rule-format-card ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => handleTabChange(tab.id)}
          >
            <span className="rule-format-label">{tab.label}</span>
            <span className="rule-format-copy">{tab.description}</span>
          </button>
        ))}
      </div>

      <div className="card">
        <div className="card-header horizontal-between">
          <div>
            <div className="eyebrow">Active format</div>
            <h2>{active.label}</h2>
          </div>
          <button className="btn btn-ghost" onClick={() => loadRules(activeTab)}>Load output</button>
        </div>
        <div className="card-body">
          <p className="section-note">{active.description}</p>
        </div>
      </div>

      <div className="card">
        <div className="card-header horizontal-between">
          <div>
            <div className="eyebrow">Preview</div>
            <h2>Generated output</h2>
          </div>
          <span className="section-note">{content ? `${content.split('\n').length} lines` : 'Not loaded yet'}</span>
        </div>
        <div className="card-body rule-panel-body">
          {loading ? <div className="spinner" /> : null}
          {!loading && !content ? (
            <div className="empty-state">
              <div className="empty-icon">Rule preview</div>
              Load the active format to inspect the generated content.
            </div>
          ) : null}
          {!loading && content ? (
            <div className="rule-output">
              <pre>{content}</pre>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
