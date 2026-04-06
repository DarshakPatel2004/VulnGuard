/*
   VulnForge - Precision Threat Intelligence Platform
   Made by Darshak Patel
   [dp-watermark-2026]
*/

import React, { useState } from 'react';
import { api } from '../api.js';

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setError('');

    const ok = await api.verifyLogin(username, password);
    if (ok) {
      api.setCredentials(username, password);
      onLogin();
    } else {
      setError('Invalid username or password. Please try again.');
    }
    setLoading(false);
  }

  return (
    <div className="login-page">
      <div className="login-layout">
        <section className="login-aside">
          <div className="eyebrow">Threat visibility</div>
          <h1>Operate your local vulnerability command center.</h1>
          <p>
            Track high-risk CVEs, monitor feed health, map assets to exposure, and export fresh detection rules from one focused workspace.
          </p>
          <div className="login-feature-list">
            <div className="login-feature-card">
              <strong>Unified feeds</strong>
              <span>NVD, CISA KEV, and OTX in one place.</span>
            </div>
            <div className="login-feature-card">
              <strong>Actionable triage</strong>
              <span>Filter by severity, KEV, and asset relevance.</span>
            </div>
            <div className="login-feature-card">
              <strong>Detection ready</strong>
              <span>Generate Snort, Sigma, and JSON outputs on demand.</span>
            </div>
          </div>
        </section>

        <div className="login-box">
          <div className="login-kicker">Secure access</div>
          <h2>Sign in to VulnForge</h2>
          <p className="login-sub">Use the credentials configured in your local environment to enter the workspace.</p>

          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label htmlFor="username">Username</label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
                required
                autoFocus
              />
            </div>
            <div className="form-group">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                required
              />
            </div>

            {error ? <div className="login-error">{error}</div> : null}

            <button id="login-submit" type="submit" className="login-btn" disabled={loading}>
              {loading ? 'Signing in...' : 'Enter workspace'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
