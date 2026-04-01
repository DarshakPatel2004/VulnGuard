/* ═══════════════════════════════════════════════════════════
   VulnTracker – Precision Threat Intelligence Platform
Made by Darshak Patel
   [dp-watermark-2026]
   ═══════════════════════════════════════════════════════════ */

// Shared API utility â€” stores basic auth credentials in sessionStorage
// and attaches them to every request with a simple Authorization header.

const API_BASE = '';  // proxied via Vite config

function getAuthHeader() {
  const username = sessionStorage.getItem('vt_user') || '';
  const password = sessionStorage.getItem('vt_pass') || '';
  return 'Basic ' + btoa(`${username}:${password}`);
}

async function apiFetch(path, options = {}) {
  const resp = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': getAuthHeader(),
      ...(options.headers || {}),
    },
  });

  if (resp.status === 401) {
    // Clear stored credentials and force re-login
    sessionStorage.clear();
    window.location.reload();
    return null;
  }

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`${resp.status}: ${text}`);
  }

  const contentType = resp.headers.get('content-type') || '';
  if (contentType.includes('application/json')) return resp.json();
  return resp.text();
}

export const api = {
  get: (path) => apiFetch(path),
  post: (path, body) => apiFetch(path, { method: 'POST', body: JSON.stringify(body) }),
  delete: (path) => apiFetch(path, { method: 'DELETE' }),

  // Auth helpers
  setCredentials(username, password) {
    sessionStorage.setItem('vt_user', username);
    sessionStorage.setItem('vt_pass', password);
  },
  clearCredentials() {
    sessionStorage.clear();
  },
  isLoggedIn() {
    return !!sessionStorage.getItem('vt_user');
  },

  // Verify credentials against /auth/verify
  async verifyLogin(username, password) {
    const resp = await fetch('/auth/verify', {
      headers: { 'Authorization': 'Basic ' + btoa(`${username}:${password}`) }
    });
    return resp.ok;
  }
};

