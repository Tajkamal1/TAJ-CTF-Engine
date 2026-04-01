/**
 * TAJ-CTF-Engine · api.js
 * Backend API communication layer
 */

const API_BASE = window.location.origin;

async function apiScanModule(url, module, options = {}) {
  const resp = await fetch(`${API_BASE}/api/scan_module`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, module, options }),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ error: resp.statusText }));
    throw new Error(err.error || `HTTP ${resp.status}`);
  }
  return resp.json();
}

async function apiScanAll(url, modules, options = {}) {
  const resp = await fetch(`${API_BASE}/api/scan`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, modules, options }),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ error: resp.statusText }));
    throw new Error(err.error || `HTTP ${resp.status}`);
  }
  return resp.json();
}

async function apiGetPayloads(module) {
  const resp = await fetch(`${API_BASE}/api/payloads/${module}`);
  if (!resp.ok) return null;
  return resp.json();
}
