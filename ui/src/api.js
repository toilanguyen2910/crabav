/**
 * CrabAV API Service — gọi HTTP backend trực tiếp.
 * Dùng thay cho window.electronAPI khi chạy trên browser thường.
 */

const API_BASE = 'http://127.0.0.1:19527';

async function request(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (body) opts.body = JSON.stringify(body);

  const res = await fetch(`${API_BASE}${path}`, opts);
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`API ${method} ${path} failed (${res.status}): ${err}`);
  }
  return res.json();
}

const api = {
  // ── System ──
  getSystemStatus: ()       => request('GET', '/api/status'),

  // ── Scans ──
  startScan: (scanType, target) => request('POST', '/api/scan/start', {
    target: target || 'C:\\Users\\taipa\\Downloads',
    scan_type: scanType || 'quick',
  }),
  getScanStatus: (scanId)   => request('GET', `/api/scan/status${scanId ? `?scan_id=${scanId}` : ''}`),
  stopScan: ()              => request('POST', '/api/scan/stop'),
  getScanHistory: ()        => request('GET', '/api/scans/history'),

  // ── Threats ──
  getThreats: ()            => request('GET', '/api/threats'),
  getThreatDetail: (id)     => request('GET', `/api/threats/${id}`),
  approveAction: (threatId, action) => request('POST', '/api/threats/approve', {
    threat_id: threatId,
    action: action,
  }),

  // ── Agents ──
  getAgents: ()             => request('GET', '/api/agents'),

  // ── Settings ──
  getSettings: ()           => request('GET', '/api/settings'),
  updateSetting: (key, value) => request('POST', '/api/settings', { key, value }),
  updateSettings: (settings) => {
    // Batch update all settings
    const promises = Object.entries(settings).map(([key, value]) =>
      request('POST', '/api/settings', { key, value })
    );
    return Promise.all(promises);
  },
};

export default api;
