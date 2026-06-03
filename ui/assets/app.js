/* ── SME-Shield frontend ─────────────────────────────────────────────────── */
'use strict';

// ── State ─────────────────────────────────────────────────────────────────────
const state = {
  ws:          null,
  connected:   false,
  scanning:    false,
  lastScanID:  null,
  devices:     [],
};

// ── WebSocket ─────────────────────────────────────────────────────────────────
function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const url   = `${proto}://${location.host}/ws`;

  state.ws = new WebSocket(url);

  state.ws.onopen = () => {
    state.connected = true;
    setWSStatus(true);
  };

  state.ws.onclose = () => {
    state.connected = false;
    setWSStatus(false);
    // Reconnect after 3 seconds.
    setTimeout(connectWS, 3000);
  };

  state.ws.onerror = () => {
    state.connected = false;
    setWSStatus(false);
  };

  state.ws.onmessage = (evt) => {
    // The writePump may batch multiple JSON objects separated by newlines.
    evt.data.split('\n').forEach(chunk => {
      chunk = chunk.trim();
      if (!chunk) return;
      try {
        handleWSMessage(JSON.parse(chunk));
      } catch(e) {
        console.warn('[ws] parse error', e, chunk);
      }
    });
  };
}

function handleWSMessage(msg) {
  switch (msg.type) {
    case 'SCAN_PROGRESS':
      onProgress(msg.payload);
      break;
    case 'PORT_FOUND':
      onPortFound(msg.payload);
      break;
    case 'SCAN_COMPLETE':
      onScanComplete(msg.payload.result);
      break;
    case 'SCAN_ERROR':
      onScanError(msg.payload.message);
      break;
    case 'DEVICES_FOUND':
      onDevicesFound(msg.payload);
      break;
    default:
      console.log('[ws] unknown message type:', msg.type);
  }
}

function setWSStatus(connected) {
  const wrap = document.getElementById('ws-status');
  const dot  = wrap.querySelector('.status-dot');
  const text = wrap.querySelector('span:last-child');
  if (connected) {
    dot.className  = 'status-dot bg-green-400';
    text.textContent = 'Connected';
    text.className = 'text-slate-400';
  } else {
    dot.className  = 'status-dot bg-red-400 animate-pulse';
    text.textContent = 'Reconnecting...';
    text.className = 'text-slate-500';
  }
}

// ── Network Discovery ─────────────────────────────────────────────────────────
async function detectSubnet() {
  const btn = document.getElementById('btn-detect');
  btn.disabled = true;
  btn.textContent = 'Detecting...';

  try {
    const res  = await fetch('/api/subnet');
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    document.getElementById('subnet-input').value = data.subnet;
    toast('Subnet detected: ' + data.subnet, 'info');
  } catch (err) {
    toast('Could not detect subnet: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Detect Network';
  }
}

async function discoverDevices() {
  const subnet = document.getElementById('subnet-input').value.trim();
  if (!subnet) {
    toast('Enter a subnet or click Detect Network first', 'error');
    return;
  }

  // Clear previous device list.
  document.getElementById('device-grid').classList.add('hidden');
  document.getElementById('device-list').innerHTML = '';
  state.devices = [];

  try {
    await fetch('/api/discover', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subnet }),
    });
    toast('Discovery started — devices will appear as found', 'info');
  } catch (err) {
    toast('Discovery request failed: ' + err.message, 'error');
  }
}

function onDevicesFound(devices) {
  state.devices = devices || [];
  const grid  = document.getElementById('device-grid');
  const list  = document.getElementById('device-list');
  const count = document.getElementById('device-count');

  list.innerHTML = '';
  count.textContent = state.devices.length;

  if (state.devices.length === 0) {
    list.innerHTML = '<p class="text-slate-500 text-sm col-span-4">No active devices found on this subnet.</p>';
  } else {
    state.devices.forEach(d => {
      const card = document.createElement('div');
      card.className = 'device-card';
      card.innerHTML = `
        <span class="device-ip">${escHtml(d.ip)}</span>
        <span class="device-hostname">${escHtml(d.hostname || 'Unknown host')}</span>
      `;
      card.addEventListener('click', () => {
        document.getElementById('audit-ip').value = d.ip;
        showView('dashboard');
        toast('IP set to ' + d.ip + ' — click Start Audit', 'info');
      });
      list.appendChild(card);
    });
  }

  grid.classList.remove('hidden');
}

// ── Audit ─────────────────────────────────────────────────────────────────────
async function startAudit() {
  const ip = document.getElementById('audit-ip').value.trim();
  if (!ip) {
    toast('Enter an IP address to audit', 'error');
    return;
  }
  if (!isValidIP(ip)) {
    toast('Enter a valid IPv4 address', 'error');
    return;
  }
  if (state.scanning) {
    toast('An audit is already running', 'error');
    return;
  }

  // Reset UI for new scan.
  resetAuditUI();
  state.scanning = true;
  state.lastScanID = null;

  const btn = document.getElementById('btn-audit');
  btn.disabled = true;
  btn.textContent = 'Scanning...';

  show('progress-wrap');
  setProgress(2, 'Starting audit on ' + ip + '...');

  try {
    const res  = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip }),
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
  } catch (err) {
    onScanError(err.message);
  }
}

function onProgress(payload) {
  setProgress(payload.percent, payload.message);
}

function onPortFound(payload) {
  show('live-feed-wrap');
  appendFeedLine(payload);
}

function onScanComplete(result) {
  state.scanning  = false;
  state.lastScanID = result.id;

  setProgress(100, 'Audit complete');

  const btn = document.getElementById('btn-audit');
  btn.disabled = false;
  btn.textContent = 'Start Audit';

  renderResults(result);
  toast('Audit complete — score: ' + result.risk_score, result.risk_score >= 70 ? 'success' : 'error');
}

function onScanError(message) {
  state.scanning = false;

  const btn = document.getElementById('btn-audit');
  btn.disabled = false;
  btn.textContent = 'Start Audit';

  setProgress(0, 'Audit failed');
  hide('progress-wrap');
  toast('Error: ' + message, 'error');
}

// ── Progress ──────────────────────────────────────────────────────────────────
function setProgress(pct, msg) {
  document.getElementById('progress-bar').style.width = pct + '%';
  document.getElementById('progress-pct').textContent  = pct + '%';
  document.getElementById('progress-msg').textContent  = msg;
}

// ── Live feed ─────────────────────────────────────────────────────────────────
function appendFeedLine(p) {
  const feed = document.getElementById('live-feed');
  const now  = new Date().toLocaleTimeString('en-GB', { hour12: false });
  const cveText = p.cve_count > 0 ? `${p.cve_count} CVE${p.cve_count > 1 ? 's' : ''}` : '';

  const line = document.createElement('div');
  line.className = 'feed-line';
  line.innerHTML = `
    <span class="feed-time">${now}</span>
    <span class="feed-port">${p.port}/tcp</span>
    <span class="feed-svc">${escHtml(p.service)}</span>
    <span class="feed-ver">${escHtml(p.product)} ${escHtml(p.version)}</span>
    ${cveText ? `<span class="feed-cve">${cveText}</span>` : ''}
  `;
  feed.appendChild(line);
  feed.scrollTop = feed.scrollHeight;
}

// ── Results rendering ─────────────────────────────────────────────────────────
function renderResults(result) {
  show('results-wrap');

  // Score ring
  const score = result.risk_score;
  const el    = document.getElementById('score-ring');
  const color = scoreColor(score);
  el.style.borderColor = color;
  document.getElementById('score-value').textContent = score;
  document.getElementById('score-label').textContent = result.summary.label;

  // Target info
  document.getElementById('result-ip').textContent       = result.ip;
  document.getElementById('result-hostname').textContent = result.hostname || '';

  // CVE counters
  document.getElementById('count-critical').textContent = result.summary.critical;
  document.getElementById('count-high').textContent     = result.summary.high;
  document.getElementById('count-medium').textContent   = result.summary.medium;
  document.getElementById('count-low').textContent      = result.summary.low;

  // Port count badge
  const portCount = (result.open_ports || []).length;
  document.getElementById('port-count-badge').textContent = portCount + ' port' + (portCount !== 1 ? 's' : '');

  // PDF report button
  if (result.id) {
    show('btn-report');
  }

  // Port table
  renderPortTable(result.open_ports || []);
}

function renderPortTable(ports) {
  const tbody = document.getElementById('port-table-body');
  tbody.innerHTML = '';

  if (ports.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="td text-center text-slate-500 py-10">
          No open ports found on this host.
        </td>
      </tr>`;
    return;
  }

  ports.forEach(p => {
    const cves    = p.vulnerabilities || [];
    const topCVE  = cves[0];
    const badgeCls = cveBadgeClass(cves.length);

    // CVE list cell (show up to 3)
    const cveHTML = cves.length === 0
      ? '<span class="badge badge-clean">Clean</span>'
      : `<div class="cve-list">
          ${cves.slice(0, 3).map(c => `
            <div class="cve-item">
              <span class="cve-id">${escHtml(c.id)}</span>
              <span class="cve-score ${severityTextClass(c.severity)}">
                ${c.score.toFixed(1)} ${c.severity}
              </span>
            </div>`).join('')}
          ${cves.length > 3 ? `<span class="text-slate-600 text-xs">+${cves.length - 3} more</span>` : ''}
        </div>`;

    // Fix text (from top CVE)
    const fixHTML = topCVE && topCVE.fix
      ? `<p class="fix-text">${escHtml(topCVE.fix)}</p>`
      : '<span class="text-slate-600 text-xs">—</span>';

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="td font-mono text-blue-400 font-semibold">${p.number}</td>
      <td class="td">${escHtml(p.service)}</td>
      <td class="td">
        <span class="text-white font-medium">${escHtml(p.service_info.product)}</span>
        <span class="text-slate-500 text-xs ml-1">${escHtml(p.service_info.version)}</span>
      </td>
      <td class="td">
        <span class="badge ${badgeCls}">${cves.length}</span>
        ${cveHTML}
      </td>
      <td class="td text-xs">${topCVE ? escHtml(topCVE.description.slice(0, 100)) + '…' : '<span class="text-slate-600">No known CVEs</span>'}</td>
      <td class="td">${fixHTML}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ── History view ──────────────────────────────────────────────────────────────
async function loadHistory() {
  const tbody = document.getElementById('history-table-body');
  tbody.innerHTML = '<tr><td colspan="8" class="td text-center text-slate-500 py-10">Loading...</td></tr>';

  try {
    const res  = await fetch('/api/history?limit=50');
    const data = await res.json();
    if (data.error) throw new Error(data.error);

    if (!data.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="td text-center text-slate-500 py-12">No scans yet. Run your first audit from the Dashboard.</td></tr>';
      return;
    }

    tbody.innerHTML = '';
    data.forEach(row => {
      const tr  = document.createElement('tr');
      const color = scoreColor(row.risk_score);
      const date  = new Date(row.scan_time).toLocaleString();

      tr.innerHTML = `
        <td class="td text-slate-500 font-mono text-xs">SCN-${String(row.id).padStart(4,'0')}</td>
        <td class="td font-mono text-blue-400 font-semibold">${escHtml(row.ip)}</td>
        <td class="td text-slate-400 text-xs">${escHtml(row.hostname || '—')}</td>
        <td class="td">
          <span class="font-bold text-base" style="color:${color}">${row.risk_score}</span>
          <span class="text-xs text-slate-500 ml-1">${scoreLabel(row.risk_score)}</span>
        </td>
        <td class="td text-slate-300">${row.port_count}</td>
        <td class="td">
          <span class="${row.cve_count > 0 ? 'text-red-400' : 'text-green-400'} font-medium">
            ${row.cve_count}
          </span>
        </td>
        <td class="td text-slate-400 text-xs whitespace-nowrap">${date}</td>
        <td class="td">
          <div class="flex gap-2">
            <button onclick="reAudit('${escHtml(row.ip)}')"
              class="btn-secondary text-xs px-3 py-1">Re-audit</button>
            <button onclick="deleteHistory(${row.id}, this)"
              class="btn-ghost text-xs px-3 py-1 text-red-400 hover:text-red-300">Delete</button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="td text-center text-red-400 py-10">Error: ${escHtml(err.message)}</td></tr>`;
  }
}

async function deleteHistory(id, btn) {
  if (!confirm('Delete this scan record?')) return;
  btn.disabled = true;
  try {
    const res  = await fetch(`/api/history/${id}`, { method: 'DELETE' });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    toast('Scan record deleted', 'success');
    loadHistory();
  } catch (err) {
    toast('Delete failed: ' + err.message, 'error');
    btn.disabled = false;
  }
}

function reAudit(ip) {
  document.getElementById('audit-ip').value = ip;
  showView('dashboard');
  toast('IP set to ' + ip + ' — click Start Audit', 'info');
}

async function downloadReport() {
  if (!state.lastScanID) return;
  window.open(`/api/report/${state.lastScanID}`, '_blank');
}

// ── View switching ────────────────────────────────────────────────────────────
function showView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
  document.getElementById('view-' + name).classList.remove('hidden');

  document.querySelectorAll('.nav-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.view === name);
  });

  if (name === 'history') loadHistory();
}

function resetAuditUI() {
  hide('results-wrap');
  hide('live-feed-wrap');
  hide('btn-report');
  document.getElementById('live-feed').innerHTML = '';
  setProgress(0, '');
}

function clearResults() {
  hide('results-wrap');
  hide('progress-wrap');
  hide('live-feed-wrap');
  document.getElementById('live-feed').innerHTML = '';
  state.lastScanID = null;
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function toast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = message;
  el.addEventListener('click', () => el.remove());
  container.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function show(id) { document.getElementById(id).classList.remove('hidden'); }
function hide(id) { document.getElementById(id).classList.add('hidden'); }

function escHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function isValidIP(ip) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) &&
    ip.split('.').every(n => +n >= 0 && +n <= 255);
}

function scoreColor(score) {
  if (score >= 80) return '#22C55E';
  if (score >= 60) return '#F59E0B';
  if (score >= 30) return '#F97316';
  return '#EF4444';
}

function scoreLabel(score) {
  if (score >= 80) return 'Secure';
  if (score >= 60) return 'Moderate';
  if (score >= 30) return 'High Risk';
  return 'Critical';
}

function cveBadgeClass(count) {
  if (count === 0) return 'badge-clean';
  if (count <= 2)  return 'badge-low';
  if (count <= 5)  return 'badge-medium';
  return 'badge-high';
}

function severityTextClass(sev) {
  switch ((sev || '').toUpperCase()) {
    case 'CRITICAL': return 'text-red-400';
    case 'HIGH':     return 'text-orange-400';
    case 'MEDIUM':   return 'text-amber-400';
    default:         return 'text-green-400';
  }
}

// ── Boot ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  connectWS();
  showView('dashboard');
});