'use strict';

const state = {
  ws: null, connected: false,
  scanning: false, lastScanID: null,
};

/* ── WebSocket ──────────────────────────────────────────────────── */
function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  state.ws = new WebSocket(`${proto}://${location.host}/ws`);
  state.ws.onopen  = () => { state.connected = true;  setWSStatus(true);  };
  state.ws.onclose = () => { state.connected = false; setWSStatus(false); setTimeout(connectWS, 3000); };
  state.ws.onerror = () => { state.connected = false; setWSStatus(false); };
  state.ws.onmessage = (evt) => {
    evt.data.split('\n').forEach(chunk => {
      chunk = chunk.trim();
      if (!chunk) return;
      try { handleWSMessage(JSON.parse(chunk)); }
      catch(e) { console.warn('[ws] parse error', e); }
    });
  };
}

function handleWSMessage(msg) {
  switch (msg.type) {
    case 'SCAN_PROGRESS': onProgress(msg.payload);            break;
    case 'PORT_FOUND':    onPortFound(msg.payload);           break;
    case 'SCAN_COMPLETE': onScanComplete(msg.payload.result); break;
    case 'SCAN_ERROR':    onScanError(msg.payload.message);   break;
    case 'DEVICES_FOUND': onDevicesFound(msg.payload);        break;
  }
}

function setWSStatus(connected) {
  const dot  = document.getElementById('ws-dot');
  const text = document.getElementById('ws-text');
  if (connected) {
    dot.className  = 'ws-dot connected';
    text.textContent = 'Connected';
  } else {
    dot.className  = 'ws-dot pulsing';
    text.textContent = 'Reconnecting';
  }
}

/* ── Discovery ──────────────────────────────────────────────────── */
async function detectSubnet() {
  const btn = document.getElementById('btn-detect');
  btn.disabled = true; btn.textContent = 'Detecting...';
  try {
    const res  = await fetch('/api/subnet');
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    document.getElementById('subnet-input').value = data.subnet;
    toast('Subnet detected: ' + data.subnet, 'info');
  } catch (err) {
    toast('Detection failed: ' + err.message, 'error');
  } finally {
    btn.disabled = false; btn.textContent = 'Auto-detect subnet';
  }
}

async function discoverDevices() {
  const subnet = document.getElementById('subnet-input').value.trim();
  if (!subnet) { toast('Enter a subnet first', 'error'); return; }
  document.getElementById('device-grid').classList.add('hidden');
  document.getElementById('device-list').innerHTML = '';
  try {
    await fetch('/api/discover', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ subnet }),
    });
    toast('Discovery started...', 'info');
  } catch (err) {
    toast('Discovery failed: ' + err.message, 'error');
  }
}

function onDevicesFound(devices) {
  const list  = document.getElementById('device-list');
  const grid  = document.getElementById('device-grid');
  const count = document.getElementById('device-count');
  list.innerHTML = '';
  count.textContent = (devices || []).length;

  if (!devices || !devices.length) {
    list.innerHTML = '<p style="font-size:12px;color:var(--stone)">No active devices found.</p>';
  } else {
    devices.forEach(d => {
      const card = document.createElement('div');
      card.className = 'device-card';
      card.setAttribute('role','button');
      card.setAttribute('tabindex','0');
      card.setAttribute('aria-label','Audit ' + d.ip);
      card.innerHTML =
        `<div class="device-ip">${escHtml(d.ip)}</div>` +
        `<div class="device-host">${escHtml(d.hostname || 'Unknown host')}</div>`;
      const pick = () => {
        document.getElementById('audit-ip').value = d.ip;
        toast('IP set — click Start audit', 'info');
      };
      card.addEventListener('click', pick);
      card.addEventListener('keydown', e => e.key === 'Enter' && pick());
      list.appendChild(card);
    });
  }
  grid.classList.remove('hidden');
}

/* ── Audit ──────────────────────────────────────────────────────── */
async function startAudit() {
  const ip = document.getElementById('audit-ip').value.trim();
  if (!ip)            { toast('Enter an IP address', 'error'); return; }
  if (!isValidIP(ip)) { toast('Enter a valid IPv4 address', 'error'); return; }
  if (state.scanning) { toast('Audit already running', 'error'); return; }

  resetAuditUI();
  state.scanning   = true;
  state.lastScanID = null;

  const btn = document.getElementById('btn-audit');
  btn.disabled = true; btn.textContent = 'Scanning...';

  show('progress-wrap');
  setProgress(2, 'Starting audit on ' + ip);

  try {
    const res  = await fetch('/api/scan', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ ip }),
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
  } catch (err) {
    onScanError(err.message);
  }
}

function onProgress(p) { setProgress(p.percent, p.message); }

function onPortFound(p) {
  show('live-feed-wrap');
  const feed = document.getElementById('live-feed');
  const now  = new Date().toLocaleTimeString('en-GB', {hour12:false});
  const line = document.createElement('div');
  line.className = 'feed-line';
  line.innerHTML =
    `<span class="feed-time">${now}</span>` +
    `<span class="feed-port">${p.port}/tcp</span>` +
    `<span class="feed-svc">${escHtml(p.service)}</span>` +
    `<span class="feed-ver">${escHtml(p.product)} ${escHtml(p.version)}</span>` +
    (p.cve_count > 0
      ? `<span class="feed-cve">${p.cve_count} CVE${p.cve_count > 1 ? 's' : ''}</span>`
      : '');
  feed.appendChild(line);
  feed.scrollTop = feed.scrollHeight;
}

function onScanComplete(result) {
  state.scanning   = false;
  state.lastScanID = result.id;
  setProgress(100, 'Audit complete');
  const btn = document.getElementById('btn-audit');
  btn.disabled = false; btn.textContent = 'Start audit';
  renderResults(result);
  const ok = result.risk_score >= 70;
  toast('Score: ' + result.risk_score + '/100 — ' + result.summary.label,
    ok ? 'success' : 'error');
}

function onScanError(msg) {
  state.scanning = false;
  const btn = document.getElementById('btn-audit');
  btn.disabled = false; btn.textContent = 'Start audit';
  setProgress(0, '');
  hide('progress-wrap');
  toast('Error: ' + msg, 'error');
}

function setProgress(pct, msg) {
  document.getElementById('progress-bar').style.width = pct + '%';
  document.getElementById('progress-pct').textContent  = pct + '%';
  document.getElementById('progress-msg').textContent  = msg;
}

/* ── Results ────────────────────────────────────────────────────── */
function renderResults(result) {
  show('results-wrap');

  const score = result.risk_score;
  const ring  = document.getElementById('score-ring');
  ring.className = 'score-circle ' + scoreRingClass(score);
  document.getElementById('score-value').textContent = score;
  document.getElementById('score-label').textContent = result.summary.label;
  document.getElementById('result-ip').textContent       = result.ip;
  document.getElementById('result-hostname').textContent = result.hostname || '';
  document.getElementById('count-critical').textContent  = result.summary.critical;
  document.getElementById('count-high').textContent      = result.summary.high;
  document.getElementById('count-medium').textContent    = result.summary.medium;
  document.getElementById('count-low').textContent       = result.summary.low;

  const pc = (result.open_ports || []).length;
  document.getElementById('port-count-badge').textContent =
    pc + ' port' + (pc !== 1 ? 's' : '');

  if (result.id) show('btn-report');
  renderPortTable(result.open_ports || []);
}

function renderPortTable(ports) {
  const tbody = document.getElementById('port-table-body');
  tbody.innerHTML = '';

  if (!ports.length) {
    tbody.innerHTML =
      `<tr><td colspan="6"
        style="text-align:center;color:var(--stone);padding:40px 0">
        No open ports found on this host.
      </td></tr>`;
    return;
  }

  ports.forEach(p => {
    const cves   = p.vulnerabilities || [];
    const topCVE = cves[0];
    const hasCVE = cves.length > 0;

    const cveCell = !hasCVE
      ? '<span style="font-size:11px;color:var(--stone)">None</span>'
      : `<div class="cve-list">
          ${cves.slice(0,3).map(c =>
            `<div class="cve-item">
              <span class="cve-id">${escHtml(c.id)}</span>
              <span style="color:var(--stone);margin-left:4px">${c.score.toFixed(1)}</span>
            </div>`).join('')}
          ${cves.length > 3
            ? `<span style="font-size:10px;color:var(--stone)">+${cves.length-3} more</span>`
            : ''}
        </div>`;

    const tr = document.createElement('tr');
    tr.innerHTML =
      `<td><span class="port-num">${p.number}</span></td>
       <td style="color:var(--cream);font-weight:500">${escHtml(p.service)}</td>
       <td>
         <span style="color:var(--cream)">${escHtml(p.service_info.product)}</span>
         <span style="color:var(--stone);font-size:11px;margin-left:4px">
           ${escHtml(p.service_info.version)}</span>
       </td>
       <td>
         <span class="cve-badge ${hasCVE ? 'has-cves' : ''}">${cves.length}</span>
         ${cveCell}
       </td>
       <td style="font-size:11px;color:var(--stone);max-width:180px">
         ${topCVE
           ? escHtml(topCVE.description.slice(0,90)) + '…'
           : '<span style="color:var(--stone)">—</span>'}
       </td>
       <td>${topCVE && topCVE.fix
         ? `<p class="fix-text">${escHtml(topCVE.fix)}</p>`
         : '<span style="color:var(--stone)">—</span>'}
       </td>`;
    tbody.appendChild(tr);
  });
}

/* ── History ────────────────────────────────────────────────────── */
async function loadHistory() {
  const tbody = document.getElementById('history-table-body');
  tbody.innerHTML =
    `<tr><td colspan="8"
      style="text-align:center;color:var(--stone);padding:40px 0">
      Loading...
    </td></tr>`;

  try {
    const res  = await fetch('/api/history?limit=50');
    const data = await res.json();
    if (data.error) throw new Error(data.error);

    if (!data.length) {
      tbody.innerHTML =
        `<tr><td colspan="8"
          style="text-align:center;color:var(--stone);padding:48px 0">
          No scans yet — run your first audit from the Scan tab.
        </td></tr>`;
      return;
    }

    tbody.innerHTML = '';
    data.forEach(row => {
      const tr   = document.createElement('tr');
      const cls  = scoreRingClass(row.risk_score).replace('ring-','');
      const date = new Date(row.scan_time).toLocaleString();
      const scoreColor = {
        secure:'var(--green)', moderate:'var(--amber)',
        high:'var(--orange)',  critical:'var(--red)'
      }[cls] || 'var(--stone)';

      tr.innerHTML =
        `<td style="font-family:var(--mono);font-size:11px;color:var(--stone)">
           SCN-${String(row.id).padStart(4,'0')}
         </td>
         <td style="font-family:var(--mono);color:var(--mint);font-size:12px">
           ${escHtml(row.ip)}
         </td>
         <td style="font-size:12px;color:var(--stone)">${escHtml(row.hostname || '—')}</td>
         <td>
           <span style="font-size:20px;font-weight:300;color:${scoreColor}">${row.risk_score}</span>
           <span style="font-size:11px;color:var(--stone);margin-left:4px">${scoreLabelText(cls)}</span>
         </td>
         <td style="color:var(--cream)">${row.port_count}</td>
         <td style="color:${row.cve_count > 0 ? 'var(--red)' : 'var(--green)'};font-weight:500">
           ${row.cve_count}
         </td>
         <td style="font-size:11px;color:var(--stone);white-space:nowrap">${date}</td>
         <td>
           <div style="display:flex;gap:6px">
             <button onclick="reAudit('${escHtml(row.ip)}')"
               class="btn btn-iris" style="font-size:11px;padding:5px 12px">
               Re-audit
             </button>
             <button onclick="deleteHistory(${row.id},this)"
               class="btn btn-danger" style="font-size:11px;padding:5px 12px">
               Delete
             </button>
           </div>
         </td>`;
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML =
      `<tr><td colspan="8"
        style="text-align:center;color:var(--red);padding:40px 0">
        Error: ${escHtml(err.message)}
      </td></tr>`;
  }
}

async function deleteHistory(id, btn) {
  if (!confirm('Delete this scan record?')) return;
  btn.disabled = true;
  try {
    const res  = await fetch(`/api/history/${id}`, {method:'DELETE'});
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    toast('Scan deleted', 'success');
    loadHistory();
  } catch (err) {
    toast('Delete failed: ' + err.message, 'error');
    btn.disabled = false;
  }
}

function reAudit(ip) {
  document.getElementById('audit-ip').value = ip;
  showView('dashboard');
  toast('IP set — click Start audit', 'info');
}

async function downloadReport() {
  if (!state.lastScanID) return;
  window.open(`/api/report/${state.lastScanID}`, '_blank');
}

/* ── View switching ─────────────────────────────────────────────── */
function showView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
  document.getElementById('view-' + name).classList.remove('hidden');
  document.querySelectorAll('.nav-tab').forEach(b => {
    const active = b.dataset.view === name;
    b.classList.toggle('active', active);
    b.setAttribute('aria-selected', active);
  });
  if (name === 'history') loadHistory();
}

function resetAuditUI() {
  hide('results-wrap'); hide('live-feed-wrap'); hide('btn-report');
  document.getElementById('live-feed').innerHTML = '';
  setProgress(0, '');
}

function clearResults() {
  hide('results-wrap'); hide('progress-wrap'); hide('live-feed-wrap');
  document.getElementById('live-feed').innerHTML = '';
  state.lastScanID = null;
}

/* ── Toast ──────────────────────────────────────────────────────── */
function toast(message, type = 'info') {
  const el = document.createElement('div');
  el.className = 'toast toast-' + type;
  el.textContent = message;
  el.addEventListener('click', () => el.remove());
  document.getElementById('toast-container').appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

/* ── Helpers ────────────────────────────────────────────────────── */
function show(id) { document.getElementById(id).classList.remove('hidden'); }
function hide(id) { document.getElementById(id).classList.add('hidden'); }

function escHtml(str) {
  return String(str ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function isValidIP(ip) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) &&
    ip.split('.').every(n => +n >= 0 && +n <= 255);
}

function scoreRingClass(score) {
  if (score >= 80) return 'ring-secure';
  if (score >= 60) return 'ring-moderate';
  if (score >= 30) return 'ring-high';
  return 'ring-critical';
}

function scoreLabelText(cls) {
  return {secure:'Secure',moderate:'Moderate Risk',
    high:'High Risk',critical:'Critical'}[cls] || '';
}

function portCountStr(n) { return n === 0 ? 'no' : String(n); }

/* ── Boot ───────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  connectWS();
  showView('dashboard');
});