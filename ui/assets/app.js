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
    case 'SCAN_BUSY':     onScanBusy(msg.payload.message);    break;
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

async function scanAllDevices() {
  const subnet = document.getElementById('subnet-input').value.trim();
  if (!subnet) { toast('Enter a subnet first', 'error'); return; }
  if (state.scanning) { toast('Audit already running', 'error'); return; }

  resetAuditUI();
  state.scanning = true;
  const btn = document.getElementById('btn-audit');
  btn.disabled = true; btn.textContent = 'Scanning...';
  show('progress-wrap');
  setProgress(0, 'Starting subnet scan on ' + subnet);

  try {
    const res  = await fetch('/api/scan/subnet', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ subnet }),
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
  } catch (err) {
    onScanError(err.message);
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
  show('btn-cancel');
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
  hide('btn-cancel');
  renderResults(result);
  const ok = result.risk_score >= 70;
  toast('Score: ' + result.risk_score + '/100 — ' + result.summary.label,
    ok ? 'success' : 'error');
}

async function cancelAudit() {
  try {
    const res  = await fetch('/api/scan/cancel', { method: 'POST' });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    toast('Scan cancellation requested', 'info');
  } catch (err) {
    toast('Cancel failed: ' + err.message, 'error');
  }
}

function onScanBusy(msg) {
  state.scanning = false;
  const btn = document.getElementById('btn-audit');
  btn.disabled = false; btn.textContent = 'Start audit';
  hide('btn-cancel');
  toast(msg || 'Another audit is already running', 'error');
}

function onScanError(msg) {
  state.scanning = false;
  const btn = document.getElementById('btn-audit');
  btn.disabled = false; btn.textContent = 'Start audit';
  hide('btn-cancel');
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
const historyState = { offset: 0, limit: 20, hasMore: false };

async function loadHistory() {
  historyState.offset = 0;
  const tbody = document.getElementById('history-table-body');
  tbody.innerHTML =
    `<tr><td colspan="8"
      style="text-align:center;color:var(--stone);padding:40px 0">
      Loading...
    </td></tr>`;
  hide('history-load-more');

  try {
    const res  = await fetch(`/api/history?limit=${historyState.limit}&offset=0`);
    const data = await res.json();
    if (data.error) throw new Error(data.error);

    tbody.innerHTML = '';

    if (!data.scans || !data.scans.length) {
      tbody.innerHTML =
        `<tr><td colspan="8"
          style="text-align:center;color:var(--stone);padding:48px 0">
          No scans yet — run your first audit from the Scan tab.
        </td></tr>`;
      return;
    }

    historyState.offset = data.scans.length;
    historyState.hasMore = data.has_more;
    data.scans.forEach(row => appendHistoryRow(row));

    if (data.has_more) show('history-load-more');
  } catch (err) {
    tbody.innerHTML =
      `<tr><td colspan="8"
        style="text-align:center;color:var(--red);padding:40px 0">
        Error: ${escHtml(err.message)}
      </td></tr>`;
  }
}

async function loadMoreHistory() {
  const btn = document.querySelector('#history-load-more button');
  btn.disabled = true; btn.textContent = 'Loading...';

  try {
    const res  = await fetch(`/api/history?limit=${historyState.limit}&offset=${historyState.offset}`);
    const data = await res.json();
    if (data.error) throw new Error(data.error);

    historyState.offset += data.scans.length;
    historyState.hasMore = data.has_more;
    data.scans.forEach(row => appendHistoryRow(row));

    if (data.has_more) {
      show('history-load-more');
    } else {
      hide('history-load-more');
    }
  } catch (err) {
    toast('Load more failed: ' + err.message, 'error');
  } finally {
    btn.disabled = false; btn.textContent = 'Load more';
  }
}

function appendHistoryRow(row) {
  const tbody = document.getElementById('history-table-body');
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
  // Update URL hash without triggering hashchange
  if (location.hash !== '#' + name) history.replaceState(null, '', '#' + name);

  document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
  document.getElementById('view-' + name).classList.remove('hidden');
  document.querySelectorAll('.nav-tab').forEach(b => {
    const active = b.dataset.view === name;
    b.classList.toggle('active', active);
    b.setAttribute('aria-selected', active);
  });
  if (name === 'history')   loadHistory();
  if (name === 'schedules') loadSchedules();
  if (name === 'settings')  loadEmailStatus();
  if (name === 'topology')  loadTopology();
  if (name === 'trends')    loadTrends();
}

function resetAuditUI() {
  hide('results-wrap'); hide('live-feed-wrap'); hide('btn-report'); hide('btn-cancel');
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

/* ── Schedules ──────────────────────────────────────────────────── */
async function loadSchedules() {
  const grid  = document.getElementById('sched-grid');
  const empty = document.getElementById('sched-empty');
  grid.innerHTML = '';

  try {
    const res  = await fetch('/api/schedules');
    const data = await res.json();
    if (data.error) throw new Error(data.error);

    if (!data.length) {
      empty.classList.remove('hidden');
      return;
    }
    empty.classList.add('hidden');
    data.forEach(sc => grid.appendChild(buildSchedCard(sc)));
  } catch (err) {
    toast('Could not load schedules: ' + err.message, 'error');
  }
}

function buildSchedCard(sc) {
  const card = document.createElement('div');
  card.className = 'sched-card' + (sc.enabled ? '' : ' disabled');
  card.id = 'sched-card-' + sc.id;

  const lastRun = sc.last_run
    ? new Date(sc.last_run).toLocaleString()
    : 'Never';
  const nextRun = new Date(sc.next_run).toLocaleString();
  const interval = intervalLabel(sc.interval_hrs);

  card.innerHTML = `
    <div class="sched-head">
      <div>
        <p class="sched-ip">${escHtml(sc.ip)}</p>
        <p class="sched-label">${escHtml(sc.label || 'No label')}</p>
      </div>
      <span class="sched-badge ${sc.enabled ? 'on' : 'off'}">
        ${sc.enabled ? 'Active' : 'Paused'}
      </span>
    </div>
    <div class="sched-meta">
      <span><b>Interval</b>${escHtml(interval)}</span>
      <span><b>Last run</b>${escHtml(lastRun)}</span>
      <span><b>Next run</b>${escHtml(nextRun)}</span>
    </div>
    <div class="sched-actions">
      <button onclick="runSchedNow(${sc.id})"
        class="btn btn-mint" style="font-size:11px;padding:5px 14px">
        Run now
      </button>
      <button onclick="toggleSched(${sc.id}, ${!sc.enabled})"
        class="btn btn-ghost" style="font-size:11px;padding:5px 14px">
        ${sc.enabled ? 'Pause' : 'Resume'}
      </button>
      <button onclick="deleteSched(${sc.id})"
        class="btn btn-danger" style="font-size:11px;padding:5px 14px">
        Delete
      </button>
    </div>`;
  return card;
}

async function createSchedule() {
  const ip       = document.getElementById('sched-ip').value.trim();
  const label    = document.getElementById('sched-label').value.trim();
  const interval = parseInt(document.getElementById('sched-interval').value);

  if (!ip)            { toast('Enter an IP address', 'error'); return; }
  if (!isValidIP(ip)) { toast('Enter a valid IPv4 address', 'error'); return; }

  try {
    const res  = await fetch('/api/schedules', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ ip, label, interval_hrs: interval }),
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);

    document.getElementById('sched-ip').value    = '';
    document.getElementById('sched-label').value = '';
    toast('Schedule created — first scan in ' + intervalLabel(interval), 'success');
    loadSchedules();
  } catch (err) {
    toast('Could not create schedule: ' + err.message, 'error');
  }
}

async function toggleSched(id, enable) {
  try {
    const res  = await fetch(`/api/schedules/${id}/toggle`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ enabled: enable }),
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    toast(enable ? 'Schedule resumed' : 'Schedule paused', 'success');
    loadSchedules();
  } catch (err) {
    toast('Could not update schedule: ' + err.message, 'error');
  }
}

async function deleteSched(id) {
  if (!confirm('Delete this schedule?')) return;
  try {
    const res  = await fetch(`/api/schedules/${id}`, { method: 'DELETE' });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    toast('Schedule deleted', 'success');
    loadSchedules();
  } catch (err) {
    toast('Could not delete schedule: ' + err.message, 'error');
  }
}

async function runSchedNow(id) {
  try {
    const res  = await fetch(`/api/schedules/${id}/run`, { method: 'POST' });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    toast('Scan started — watch the live feed on the Scan tab', 'info');
  } catch (err) {
    toast('Could not start scan: ' + err.message, 'error');
  }
}

function intervalLabel(hrs) {
  if (hrs === 6)   return 'Every 6 hours';
  if (hrs === 12)  return 'Every 12 hours';
  if (hrs === 24)  return 'Every 24 hours';
  if (hrs === 48)  return 'Every 2 days';
  if (hrs === 168) return 'Every week';
  return `Every ${hrs} hours`;
}

/* ── Settings ──────────────────────────────────────────────────── */
async function changePassword() {
  const current = document.getElementById('settings-current-pw').value;
  const newPw   = document.getElementById('settings-new-pw').value;
  const confirm = document.getElementById('settings-confirm-pw').value;

  if (!current || !newPw || !confirm) {
    toast('All fields are required', 'error'); return;
  }
  if (newPw.length < 8) {
    toast('New password must be at least 8 characters', 'error'); return;
  }
  if (newPw !== confirm) {
    toast('New passwords do not match', 'error'); return;
  }

  try {
    const res  = await fetch('/api/settings/password', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ current_password: current, new_password: newPw }),
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    toast('Password changed successfully', 'success');
    document.getElementById('settings-current-pw').value = '';
    document.getElementById('settings-new-pw').value = '';
    document.getElementById('settings-confirm-pw').value = '';
  } catch (err) {
    toast('Error: ' + err.message, 'error');
  }
}

/* ── Email verification (Settings) ──────────────────────────────── */
async function loadEmailStatus() {
  const wrap = document.getElementById('email-status-wrap');
  if (!wrap) return;
  try {
    const res  = await fetch('/api/settings/email-status');
    if (res.status === 401) {
      wrap.innerHTML = `<p style="font-size:13px;color:var(--red)">Session expired — <a href="/login" style="color:var(--mint)">log in again</a></p>`;
      return;
    }
    if (!res.ok) throw new Error(`Server returned ${res.status}`);
    const data = await res.json();
    if (data.error) throw new Error(data.error);

    let html = '';
    if (!data.email) {
      html = `
        <p style="font-size:13px;color:var(--stone);margin-bottom:12px">No email address set.</p>
        <div style="display:flex;gap:8px;align-items:center">
          <input id="settings-email-input" type="email" placeholder="you@company.com" class="input" style="flex:1"/>
          <button onclick="saveEmail()" class="btn btn-mint" style="white-space:nowrap">Save email</button>
        </div>`;
    } else if (data.verified) {
      html = `
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
          <span style="display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:50%;background:rgba(74,222,128,0.12);border:1px solid rgba(74,222,128,0.3)">
            <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.5l2.5 2.5 4.5-4.5" stroke="#4ade80" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </span>
          <span style="font-size:13px;color:var(--cream)">${data.email}</span>
        </div>
        <p style="font-size:12px;color:var(--green)">Email verified</p>`;
    } else {
      html = `
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
          <span style="display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:50%;background:rgba(251,191,36,0.12);border:1px solid rgba(251,191,36,0.3)">
            <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><circle cx="6" cy="6" r="4" stroke="#fbbf24" stroke-width="1.2"/><path d="M6 4v2.5" stroke="#fbbf24" stroke-width="1.2" stroke-linecap="round"/></svg>
          </span>
          <span style="font-size:13px;color:var(--cream)">${data.email}</span>
        </div>
        <p style="font-size:12px;color:#fbbf24;margin-bottom:12px">Email not verified</p>
        ${data.smtp_configured
          ? `<button onclick="resendVerification()" class="btn btn-mint" style="font-size:12px;padding:8px 16px">Resend verification email</button>`
          : `<p style="font-size:12px;color:var(--stone)">SMTP is not configured — ask your admin to set it up in config.yaml</p>`
        }`;
    }
    wrap.innerHTML = html;
  } catch (err) {
    wrap.innerHTML = `<p style="font-size:13px;color:var(--red)">Could not load email status: ${err.message}</p>`;
  }
}

async function saveEmail() {
  const input = document.getElementById('settings-email-input');
  const email = input ? input.value.trim() : '';
  if (!email) { toast('Please enter an email address', 'error'); return; }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { toast('Invalid email address', 'error'); return; }

  try {
    const res = await fetch('/api/settings/email-status', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ email }),
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    toast('Email saved — check your inbox for verification', 'success');
    loadEmailStatus();
  } catch (err) {
    toast('Error: ' + err.message, 'error');
  }
}

async function resendVerification() {
  try {
    const res  = await fetch('/api/settings/resend-verification', { method: 'POST' });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    toast(data.status || 'Verification email sent', 'success');
  } catch (err) {
    toast('Error: ' + err.message, 'error');
  }
}

/* ── Network Topology Map ───────────────────────────────────────── */
async function loadTopology() {
  const svg = document.getElementById('topo-svg');
  if (!svg) return;
  svg.innerHTML = '<text x="50%" y="50%" text-anchor="middle" fill="#a69f9d" font-size="14">Loading topology...</text>';

  try {
    const res  = await fetch('/api/topology');
    if (res.status === 401) { svg.innerHTML = '<text x="50%" y="50%" text-anchor="middle" fill="#f87171" font-size="14">Session expired — <a href="/login" fill="#a2f6f5">log in</a></text>'; return; }
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    renderTopology(svg, data.devices, data.gateway);
  } catch (err) {
    svg.innerHTML = `<text x="50%" y="50%" text-anchor="middle" fill="#f87171" font-size="14">Error: ${err.message}</text>`;
  }
}

function renderTopology(svg, devices, gateway) {
  const W = 900, H = 500, CX = W/2, CY = H/2;
  svg.innerHTML = '';

  if (!devices || devices.length === 0) {
    svg.innerHTML = '<text x="50%" y="50%" text-anchor="middle" fill="#a69f9d" font-size="14">No devices scanned yet. Run a scan to see your network map.</text>';
    return;
  }

  // Defs for glow filters
  const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
  defs.innerHTML = `
    <filter id="glow"><feGaussianBlur stdDeviation="3" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    <radialGradient id="gwGrad"><stop offset="0%" stop-color="#858df9" stop-opacity="0.3"/><stop offset="100%" stop-color="#858df9" stop-opacity="0.05"/></radialGradient>
  `;
  svg.appendChild(defs);

  // Gateway ring
  const gwRing = svgEl('circle', { cx: CX, cy: CY, r: 40, fill: 'url(#gwGrad)', stroke: '#858df9', 'stroke-width': 1.5, opacity: 0.7 });
  svg.appendChild(gwRing);
  const gwLabel = svgEl('text', { x: CX, y: CY + 4, 'text-anchor': 'middle', fill: '#fcfaf9', 'font-size': 11, 'font-weight': 500 });
  gwLabel.textContent = 'Gateway';
  svg.appendChild(gwLabel);

  // Position devices in a circle around the gateway
  const radius = Math.min(W, H) * 0.35;
  const angleStep = (2 * Math.PI) / devices.length;

  devices.forEach((dev, i) => {
    const angle = -Math.PI/2 + i * angleStep;
    const x = CX + radius * Math.cos(angle);
    const y = CY + radius * Math.sin(angle);
    const color = riskColor(dev.risk_score);

    // Connection line
    const line = svgEl('line', { x1: CX, y1: CY, x2: x, y2: y, stroke: color, 'stroke-width': 1, opacity: 0.3 });
    svg.appendChild(line);

    // Device group (clickable)
    const g = svgEl('g', { cursor: 'pointer', 'data-ip': dev.ip });
    g.addEventListener('click', () => showTopoDetail(dev));

    // Device type icon (small shape)
    const icon = deviceIcon(dev.device_type);
    const iconEl = svgEl('text', { x: x, y: y - 18, 'text-anchor': 'middle', 'font-size': 16 });
    iconEl.textContent = icon;
    g.appendChild(iconEl);

    // Node circle
    const circle = svgEl('circle', { cx: x, cy: y, r: 22, fill: color, opacity: 0.15, stroke: color, 'stroke-width': 1.5 });
    g.appendChild(circle);

    // Score text inside circle
    const scoreText = svgEl('text', { x: x, y: y + 4, 'text-anchor': 'middle', fill: color, 'font-size': 13, 'font-weight': 500 });
    scoreText.textContent = dev.risk_score;
    g.appendChild(scoreText);

    // IP label below
    const ipLabel = svgEl('text', { x: x, y: y + 38, 'text-anchor': 'middle', fill: '#a69f9d', 'font-size': 10 });
    ipLabel.textContent = dev.hostname || dev.ip;
    g.appendChild(ipLabel);

    // Device type label
    const typeLabel = svgEl('text', { x: x, y: y + 50, 'text-anchor': 'middle', fill: '#a69f9d', 'font-size': 9, opacity: 0.6 });
    typeLabel.textContent = dev.device_type;
    g.appendChild(typeLabel);

    svg.appendChild(g);
  });
}

function showTopoDetail(dev) {
  const panel = document.getElementById('topo-detail');
  const color = riskColor(dev.risk_score);
  document.getElementById('topo-detail-title').textContent = dev.hostname || dev.ip;
  document.getElementById('topo-detail-sub').innerHTML = `<span style="color:${color}">${dev.risk_score}/100</span> · ${dev.device_type} · ${dev.os_hint}`;

  let servicesHtml = '';
  if (dev.services && dev.services.length > 0) {
    servicesHtml = dev.services.map(s => `<span style="display:inline-block;padding:2px 8px;background:rgba(162,246,245,0.08);border:1px solid rgba(162,246,245,0.15);border-radius:999px;font-size:11px;margin:2px">${s}</span>`).join('');
  } else {
    servicesHtml = '<span style="color:var(--stone);font-size:12px">No services detected</span>';
  }

  document.getElementById('topo-detail-body').innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px">
      <div><p style="font-size:11px;color:var(--stone);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:2px">IP Address</p><p style="font-size:13px;color:var(--cream)">${dev.ip}</p></div>
      <div><p style="font-size:11px;color:var(--stone);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:2px">Last Scan</p><p style="font-size:13px;color:var(--cream)">${new Date(dev.scan_time).toLocaleString()}</p></div>
      <div><p style="font-size:11px;color:var(--stone);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:2px">Open Ports</p><p style="font-size:13px;color:var(--cream)">${dev.open_ports}</p></div>
      <div><p style="font-size:11px;color:var(--stone);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:2px">CVEs Found</p><p style="font-size:13px;color:${dev.cve_count > 0 ? 'var(--red)' : 'var(--green)'}">${dev.cve_count}</p></div>
    </div>
    <p style="font-size:11px;color:var(--stone);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:6px">Services</p>
    <div style="display:flex;flex-wrap:wrap;gap:4px">${servicesHtml}</div>
  `;
  panel.style.display = 'block';
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function svgEl(tag, attrs) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  return el;
}

function deviceIcon(type) {
  const icons = { server: '🖥', workstation: '💻', printer: '🖨', router: '📡', iot: '📷', unknown: '❓' };
  return icons[type] || '❓';
}

function riskColor(score) {
  if (score >= 80) return '#4ade80';
  if (score >= 50) return '#fbbf24';
  if (score >= 20) return '#f97316';
  return '#f87171';
}

/* ── Vulnerability Trend Tracker ────────────────────────────────── */
async function loadTrends() {
  try {
    const [devicesRes, pointsRes] = await Promise.all([
      fetch('/api/trends/devices'),
      fetch('/api/trends'),
    ]);
    const devicesData = await devicesRes.json();
    const pointsData  = await pointsRes.json();
    if (devicesData.error) throw new Error(devicesData.error);

    renderTrendChart(pointsData.points || []);
    renderTrendDevices(devicesData.devices || []);
  } catch (err) {
    document.getElementById('trend-devices-list').innerHTML = `<p style="color:var(--red)">Error: ${err.message}</p>`;
  }
}

function renderTrendChart(points) {
  const svg = document.getElementById('trend-chart');
  if (!svg) return;
  svg.innerHTML = '';

  const W = 800, H = 280, PAD = { top: 20, right: 20, bottom: 40, left: 50 };
  const plotW = W - PAD.left - PAD.right;
  const plotH = H - PAD.top - PAD.bottom;

  if (!points || points.length === 0) {
    svg.innerHTML = '<text x="50%" y="50%" text-anchor="middle" fill="#a69f9d" font-size="13">No scan data yet. Run some scans to see trends.</text>';
    return;
  }

  // Y axis: 0-100
  const yScale = (v) => PAD.top + plotH * (1 - v / 100);
  // X axis: spread points evenly
  const xScale = (i) => PAD.left + (i / Math.max(points.length - 1, 1)) * plotW;

  // Grid lines
  [0, 25, 50, 75, 100].forEach(v => {
    const y = yScale(v);
    const line = svgEl('line', { x1: PAD.left, y1: y, x2: W - PAD.right, y2: y, stroke: 'rgba(227,204,192,0.08)', 'stroke-width': 1 });
    svg.appendChild(line);
    const label = svgEl('text', { x: PAD.left - 8, y: y + 4, 'text-anchor': 'end', fill: '#a69f9d', 'font-size': 10 });
    label.textContent = v;
    svg.appendChild(label);
  });

  // Risk zones (background bands)
  const zones = [
    { y1: 0, y2: 20, color: 'rgba(248,113,113,0.04)' },
    { y1: 20, y2: 50, color: 'rgba(249,115,22,0.03)' },
    { y1: 50, y2: 80, color: 'rgba(251,191,36,0.03)' },
    { y1: 80, y2: 100, color: 'rgba(74,222,128,0.03)' },
  ];
  zones.forEach(z => {
    const rect = svgEl('rect', { x: PAD.left, y: yScale(z.y2), width: plotW, height: yScale(z.y1) - yScale(z.y2), fill: z.color });
    svg.appendChild(rect);
  });

  // Line path
  if (points.length > 1) {
    let d = '';
    points.forEach((p, i) => {
      const x = xScale(i), y = yScale(p.risk_score);
      d += (i === 0 ? 'M' : 'L') + `${x},${y}`;
    });
    const path = svgEl('path', { d, fill: 'none', stroke: '#a2f6f5', 'stroke-width': 2, 'stroke-linejoin': 'round' });
    svg.appendChild(path);
  }

  // Data points
  points.forEach((p, i) => {
    const x = xScale(i), y = yScale(p.risk_score);
    const color = riskColor(p.risk_score);

    const circle = svgEl('circle', { cx: x, cy: y, r: 5, fill: color, stroke: '#200f0a', 'stroke-width': 1.5, cursor: 'pointer' });
    circle.addEventListener('mouseenter', () => {
      // Show tooltip
      const tip = svgEl('g', { id: 'trend-tooltip' });
      const bg = svgEl('rect', { x: x - 60, y: y - 40, width: 120, height: 32, rx: 4, fill: '#2b2538', stroke: 'rgba(227,204,192,0.2)' });
      const txt = svgEl('text', { x: x, y: y - 22, 'text-anchor': 'middle', fill: '#fcfaf9', 'font-size': 11 });
      txt.textContent = `${p.hostname || p.ip}: ${p.risk_score}`;
      tip.appendChild(bg);
      tip.appendChild(txt);
      svg.appendChild(tip);
    });
    circle.addEventListener('mouseleave', () => {
      const tip = svg.getElementById('trend-tooltip');
      if (tip) tip.remove();
    });
    svg.appendChild(circle);
  });

  // X-axis labels (date range)
  if (points.length > 0) {
    const first = new Date(points[0].scan_time).toLocaleDateString();
    const last  = new Date(points[points.length - 1].scan_time).toLocaleDateString();
    const lbl1 = svgEl('text', { x: PAD.left, y: H - 8, fill: '#a69f9d', 'font-size': 10 });
    lbl1.textContent = first;
    svg.appendChild(lbl1);
    const lbl2 = svgEl('text', { x: W - PAD.right, y: H - 8, 'text-anchor': 'end', fill: '#a69f9d', 'font-size': 10 });
    lbl2.textContent = last;
    svg.appendChild(lbl2);
  }
}

function renderTrendDevices(devices) {
  const wrap = document.getElementById('trend-devices-list');
  if (!wrap) return;

  if (!devices || devices.length === 0) {
    wrap.innerHTML = '<p style="color:var(--stone)">No devices scanned yet.</p>';
    return;
  }

  let html = '<div style="display:flex;flex-direction:column;gap:8px">';
  devices.forEach(d => {
    const color = riskColor(d.latest_score);
    const barWidth = d.latest_score;
    html += `
      <div onclick="loadDeviceTrend('${d.ip}')" style="cursor:pointer;padding:10px 14px;background:rgba(227,204,192,0.03);border:1px solid rgba(227,204,192,0.08);border-radius:6px;transition:border-color 0.15s" onmouseover="this.style.borderColor='rgba(162,246,245,0.2)'" onmouseout="this.style.borderColor='rgba(227,204,192,0.08)'">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
          <span style="font-size:13px;color:var(--cream)">${d.hostname || d.ip}</span>
          <span style="font-size:12px;color:${color};font-weight:500">${d.latest_score}/100</span>
        </div>
        <div style="height:3px;background:rgba(227,204,192,0.08);border-radius:99px;overflow:hidden">
          <div style="height:100%;width:${barWidth}%;background:${color};border-radius:99px"></div>
        </div>
        <div style="display:flex;justify-content:space-between;margin-top:4px">
          <span style="font-size:10px;color:var(--stone)">${d.scan_count} scan${d.scan_count !== 1 ? 's' : ''}</span>
          <span style="font-size:10px;color:var(--stone)">${d.ip}</span>
        </div>
      </div>`;
  });
  html += '</div>';
  wrap.innerHTML = html;
}

async function loadDeviceTrend(ip) {
  try {
    const res  = await fetch(`/api/trends?ip=${encodeURIComponent(ip)}`);
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    renderTrendChart(data.points || []);
  } catch (err) {
    toast('Error loading trend: ' + err.message, 'error');
  }
}

/* ── Boot ───────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  connectWS();
  // Restore view from URL hash (survives page refresh)
  const hash = location.hash.replace('#', '');
  const validViews = ['dashboard', 'history', 'schedules', 'topology', 'trends', 'settings'];
  const initialView = validViews.includes(hash) ? hash : 'dashboard';
  showView(initialView);
});

// Listen for hash changes (back/forward browser navigation)
window.addEventListener('hashchange', () => {
  const hash = location.hash.replace('#', '');
  const validViews = ['dashboard', 'history', 'schedules', 'settings'];
  if (validViews.includes(hash)) showView(hash);
});