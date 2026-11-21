'use strict';

const state = {
  ws: null, connected: false,
  scanning: false, lastScanID: null,
};

/* - WebSocket - */
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

/* - Discovery - */
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
        toast('IP set - click Start audit', 'info');
      };
      card.addEventListener('click', pick);
      card.addEventListener('keydown', e => e.key === 'Enter' && pick());
      list.appendChild(card);
    });
  }
  grid.classList.remove('hidden');
}

/* - Audit - */
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
  toast('Score: ' + result.risk_score + '/100 - ' + result.summary.label,
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

/* - Results - */
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
           : '<span style="color:var(--stone)">-</span>'}
       </td>
       <td>${topCVE && topCVE.fix
         ? `<p class="fix-text">${escHtml(topCVE.fix)}</p>`
         : '<span style="color:var(--stone)">-</span>'}
       </td>`;
    tbody.appendChild(tr);
  });
}

/* - History - */
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
          No scans yet - run your first audit from the Scan tab.
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
     <td style="font-size:12px;color:var(--stone)">${escHtml(row.hostname || '-')}</td>
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
  toast('IP set - click Start audit', 'info');
}

async function downloadReport() {
  if (!state.lastScanID) return;
  window.open(`/api/report/${state.lastScanID}`, '_blank');
}

/* - View switching - */
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

/* - Toast - */
function toast(message, type = 'info') {
  const el = document.createElement('div');
  el.className = 'toast toast-' + type;
  el.textContent = message;
  el.addEventListener('click', () => el.remove());
  document.getElementById('toast-container').appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

/* - Helpers - */
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

/* - Schedules - */
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
  const emailReport = sc.email_report !== undefined ? sc.email_report : false;
  const emailSent = sc.email_sent;
  const emailSentAt = sc.email_sent_at
    ? 'Email sent ' + new Date(sc.email_sent_at).toLocaleString()
    : '';

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
      ${emailReport ? `<span style="color:var(--mint)">
        <b>Report email</b>${emailSentAt || 'Sending on next run'}
      </span>` : `<span style="color:var(--stone)">
        <b>Report email</b>off
      </span>`}
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
      <button onclick="toggleEmailReport(${sc.id}, ${!emailReport})"
        class="btn btn-ghost" style="font-size:11px;padding:5px 14px">
        ${emailReport ? 'Disable report email' : 'Email report'}
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
  const emailReport = document.getElementById('sched-email-report').checked;

  if (!ip)            { toast('Enter an IP address', 'error'); return; }
  if (!isValidIP(ip)) { toast('Enter a valid IPv4 address', 'error'); return; }

  try {
    const res  = await fetch('/api/schedules', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ ip, label, interval_hrs: interval, email_report: emailReport }),
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);

    document.getElementById('sched-ip').value    = '';
    document.getElementById('sched-label').value = '';
    toast('Schedule created - first scan in ' + intervalLabel(interval), 'success');
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
    toast('Scan started - watch the live feed on the Scan tab', 'info');
  } catch (err) {
    toast('Could not start scan: ' + err.message, 'error');
  }
}

async function toggleEmailReport(id, enable) {
  try {
    const res  = await fetch(`/api/schedules/${id}/email-report`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ email_report: enable }),
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    toast(enable ? 'Report email enabled for next run' : 'Report email disabled', 'success');
    loadSchedules();
  } catch (err) {
    toast('Could not update report email: ' + err.message, 'error');
  }
}

async function changeEmail() {
  const email = document.getElementById('settings-change-email').value.trim();
  const pw    = document.getElementById('settings-change-email-pw').value;

  if (!email) { toast('Enter the new email address', 'error'); return; }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { toast('Invalid email address', 'error'); return; }
  if (!pw)    { toast('Enter your current password', 'error'); return; }

  try {
    const res  = await fetch('/api/settings/change-email', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ email, password: pw }),
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    toast(data.message || 'Email change requested - check your inbox', 'success');
    if (data.verify_link) {
      toast('Click here to verify: ' + data.verify_link, 'info');
    }
    document.getElementById('settings-change-email').value = '';
    document.getElementById('settings-change-email-pw').value = '';
    loadEmailStatus();
  } catch (err) {
    toast('Error: ' + err.message, 'error');
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

/* - Settings - */
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
  if (!/[A-Za-z]/.test(newPw)) {
    toast('New password must contain at least one letter', 'error'); return;
  }
  if (!/[0-9]/.test(newPw)) {
    toast('New password must contain at least one number', 'error'); return;
  }
  if (!/[^A-Za-z0-9]/.test(newPw)) {
    toast('New password must contain at least one special character or symbol', 'error'); return;
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

/* - Email verification (Settings) - */
async function loadEmailStatus() {
  const wrap = document.getElementById('email-status-wrap');
  if (!wrap) return;
  try {
    const res  = await fetch('/api/settings/email-status');
    if (res.status === 401) {
      wrap.innerHTML = `<p style="font-size:13px;color:var(--red)">Session expired - <a href="/login" style="color:var(--mint)">log in again</a></p>`;
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
          : `<p style="font-size:12px;color:var(--stone)">SMTP is not configured - ask your admin to set it up in config.yaml</p>`
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
    toast('Email saved - check your inbox for verification', 'success');
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

/* - Network Topology Map - */
async function loadTopology() {
  const svg = document.getElementById('topo-svg');
  if (!svg) return;
  svg.innerHTML = '<text x="50%" y="50%" text-anchor="middle" fill="#a69f9d" font-size="14">Loading topology...</text>';

  try {
    const res  = await fetch('/api/topology');
    if (res.status === 401) { svg.innerHTML = '<text x="50%" y="50%" text-anchor="middle" fill="#f87171" font-size="14">Session expired - <a href="/login" fill="#a2f6f5">log in</a></text>'; return; }
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    renderTopology(svg, data.devices, data.gateway, data.topology_type);
  } catch (err) {
    svg.innerHTML = `<text x="50%" y="50%" text-anchor="middle" fill="#f87171" font-size="14">Error: ${err.message}</text>`;
  }
}

function renderTopology(svg, devices, gateway, topologyType) {
  const W = 900, H = 500, CX = W/2, CY = H/2;
  svg.innerHTML = '';

  if (!devices || devices.length === 0) {
    svg.innerHTML = '<text x="50%" y="50%" text-anchor="middle" fill="#a69f9d" font-size="14">No devices scanned yet. Run a scan to see your network map.</text>';
    return;
  }

  // Topology type badge (top-left of canvas)
  if (topologyType && topologyType !== 'unknown') {
    const badge = svgEl('text', { x: 14, y: 22, fill: '#a2f6f5', 'font-size': 11, opacity: 0.8 });
    badge.textContent = `Topology: ${topologyType.charAt(0).toUpperCase() + topologyType.slice(1)}`;
    svg.appendChild(badge);
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

/* ═══════════════════════════════════════════════════════════════════════════
   Vulnerability Trend Tracker
   ═══════════════════════════════════════════════════════════════════════════ */

// Palette — one colour per device (cycles if >8 devices)
const TREND_PALETTE = ['#a2f6f5','#f9a825','#f06292','#81d4fa','#aed581','#ce93d8','#ff8a65','#4db6ac'];

// State
let _trendData     = [];   // full summary from /api/trends/summary
let _trendMetric   = 'risk'; // 'risk' | 'cve' | 'ports'
let _trendFilterIP = null;   // null = show all

async function loadTrends() {
  const listEl = document.getElementById('trend-devices-list');
  if (listEl) listEl.innerHTML = '<p style="color:var(--stone)">Loading…</p>';

  try {
    const res  = await fetch('/api/trends/summary');
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    _trendData   = data.devices || [];
    _trendFilterIP = null;
    renderTrendStats(_trendData);
    renderTrendLegend(_trendData);
    drawTrendChart(_trendData, null, _trendMetric);
    renderTrendDeviceCards(_trendData);
    setTrendMetric(_trendMetric, /*silent*/true);
  } catch (err) {
    if (listEl) listEl.innerHTML = `<p style="color:var(--red)">Error: ${err.message}</p>`;
  }
}

// ── Metric toggle ────────────────────────────────────────────────────────────
function setTrendMetric(metric, silent) {
  _trendMetric = metric;
  ['risk','cve','ports'].forEach(m => {
    const btn = document.getElementById(`trend-btn-${m}`);
    if (!btn) return;
    btn.style.background    = m === metric ? 'rgba(162,246,245,0.15)' : '';
    btn.style.borderColor   = m === metric ? 'rgba(162,246,245,0.4)'  : '';
    btn.style.color         = m === metric ? '#a2f6f5' : '';
  });
  const labels = { risk: 'Risk Score (0–100)', cve: 'CVE Count', ports: 'Open Ports' };
  const sub    = { risk: 'Higher = safer', cve: 'Lower = safer', ports: 'New ports appearing = potential exposure' };
  const titleEl = document.getElementById('trend-chart-title');
  const subEl   = document.getElementById('trend-chart-sub');
  if (titleEl) titleEl.textContent = labels[metric] + ' Over Time';
  if (subEl)   subEl.textContent   = (_trendFilterIP ? `Filtered: ${_trendFilterIP} — ` : 'All devices — ') + sub[metric];
  if (!silent) drawTrendChart(_trendData, _trendFilterIP, metric);
}

// ── Filter by device ─────────────────────────────────────────────────────────
function filterTrendDevice(ip) {
  _trendFilterIP = ip;
  document.getElementById('trend-clear-btn').style.display = 'block';
  setTrendMetric(_trendMetric, /*silent*/true);
  drawTrendChart(_trendData, ip, _trendMetric);
  renderTrendLegend(_trendData, ip);
}

function clearTrendFilter() {
  _trendFilterIP = null;
  document.getElementById('trend-clear-btn').style.display = 'none';
  setTrendMetric(_trendMetric, /*silent*/true);
  drawTrendChart(_trendData, null, _trendMetric);
  renderTrendLegend(_trendData, null);
}

// ── Summary stat tiles ───────────────────────────────────────────────────────
function renderTrendStats(devices) {
  const row = document.getElementById('trend-stats-row');
  if (!row) return;

  const totalDevices = devices.length;
  const avgScore     = totalDevices ? Math.round(devices.reduce((s,d) => s + d.latest_score, 0) / totalDevices) : 0;
  const totalCVEs    = devices.reduce((s,d) => s + d.latest_cve, 0);
  const improved     = devices.filter(d => d.delta > 0).length;
  const worsened     = devices.filter(d => d.delta < 0).length;

  const tiles = [
    { label: 'Devices Monitored', value: totalDevices,              color: '#a2f6f5' },
    { label: 'Avg Risk Score',    value: avgScore + '/100',         color: riskColor(avgScore) },
    { label: 'Total CVEs',        value: totalCVEs,                 color: totalCVEs > 0 ? '#f87171' : '#4ade80' },
    { label: 'Improved',          value: '↑ ' + improved,          color: '#4ade80' },
    { label: 'Worsened',          value: '↓ ' + worsened,          color: worsened > 0 ? '#f87171' : '#a69f9d' },
  ];

  row.innerHTML = tiles.map(t => `
    <div style="background:rgba(227,204,192,0.03);border:1px solid rgba(227,204,192,0.08);border-radius:8px;padding:14px 16px">
      <p style="font-size:10px;color:var(--stone);text-transform:uppercase;letter-spacing:0.07em;margin-bottom:4px">${t.label}</p>
      <p style="font-size:22px;font-weight:600;color:${t.color};line-height:1">${t.value}</p>
    </div>`).join('');
}

// ── Legend ───────────────────────────────────────────────────────────────────
function renderTrendLegend(devices, activeIP) {
  const el = document.getElementById('trend-legend');
  if (!el) return;
  el.innerHTML = devices.map((d, i) => {
    const color   = TREND_PALETTE[i % TREND_PALETTE.length];
    const dimmed  = activeIP && activeIP !== d.ip;
    return `<span style="display:flex;align-items:center;gap:5px;opacity:${dimmed ? 0.3 : 1};cursor:pointer" onclick="filterTrendDevice('${d.ip}')">
      <span style="display:inline-block;width:16px;height:2px;background:${color};border-radius:1px"></span>
      <span style="color:var(--stone)">${d.hostname || d.ip}</span>
    </span>`;
  }).join('');
}

// ── Multi-line chart ─────────────────────────────────────────────────────────
function drawTrendChart(devices, filterIP, metric) {
  const svg = document.getElementById('trend-chart');
  if (!svg) return;
  svg.innerHTML = '';

  const W = 820, H = 300, PAD = { top: 24, right: 24, bottom: 44, left: 52 };
  const plotW = W - PAD.left - PAD.right;
  const plotH = H - PAD.top  - PAD.bottom;

  const visible = filterIP ? devices.filter(d => d.ip === filterIP) : devices;

  if (!visible.length || !visible.some(d => d.points.length > 0)) {
    svg.innerHTML = '<text x="50%" y="50%" text-anchor="middle" fill="#a69f9d" font-size="13">No scan data yet. Run some scans to see trends.</text>';
    return;
  }

  // Collect all timestamps globally for a shared X axis
  const allTimes = [...new Set(
    visible.flatMap(d => d.points.map(p => p.scan_time))
  )].sort();

  const getValue = (p) => metric === 'cve' ? p.cve_count : metric === 'ports' ? p.port_count : p.risk_score;

  // Y domain
  const allVals = visible.flatMap(d => d.points.map(getValue));
  const yMin = metric === 'risk' ? 0 : 0;
  const yMax = metric === 'risk' ? 100 : Math.max(10, ...allVals);

  const xScale = (t) => PAD.left + (allTimes.indexOf(t) / Math.max(allTimes.length - 1, 1)) * plotW;
  const yScale = (v) => PAD.top  + plotH * (1 - (v - yMin) / (yMax - yMin));

  // Risk zone bands (only for risk metric)
  if (metric === 'risk') {
    [
      { lo: 0,  hi: 20,  c: 'rgba(248,113,113,0.05)' },
      { lo: 20, hi: 50,  c: 'rgba(249,115,22,0.04)'  },
      { lo: 50, hi: 80,  c: 'rgba(251,191,36,0.03)'  },
      { lo: 80, hi: 100, c: 'rgba(74,222,128,0.03)'  },
    ].forEach(z => {
      const rect = svgEl('rect', { x: PAD.left, y: yScale(z.hi), width: plotW, height: yScale(z.lo) - yScale(z.hi), fill: z.c });
      svg.appendChild(rect);
    });
  }

  // Grid lines (Y)
  const gridTicks = metric === 'risk' ? [0, 25, 50, 75, 100] : Array.from({ length: 5 }, (_, i) => Math.round(yMin + (yMax - yMin) * i / 4));
  gridTicks.forEach(v => {
    const y = yScale(v);
    svg.appendChild(svgEl('line', { x1: PAD.left, y1: y, x2: W - PAD.right, y2: y, stroke: 'rgba(227,204,192,0.07)', 'stroke-width': 1 }));
    const lbl = svgEl('text', { x: PAD.left - 8, y: y + 4, 'text-anchor': 'end', fill: '#a69f9d', 'font-size': 10 });
    lbl.textContent = v;
    svg.appendChild(lbl);
  });

  // X-axis date labels (first and last, plus middle if ≥3 points)
  const xLabelIdxs = allTimes.length <= 1 ? [0] :
    allTimes.length === 2 ? [0, 1] :
    [0, Math.floor((allTimes.length - 1) / 2), allTimes.length - 1];
  xLabelIdxs.forEach(idx => {
    const t = allTimes[idx];
    const x = xScale(t);
    const lbl = svgEl('text', { x, y: H - 6, 'text-anchor': 'middle', fill: '#a69f9d', 'font-size': 10 });
    lbl.textContent = new Date(t).toLocaleDateString('en-KE', { month: 'short', day: 'numeric' });
    svg.appendChild(lbl);
    // Tick
    svg.appendChild(svgEl('line', { x1: x, y1: PAD.top + plotH, x2: x, y2: PAD.top + plotH + 4, stroke: 'rgba(227,204,192,0.2)', 'stroke-width': 1 }));
  });

  // One line + dots per device
  visible.forEach((dev, i) => {
    const color = TREND_PALETTE[(filterIP ? devices.findIndex(d => d.ip === dev.ip) : i) % TREND_PALETTE.length];
    const pts   = dev.points;
    if (pts.length === 0) return;

    // Line
    if (pts.length > 1) {
      let d = '';
      pts.forEach(p => {
        const x = xScale(p.scan_time), y = yScale(getValue(p));
        d += (d === '' ? 'M' : 'L') + `${x.toFixed(1)},${y.toFixed(1)}`;
      });
      svg.appendChild(svgEl('path', { d, fill: 'none', stroke: color, 'stroke-width': 2, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }));
    }

    // Dots with tooltip
    pts.forEach(p => {
      const x = xScale(p.scan_time), y = yScale(getValue(p));
      const dot = svgEl('circle', { cx: x, cy: y, r: 4.5, fill: color, stroke: '#1a0d0a', 'stroke-width': 1.5, cursor: 'pointer' });

      dot.addEventListener('mouseenter', (e) => {
        const tip = svgEl('g', { id: 'trend-tooltip' });
        const lines = [
          dev.hostname || dev.ip,
          new Date(p.scan_time).toLocaleString('en-KE', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }),
          `Risk: ${p.risk_score}/100  CVEs: ${p.cve_count}  Ports: ${p.port_count}`,
        ];
        const tw = 210, th = lines.length * 15 + 10;
        let tx = x - tw / 2, ty = y - th - 10;
        if (tx < PAD.left) tx = PAD.left;
        if (tx + tw > W - PAD.right) tx = W - PAD.right - tw;
        if (ty < 0) ty = y + 14;
        tip.appendChild(svgEl('rect', { x: tx, y: ty, width: tw, height: th, rx: 5, fill: '#1e1428', stroke: 'rgba(227,204,192,0.18)' }));
        lines.forEach((line, li) => {
          const t = svgEl('text', { x: tx + tw / 2, y: ty + 14 + li * 15, 'text-anchor': 'middle', fill: li === 0 ? color : '#d0c8c0', 'font-size': li === 0 ? 11 : 10 });
          t.textContent = line;
          tip.appendChild(t);
        });
        svg.appendChild(tip);
      });
      dot.addEventListener('mouseleave', () => {
        const tip = svg.querySelector('#trend-tooltip');
        if (tip) tip.remove();
      });
      svg.appendChild(dot);
    });
  });
}

// ── Device cards ─────────────────────────────────────────────────────────────
function renderTrendDeviceCards(devices) {
  const wrap = document.getElementById('trend-devices-list');
  if (!wrap) return;

  if (!devices || devices.length === 0) {
    wrap.innerHTML = '<p style="color:var(--stone)">No devices scanned yet. Run a scan first.</p>';
    return;
  }

  let html = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px">';
  devices.forEach((d, i) => {
    const color     = TREND_PALETTE[i % TREND_PALETTE.length];
    const scoreCol  = riskColor(d.latest_score);
    const deltaSign = d.delta > 0 ? '↑' : d.delta < 0 ? '↓' : '→';
    const deltaCol  = d.delta > 0 ? '#4ade80' : d.delta < 0 ? '#f87171' : '#a69f9d';
    const deltaLabel = d.delta === 0 ? 'No change' : (d.delta > 0 ? `+${d.delta} improved` : `${d.delta} worsened`);

    // Sparkline (risk score mini line, last 8 points max)
    const spark = d.points.slice(-8);
    let sparkSVG = '';
    if (spark.length > 1) {
      const sW = 80, sH = 24;
      const sMax = Math.max(...spark.map(p => p.risk_score), 1);
      const sMin = Math.min(...spark.map(p => p.risk_score));
      const sRange = sMax - sMin || 1;
      const sx = (i) => (i / (spark.length - 1)) * sW;
      const sy = (v) => sH - ((v - sMin) / sRange) * (sH - 4) - 2;
      let dPath = spark.map((p, i) => `${i === 0 ? 'M' : 'L'}${sx(i).toFixed(1)},${sy(p.risk_score).toFixed(1)}`).join(' ');
      sparkSVG = `<svg width="${sW}" height="${sH}" viewBox="0 0 ${sW} ${sH}" style="display:block;flex-shrink:0"><path d="${dPath}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linejoin="round"/></svg>`;
    }

    html += `
      <div onclick="filterTrendDevice('${d.ip}')"
           style="cursor:pointer;padding:14px;background:rgba(227,204,192,0.03);border:1px solid rgba(227,204,192,0.08);border-radius:8px;transition:border-color 0.15s"
           onmouseover="this.style.borderColor='${color}40'" onmouseout="this.style.borderColor='rgba(227,204,192,0.08)'">

        <!-- Header row -->
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:10px">
          <div style="min-width:0">
            <div style="display:flex;align-items:center;gap:6px;margin-bottom:2px">
              <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${color};flex-shrink:0"></span>
              <span style="font-size:13px;color:var(--cream);font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${d.hostname || d.ip}</span>
            </div>
            <span style="font-size:10px;color:var(--stone)">${d.ip}</span>
          </div>
          <div style="text-align:right;flex-shrink:0">
            <div style="font-size:20px;font-weight:600;color:${scoreCol};line-height:1">${d.latest_score}</div>
            <div style="font-size:10px;color:var(--stone)">/ 100</div>
          </div>
        </div>

        <!-- Sparkline + delta -->
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
          ${sparkSVG}
          <div style="text-align:right">
            <div style="font-size:15px;font-weight:600;color:${deltaCol}">${deltaSign} ${Math.abs(d.delta)}</div>
            <div style="font-size:9px;color:var(--stone)">${deltaLabel}</div>
          </div>
        </div>

        <!-- Stats row -->
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:4px;border-top:1px solid rgba(227,204,192,0.06);padding-top:8px">
          <div>
            <div style="font-size:11px;color:var(--stone)">CVEs</div>
            <div style="font-size:13px;color:${d.latest_cve > 0 ? '#f87171' : '#4ade80'};font-weight:500">${d.latest_cve}</div>
          </div>
          <div>
            <div style="font-size:11px;color:var(--stone)">Scans</div>
            <div style="font-size:13px;color:var(--cream);font-weight:500">${d.scan_count}</div>
          </div>
          <div>
            <div style="font-size:11px;color:var(--stone)">Ports</div>
            <div style="font-size:13px;color:var(--cream);font-weight:500">${d.points.length ? d.points[d.points.length-1].port_count : '—'}</div>
          </div>
        </div>
      </div>`;
  });
  html += '</div>';
  wrap.innerHTML = html;
}

/* - Boot - */
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