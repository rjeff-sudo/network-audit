/**
 * SME-Shield Frontend Logic
 * Manages scan triggering, history fetching, and modal rendering.
 */

// 0. Network Discovery Functions
async function detectSubnet() {
    console.log("Detecting local subnet...");
    const input = document.getElementById('subnet-input');
    input.value = 'Detecting...';
    
    try {
        const response = await fetch('/api/subnet');
        if (!response.ok) throw new Error('Failed to detect subnet');
        
        const subnet = await response.json();
        input.value = subnet.cidr;
        
        // Automatically populate the scan target with the detected subnet
        const targetInput = document.getElementById('scan-target');
        if (!targetInput.value) {
            targetInput.value = subnet.cidr;
        }
        
        console.log("✅ Subnet detected:", subnet.cidr);
    } catch (error) {
        console.error('Subnet detection error:', error);
        input.value = 'Failed to detect';
        alert('Could not detect subnet. Please enter manually.');
    }
}

async function discoverDevices() {
    const targetInput = document.getElementById('scan-target');
    const target = targetInput.value.trim();
    
    if (!target) {
        alert('Please enter a subnet or IP range first');
        return;
    }
    
    console.log("Discovering devices on:", target);
    const btn = event.target;
    btn.disabled = true;
    const originalText = btn.innerText;
    btn.innerText = 'Scanning...';
    
    try {
        const response = await fetch('/api/discover', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cidr: target })
        });
        
        if (!response.ok) throw new Error('Discovery failed');
        
        const devices = await response.json();
        displayDevices(devices);
        console.log("✅ Found", devices.length, "active devices");
        
    } catch (error) {
        console.error('Device discovery error:', error);
        alert('Failed to discover devices: ' + error.message);
    } finally {
        btn.disabled = false;
        btn.innerText = originalText;
    }
}

function displayDevices(devices) {
    const section = document.getElementById('devices-section');
    const list = document.getElementById('devices-list');
    
    if (!devices || devices.length === 0) {
        list.innerHTML = '<p class="col-span-full text-center text-slate-400">No active devices found</p>';
        section.classList.remove('hidden');
        return;
    }
    
    list.innerHTML = '';
    devices.forEach(device => {
        const div = document.createElement('div');
        div.className = 'bg-slate-900/50 border border-slate-700 rounded-lg p-3 cursor-pointer hover:border-blue-500 hover:bg-slate-900 transition';
        div.innerHTML = `
            <div class="font-mono text-blue-400 font-bold">${device.ip}</div>
            <div class="text-xs text-slate-400 mt-1">${device.hostname || 'Unknown'}</div>
            <button onclick="selectDevice('${device.ip}')" class="mt-2 w-full bg-blue-600 hover:bg-blue-500 text-white text-xs py-1 rounded transition">
                Scan This IP
            </button>
        `;
        list.appendChild(div);
    });
    
    section.classList.remove('hidden');
}

function selectDevice(ip) {
    document.getElementById('scan-target').value = ip;
    console.log("Selected device:", ip);
}

// 1. Fetch and display the scan history
let allScanHistory = [];
let showingMore = false;

async function fetchHistory() {
    try {
        const response = await fetch('/api/history');
        if (!response.ok) throw new Error('Failed to fetch history');
        
        const data = await response.json();
        allScanHistory = data;
        const tableBody = document.getElementById('history-body');
        const avgScoreElem = document.getElementById('avg-score');
        
        tableBody.innerHTML = ''; 
        showingMore = false;

        if (!data || data.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="4" class="p-8 text-center text-slate-500">No scan history found. Run your first audit to see results.</td></tr>';
            avgScoreElem.innerText = '--';
            return;
        }

        // Update overall health (average score) based on ALL scans
        const totalScore = data.reduce((acc, curr) => acc + curr.score, 0);
        const avg = Math.round(totalScore / data.length);
        avgScoreElem.innerText = `${avg}/100`;
        avgScoreElem.className = `text-4xl font-bold mt-2 ${getScoreColorText(avg)}`;

        // Display only the first 10 scans
        const scansToDisplay = data.slice(0, 10);
        scansToDisplay.forEach(scan => {
            const row = `
                <tr class="border-b border-slate-700 hover:bg-slate-700/30 transition">
                    <td class="p-4 font-mono text-blue-400">${scan.ip}</td>
                    <td class="p-4">
                        <span class="px-3 py-1 rounded-full text-xs font-bold ${getScoreColor(scan.score)}">
                            ${scan.score}/100
                        </span>
                    </td>
                    <td class="p-4 text-slate-400 text-sm">${new Date(scan.timestamp).toLocaleString()}</td>
                    <td class="p-4 text-right">
                       <button onclick="viewDetails(${scan.id})" class="bg-slate-700 hover:bg-slate-600 text-white px-4 py-1.5 rounded-lg text-xs transition">
                         View Details
                       </button>
                    </td>
                </tr>
            `;
            tableBody.insertAdjacentHTML('beforeend', row);
        });

        // Add "Show More" button if there are more than 10 scans
        if (data.length > 10) {
            const showMoreRow = `
                <tr class="border-b border-slate-700">
                    <td colspan="4" class="p-4 text-center">
                        <button onclick="toggleShowMore()" class="bg-blue-600 hover:bg-blue-500 text-white px-6 py-2 rounded-lg text-sm transition font-medium">
                            Show More (${data.length - 10} more scans)
                        </button>
                    </td>
                </tr>
            `;
            tableBody.insertAdjacentHTML('beforeend', showMoreRow);
        }
    } catch (error) {
        console.error('Error fetching history:', error);
    }
}

function toggleShowMore() {
    const tableBody = document.getElementById('history-body');
    showingMore = !showingMore;

    if (showingMore) {
        // Show all scans
        const btn = event.target;
        const allScans = allScanHistory;
        
        // Keep the first 10, then add the rest
        tableBody.innerHTML = '';
        allScans.forEach(scan => {
            const row = `
                <tr class="border-b border-slate-700 hover:bg-slate-700/30 transition">
                    <td class="p-4 font-mono text-blue-400">${scan.ip}</td>
                    <td class="p-4">
                        <span class="px-3 py-1 rounded-full text-xs font-bold ${getScoreColor(scan.score)}">
                            ${scan.score}/100
                        </span>
                    </td>
                    <td class="p-4 text-slate-400 text-sm">${new Date(scan.timestamp).toLocaleString()}</td>
                    <td class="p-4 text-right">
                       <button onclick="viewDetails(${scan.id})" class="bg-slate-700 hover:bg-slate-600 text-white px-4 py-1.5 rounded-lg text-xs transition">
                         View Details
                       </button>
                    </td>
                </tr>
            `;
            tableBody.insertAdjacentHTML('beforeend', row);
        });

        // Show "Show Less" button
        const showLessRow = `
            <tr class="border-b border-slate-700">
                <td colspan="4" class="p-4 text-center">
                    <button onclick="toggleShowMore()" class="bg-blue-600 hover:bg-blue-500 text-white px-6 py-2 rounded-lg text-sm transition font-medium">
                        Show Less
                    </button>
                </td>
            </tr>
        `;
        tableBody.insertAdjacentHTML('beforeend', showLessRow);
    } else {
        // Show only first 10
        fetchHistory();
    }
}

// 2. Trigger a new scan
async function startScan() {
    console.log("Button clicked: starting scan...");
    const btn = document.getElementById('scan-btn');
    if (!btn) {
        console.error("❌ Scan button not found!");
        return;
    }

    // Get the target from input or use localhost
    const targetInput = document.getElementById('scan-target');
    const target = targetInput ? targetInput.value.trim() : '';
    
    if (!target) {
        alert('Please specify a target IP, range, or use the Detect button');
        return;
    }

    btn.disabled = true;
    btn.classList.add('opacity-50', 'cursor-not-allowed');
    const originalContent = btn.innerHTML;
    
    btn.innerHTML = `
        <svg class="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
        Scanning...
    `;

    try {
        const response = await fetch('/api/scan', { 
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip_range: target })
        });
        if (!response.ok) throw new Error(`Server returned error: ${response.status} ${response.statusText}`);

        const result = await response.json();
        console.log("Scan response:", result);
        
        if (!result || !result.status) {
            throw new Error('Invalid response from server');
        }
        
        if (result.status === 'success') {
            await fetchHistory(); 
            console.log("✅ Scan successful, results:", result.results);
            alert(`Scan completed successfully! Scanned ${result.results ? result.results.length : 1} target(s).`);
        } else {
            throw new Error(`Server returned status: ${result.status}`);
        }
    } catch (error) {
        console.error('❌ Scan error:', error);
        alert(`Failed to start scan: ${error.message}\n\nMake sure your Go server is running at http://localhost:8080`);
    } finally {
        btn.disabled = false;
        btn.classList.remove('opacity-50', 'cursor-not-allowed');
        btn.innerHTML = originalContent;
    }
}

// 3. View individual scan findings
async function viewDetails(scanId) {
    const modal = document.getElementById('details-modal');
    const content = document.getElementById('modal-content');
    
    modal.classList.remove('hidden');
    content.innerHTML = '<p class="text-center py-10 text-slate-400">Fetching detailed vulnerability data...</p>';

    try {
        const response = await fetch(`/api/details?id=${scanId}`);
        const details = await response.json();

        if (!details || details.length === 0) {
            content.innerHTML = '<p class="text-center py-10">No detailed port data found for this scan.</p>';
            return;
        }

        let html = '<div class="space-y-6">';
        details.forEach(item => {
            // Parse vulnerabilities from JSON string if needed
            let vuls = item.vulnerabilities || [];
            if (typeof vuls === 'string') {
                try {
                    vuls = JSON.parse(vuls);
                } catch (e) {
                    console.error('Failed to parse vulnerabilities:', e);
                    vuls = [];
                }
            }
            html += `
                <div class="border-l-2 border-blue-500 pl-4 py-1 bg-slate-900/20 rounded-r-lg p-3">
                    <div class="flex justify-between items-start mb-2">
                        <div>
                            <span class="text-blue-400 font-mono font-bold text-lg">Port ${item.port}</span>
                            <p class="text-slate-400 italic">${item.service} ${item.version}</p>
                        </div>
                        <span class="text-xs bg-slate-700 px-2 py-1 rounded text-slate-400">
                            ${vuls.length} CVEs
                        </span>
                    </div>
                    ${renderVulnerabilities(vuls)}
                </div>
            `;
        });
        html += '</div>';
        content.innerHTML = html;

    } catch (error) {
        console.error('Error fetching details:', error);
        content.innerHTML = '<p class="text-red-400">Error loading details.</p>';
    }
}

// Helpers
function renderVulnerabilities(vuls) {
    if (!vuls || vuls.length === 0) return '<p class="text-emerald-400 text-xs">✅ No known vulnerabilities.</p>';
    
    return vuls.map(v => `
        <div class="bg-slate-900/50 p-2 mt-2 rounded border border-slate-700/50 text-xs">
            <span class="text-red-400 font-bold">${v.id}</span> 
            <span class="text-slate-500 ml-2">Score: ${v.score}</span>
            <p class="text-slate-400 mt-1">${v.description || 'No description available.'}</p>
        </div>
    `).join('');
}

function closeModal() {
    document.getElementById('details-modal').classList.add('hidden');
}

function getScoreColor(score) {
    if (score >= 90) return 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/50';
    if (score >= 70) return 'bg-amber-500/20 text-amber-400 border border-amber-500/50';
    return 'bg-red-500/20 text-red-400 border border-red-500/50';
}

function getScoreColorText(score) {
    if (score >= 90) return 'text-emerald-400';
    if (score >= 70) return 'text-amber-400';
    return 'text-red-400';
}

// 4. Initialization Logic
document.addEventListener('DOMContentLoaded', () => {
    console.log("🚀 SME-Shield initialized");
    fetchHistory();
    detectSubnet();
    
    // Check if button is accessible
    const btn = document.getElementById('scan-btn');
    if (!btn) {
        console.error("❌ ERROR: Button with ID 'scan-btn' not found in HTML!");
    } else {
        console.log("✅ Scan button linked successfully.");
    }
});

// Close modal when clicking outside
window.onclick = (event) => {
    const modal = document.getElementById('details-modal');
    if (event.target == modal) closeModal();
}