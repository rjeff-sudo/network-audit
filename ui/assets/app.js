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
let filteredScanHistory = [];
let currentFilter = 'all';
let showingMore = false;

function getFilteredScans(filter) {
    const now = new Date();
    let filtered = [];

    allScanHistory.forEach(scan => {
        const scanDate = new Date(scan.timestamp);
        const daysDiff = Math.floor((now - scanDate) / (1000 * 60 * 60 * 24));

        if (filter === 'all') {
            filtered.push(scan);
        } else if (filter === 'week' && daysDiff <= 7) {
            filtered.push(scan);
        } else if (filter === '2days' && daysDiff <= 2) {
            filtered.push(scan);
        }
    });

    return filtered;
}

async function fetchHistory() {
    try {
        const response = await fetch('/api/history');
        if (!response.ok) throw new Error('Failed to fetch history');
        
        const data = await response.json();
        allScanHistory = data;
        currentFilter = 'all';
        filterHistory('all');
        
        const avgScoreElem = document.getElementById('avg-score');
        
        if (!data || data.length === 0) {
            avgScoreElem.innerText = '--';
            return;
        }

        // Update overall health (average score) based on ALL scans
        const totalScore = data.reduce((acc, curr) => acc + curr.score, 0);
        const avg = Math.round(totalScore / data.length);
        avgScoreElem.innerText = `${avg}/100`;
        avgScoreElem.className = `text-4xl font-bold mt-2 ${getScoreColorText(avg)}`;
    } catch (error) {
        console.error('Error fetching history:', error);
    }
}

function filterHistory(filter) {
    currentFilter = filter;
    filteredScanHistory = getFilteredScans(filter);
    showingMore = false;
    
    // Update filter button styling
    document.querySelectorAll('.filter-btn').forEach(btn => {
        if (btn.dataset.filter === filter) {
            btn.classList.remove('bg-slate-700', 'hover:bg-slate-600');
            btn.classList.add('bg-blue-600', 'hover:bg-blue-500');
        } else {
            btn.classList.remove('bg-blue-600', 'hover:bg-blue-500');
            btn.classList.add('bg-slate-700', 'hover:bg-slate-600');
        }
    });

    const tableBody = document.getElementById('history-body');
    tableBody.innerHTML = '';

    if (filteredScanHistory.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="4" class="p-8 text-center text-slate-500">No scans found for this filter.</td></tr>';
        return;
    }

    // Display only the first 10 scans
    const scansToDisplay = filteredScanHistory.slice(0, 10);
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

    // Add "Show More" button if there are more than 10 scans in the filter
    if (filteredScanHistory.length > 10) {
        const showMoreRow = `
            <tr class="border-b border-slate-700">
                <td colspan="4" class="p-4 text-center">
                    <button onclick="toggleShowMore()" class="bg-blue-600 hover:bg-blue-500 text-white px-6 py-2 rounded-lg text-sm transition font-medium">
                        Show More (${filteredScanHistory.length - 10} more scans)
                    </button>
                </td>
            </tr>
        `;
        tableBody.insertAdjacentHTML('beforeend', showMoreRow);
    }
}

function toggleShowMore() {
    const tableBody = document.getElementById('history-body');
    showingMore = !showingMore;

    if (showingMore) {
        // Show all filtered scans
        tableBody.innerHTML = '';
        filteredScanHistory.forEach(scan => {
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
        // Reset to showing first 10
        filterHistory(currentFilter);
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
        // Fetch details and scan info from history
        const response = await fetch(`/api/details?id=${scanId}`);
        const details = await response.json();

        // Find the scan in history to get score and IP
        const scan = allScanHistory.find(s => s.id === scanId);
        if (scan) {
            document.getElementById('scan-ip').textContent = `Target: ${scan.ip}`;
            document.getElementById('scan-score').textContent = `${scan.score}/100`;
            document.getElementById('scan-score').className = `text-3xl font-bold mt-1 ${getScoreColorText(scan.score)}`;
            document.getElementById('scan-date').textContent = new Date(scan.timestamp).toLocaleString();
        }

        if (!details || details.length === 0) {
            content.innerHTML = '<p class="text-center py-10">No detailed port data found for this scan.</p>';
            document.getElementById('scan-cve-count').textContent = '0';
            return;
        }

        // Count total CVEs across all ports
        let totalCVEs = 0;
        details.forEach(item => {
            let vuls = item.vulnerabilities || [];
            if (typeof vuls === 'string') {
                try {
                    vuls = JSON.parse(vuls);
                } catch (e) {}
            }
            totalCVEs += vuls.length;
        });
        document.getElementById('scan-cve-count').textContent = totalCVEs;

        // Group ports by risk level
        const grouped = groupByRisk(details);
        let html = '';

        // Critical vulnerabilities
        if (grouped.critical.length > 0) {
            html += renderRiskGroup('Critical', grouped.critical, 'critical');
        }

        // High vulnerabilities
        if (grouped.high.length > 0) {
            html += renderRiskGroup('High', grouped.high, 'high');
        }

        // Medium vulnerabilities
        if (grouped.medium.length > 0) {
            html += renderRiskGroup('Medium', grouped.medium, 'medium');
        }

        // Low & others
        if (grouped.low.length > 0) {
            html += renderRiskGroup('Low & Info', grouped.low, 'low');
        }

        // Clean ports (no vulnerabilities)
        if (grouped.clean.length > 0) {
            html += renderRiskGroup('Clean Ports', grouped.clean, 'clean');
        }

        if (!html) {
            html = '<p class="text-center py-10 text-emerald-400">✅ All ports are clean!</p>';
        }

        content.innerHTML = html;

    } catch (error) {
        console.error('Error fetching details:', error);
        content.innerHTML = '<p class="text-red-400">Error loading details.</p>';
    }
}

function groupByRisk(details) {
    const grouped = {
        critical: [],
        high: [],
        medium: [],
        low: [],
        clean: []
    };

    details.forEach(item => {
        let vuls = item.vulnerabilities || [];
        if (typeof vuls === 'string') {
            try {
                vuls = JSON.parse(vuls);
            } catch (e) {
                vuls = [];
            }
        }

        if (vuls.length === 0) {
            grouped.clean.push(item);
        } else {
            // Determine risk based on max severity
            const maxScore = Math.max(...vuls.map(v => v.score || 0));
            
            if (maxScore >= 9.0) {
                grouped.critical.push(item);
            } else if (maxScore >= 7.0) {
                grouped.high.push(item);
            } else if (maxScore >= 4.0) {
                grouped.medium.push(item);
            } else {
                grouped.low.push(item);
            }
        }
    });

    // Limit to top N per category
    grouped.critical = grouped.critical.slice(0, 20);
    grouped.high = grouped.high.slice(0, 20);
    grouped.medium = grouped.medium.slice(0, 20);

    return grouped;
}

function renderRiskGroup(label, items, riskLevel) {
    const colors = {
        critical: 'border-red-500 bg-red-500/5',
        high: 'border-orange-500 bg-orange-500/5',
        medium: 'border-amber-500 bg-amber-500/5',
        low: 'border-yellow-500 bg-yellow-500/5',
        clean: 'border-emerald-500 bg-emerald-500/5'
    };

    const badgeColors = {
        critical: 'bg-red-500/20 text-red-400 border-red-500/50',
        high: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
        medium: 'bg-amber-500/20 text-amber-400 border-amber-500/50',
        low: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
        clean: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/50'
    };

    const buttonId = `group-${riskLevel}`;
    const contentId = `content-${riskLevel}`;

    let html = `
        <div class="border-l-4 ${colors[riskLevel]} rounded-r-lg p-4 mb-4">
            <button onclick="toggleGroup('${contentId}')" class="w-full text-left flex justify-between items-center">
                <div class="flex items-center gap-3">
                    <h3 class="font-bold text-lg">${label}</h3>
                    <span class="px-3 py-1 rounded-full text-sm font-semibold ${badgeColors[riskLevel]}">
                        ${items.length} port${items.length !== 1 ? 's' : ''}
                    </span>
                </div>
                <span class="text-xl text-slate-400" id="${buttonId}">▼</span>
            </button>
            <div id="${contentId}" class="mt-4 space-y-3 hidden">
    `;

    items.forEach(item => {
        let vuls = item.vulnerabilities || [];
        if (typeof vuls === 'string') {
            try {
                vuls = JSON.parse(vuls);
            } catch (e) {
                vuls = [];
            }
        }

        html += `
            <div class="bg-slate-900/50 border border-slate-700 rounded-lg p-3 ml-2">
                <div class="flex justify-between items-start mb-2">
                    <div>
                        <span class="text-blue-400 font-mono font-bold text-base">Port ${item.port}</span>
                        <p class="text-slate-400 text-sm italic mt-1">${item.service} ${item.version}</p>
                    </div>
                    <span class="text-xs bg-slate-700 px-2 py-1 rounded text-slate-300">
                        ${vuls.length} CVE${vuls.length !== 1 ? 's' : ''}
                    </span>
                </div>
                ${renderVulnerabilities(vuls)}
            </div>
        `;
    });

    html += `
            </div>
        </div>
    `;

    return html;
}

function toggleGroup(contentId) {
    const content = document.getElementById(contentId);
    const button = document.getElementById('group-' + contentId.split('-')[1]);
    
    content.classList.toggle('hidden');
    button.style.transform = content.classList.contains('hidden') ? 'rotate(0deg)' : 'rotate(180deg)';
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