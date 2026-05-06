async function fetchHistory() {
    try {
        const response = await fetch('/api/history');
        const data = await response.json();
        
        const tableBody = document.getElementById('history-body');
        tableBody.innerHTML = ''; // Clear current rows

        // If no data, show a message
        if (!data || data.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="4" class="p-8 text-center text-slate-500">No scan history found. Run your first audit to see results.</td></tr>';
            return;
        }

        data.forEach(scan => {
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
    } catch (error) {
        console.error('Error fetching history:', error);
    }
}

async function viewDetails(scanId) {
    const modal = document.getElementById('details-modal');
    const content = document.getElementById('modal-content');
    
    // Show modal and loading state
    modal.classList.remove('hidden');
    content.innerHTML = '<p class="text-center py-10">Fetching detailed vulnerability data...</p>';

    try {
        const response = await fetch(`/api/details?id=${scanId}`);
        const details = await response.json();

        if (!details || details.length === 0) {
            content.innerHTML = '<p class="text-center py-10">No detailed port data found for this scan.</p>';
            return;
        }

        let html = '<div class="space-y-6">';
        details.forEach(item => {
            const vuls = item.vulnerabilities || [];
            html += `
                <div class="border-l-2 border-blue-500 pl-4 py-1">
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
        content.innerHTML = '<p class="text-red-400">Error loading details. Ensure the server is running.</p>';
    }
}

function renderVulnerabilities(vuls) {
    if (vuls.length === 0) return '<p class="text-emerald-400 text-xs">✅ No known vulnerabilities for this service.</p>';
    
    return vuls.map(v => `
        <div class="bg-slate-900/50 p-2 mt-2 rounded border border-slate-700/50 text-xs">
            <span class="text-red-400 font-bold">${v.id}</span> 
            <span class="text-slate-500 ml-2">Score: ${v.score}</span>
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

// Close modal when clicking outside of it
window.onclick = function(event) {
    const modal = document.getElementById('details-modal');
    if (event.target == modal) {
        closeModal();
    }
}

window.onload = fetchHistory;