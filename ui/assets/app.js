async function fetchHistory() {
    try {
        const response = await fetch('/api/history');
        const data = await response.json();
        
        const tableBody = document.getElementById('history-body');
        tableBody.innerHTML = ''; // Clear current rows

        data.forEach(scan => {
            const row = `
                <tr class="border-b border-slate-700 hover:bg-slate-700/30 transition">
                    <td class="p-4 font-mono">${scan.ip}</td>
                    <td class="p-4">
                        <span class="px-3 py-1 rounded-full text-xs font-bold ${getScoreColor(scan.score)}">
                            ${scan.score}/100
                        </span>
                    </td>
                    <td class="p-4 text-slate-400 text-sm">${new Date(scan.timestamp).toLocaleString()}</td>
                    <td class="p-4 text-right">
                       <button onclick="viewDetails(${scan.id})" class="text-blue-400 hover:underline text-sm">View Details</button>
                    </td>
                </tr>
            `;
            tableBody.insertAdjacentHTML('beforeend', row);
        });
    } catch (error) {
        console.error('Etrror fetching history:', error);
    }
}

function getScoreColor(score) {
    if (score >= 90) return 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/50';
    if (score >= 70) return 'bg-amber-500/20 text-amber-400 border border-amber-500/50';
    return 'bg-red-500/20 text-red-400 border border-red-500/50';
}

// Load history when page opens
window.onload = fetchHistory;