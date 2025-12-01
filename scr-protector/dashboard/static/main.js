/**
 * scr-protector Dashboard JavaScript
 * Handles tab switching, API calls, and UI interactions
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tabs
    initTabs();
    
    // Initialize block form
    initBlockForm();
    
    // Refresh data periodically
    setInterval(refreshStats, 30000);
});

/**
 * Tab Navigation
 */
function initTabs() {
    const tabs = document.querySelectorAll('.tab');
    const contents = document.querySelectorAll('.tab-content');
    
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            // Remove active class from all
            tabs.forEach(t => t.classList.remove('active'));
            contents.forEach(c => c.classList.remove('active'));
            
            // Add active to clicked tab
            tab.classList.add('active');
            
            // Show corresponding content
            const tabId = tab.dataset.tab + '-tab';
            const content = document.getElementById(tabId);
            if (content) {
                content.classList.add('active');
            }
        });
    });
}

/**
 * Block IP Form
 */
function initBlockForm() {
    const form = document.getElementById('block-form');
    const resultDiv = document.getElementById('block-result');
    
    if (form) {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const ip = document.getElementById('block-ip').value.trim();
            const notes = document.getElementById('block-notes').value.trim();
            
            if (!ip) {
                showResult(resultDiv, 'error', 'Please enter an IP address');
                return;
            }
            
            try {
                const response = await fetch('/api/block', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ ip, notes }),
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showResult(resultDiv, 'success', `IP ${ip} has been blocked`);
                    form.reset();
                    refreshBlockedList();
                } else {
                    showResult(resultDiv, 'error', data.error || 'Failed to block IP');
                }
            } catch (err) {
                showResult(resultDiv, 'error', 'Network error: ' + err.message);
            }
        });
    }
}

/**
 * Block IP from anywhere (e.g., alerts table)
 */
async function blockIP(ip) {
    if (!confirm(`Block IP ${ip}?`)) {
        return;
    }
    
    try {
        const response = await fetch('/api/block', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ ip, notes: 'Blocked from alerts view' }),
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert(`IP ${ip} has been blocked`);
            location.reload();
        } else {
            alert('Error: ' + (data.error || 'Failed to block IP'));
        }
    } catch (err) {
        alert('Network error: ' + err.message);
    }
}

/**
 * Unblock IP
 */
async function unblockIP(ip) {
    if (!confirm(`Unblock IP ${ip}?`)) {
        return;
    }
    
    try {
        const response = await fetch('/api/unblock', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ ip }),
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Remove row from table
            const row = document.querySelector(`tr[data-ip="${ip}"]`);
            if (row) {
                row.remove();
            }
        } else {
            alert('Error: ' + (data.error || 'Failed to unblock IP'));
        }
    } catch (err) {
        alert('Network error: ' + err.message);
    }
}

/**
 * Show result message
 */
function showResult(element, type, message) {
    if (!element) return;
    
    element.className = 'result-message ' + type;
    element.textContent = message;
    element.style.display = 'block';
    
    // Hide after 5 seconds
    setTimeout(() => {
        element.style.display = 'none';
    }, 5000);
}

/**
 * Refresh blocked IPs list
 */
async function refreshBlockedList() {
    try {
        const response = await fetch('/api/blocked');
        const data = await response.json();
        
        const tbody = document.getElementById('blocked-list');
        if (!tbody) return;
        
        tbody.innerHTML = data.map(ip => `
            <tr data-ip="${escapeHtml(ip.ip)}">
                <td class="ip">${escapeHtml(ip.ip)}</td>
                <td>${escapeHtml(ip.time)}</td>
                <td>${escapeHtml(ip.source || 'manual')}</td>
                <td>${escapeHtml(ip.notes || '-')}</td>
                <td>
                    <button class="btn btn-sm btn-success" onclick="unblockIP('${escapeHtml(ip.ip)}')">Unblock</button>
                </td>
            </tr>
        `).join('');
    } catch (err) {
        console.error('Failed to refresh blocked list:', err);
    }
}

/**
 * Refresh statistics
 */
async function refreshStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();
        
        // Update stat cards if we add IDs to them
        console.log('Stats refreshed:', data);
    } catch (err) {
        console.error('Failed to refresh stats:', err);
    }
}

/**
 * Format timestamp
 */
function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
