// ════════════════════════════════════════════════════════════════════
// BLUE TEAM — SOC Dashboard JavaScript
// ════════════════════════════════════════════════════════════════════

const socket = io('/blue');

// ─── STATE ───
let allAlerts = [];
let currentFilter = { source: 'all', severity: '' };
let dashboardData = {};

// ─── INIT ───
document.addEventListener('DOMContentLoaded', () => {
    initWebSocket();
    loadDashboard();
    loadAlerts();
    loadFirewallRules();
    loadBlockedIPs();
    loadIDSRules();
    loadLogs();
    attachEventListeners();
    
    // Poll every 3s
    setInterval(loadDashboard, 3000);
    setInterval(checkSnortStatus, 5000);
});

// ═══════════════════════════════════════════════════════════════════
// WEBSOCKET
// ═══════════════════════════════════════════════════════════════════

function initWebSocket() {
    socket.on('connect', () => {
        console.log('[WS] Connected to Blue Team');
    });
    
    // IDS alert
    socket.on('security_alert', (alert) => {
        console.log('[WS] IDS Alert:', alert);
        addAlertToFeed(alert);
        updateMetrics();
    });
    
    // Snort alert
    socket.on('snort_alert', (alert) => {
        console.log('[WS] Snort Alert:', alert);
        addAlertToFeed(alert);
        updateMetrics();
    });
    
    // Log update
    socket.on('log_update', (log) => {
        addLogEntry(log);
    });
    
    // Snort status
    socket.on('snort_status', (status) => {
        updateSnortPill(status.is_running);
    });
    
    // Attack correlation
    socket.on('attack_correlation', (data) => {
        showNotification(`Snort detected ${data.snort_alerts} activities related to attack ${data.attack_id}`, 'info');
    });
}

// ═══════════════════════════════════════════════════════════════════
// DASHBOARD METRICS
// ═══════════════════════════════════════════════════════════════════

async function loadDashboard() {
    try {
        const res = await fetch('/api/blue/dashboard');
        dashboardData = await res.json();
        
        document.getElementById('securityScore').textContent = dashboardData.security_score || 100;
        document.getElementById('activeThreats').textContent = dashboardData.active_threats || 0;
        document.getElementById('totalAlerts').textContent = dashboardData.total_alerts || 0;
        document.getElementById('snortAlertCount').textContent = dashboardData.snort_alerts || 0;
        document.getElementById('blockedAttacks').textContent = dashboardData.blocked_attacks || 0;
        
        const statusEl = document.getElementById('systemStatus');
        if (dashboardData.system_status === 'compromised') {
            statusEl.innerHTML = '<i class="fas fa-circle"></i> Compromised';
            statusEl.classList.add('compromised');
        } else {
            statusEl.innerHTML = '<i class="fas fa-circle"></i> Operational';
            statusEl.classList.remove('compromised');
        }
        
        updateSnortPill(dashboardData.snort_enabled);
    } catch (err) {
        console.error('[Dashboard] Error:', err);
    }
}

async function updateMetrics() {
    loadDashboard();
}

// ═══════════════════════════════════════════════════════════════════
// SNORT STATUS
// ═══════════════════════════════════════════════════════════════════

function updateSnortPill(isRunning) {
    const pill = document.getElementById('snortPill');
    if (isRunning) {
        pill.classList.remove('offline');
        pill.innerHTML = '<i class="fas fa-circle snort-dot"></i> Snort';
    } else {
        pill.classList.add('offline');
        pill.innerHTML = '<i class="fas fa-circle snort-dot"></i> Snort';
    }
}

async function checkSnortStatus() {
    try {
        const res = await fetch('/api/blue/snort/status');
        if (res.ok) {
            const data = await res.json();
            updateSnortPill(data.is_running);
        }
    } catch (err) {
        updateSnortPill(false);
    }
}

// ═══════════════════════════════════════════════════════════════════
// ALERTS FEED
// ═══════════════════════════════════════════════════════════════════

async function loadAlerts() {
    try {
        const res = await fetch('/api/blue/alerts');
        allAlerts = await res.json();
        renderAlerts();
    } catch (err) {
        console.error('[Alerts] Error:', err);
    }
}

function renderAlerts() {
    const container = document.getElementById('alertFeed');
    
    let filtered = allAlerts.filter(a => {
        if (currentFilter.source !== 'all' && a.source !== currentFilter.source) return false;
        if (currentFilter.severity && a.severity !== currentFilter.severity) return false;
        return true;
    });
    
    if (filtered.length === 0) {
        container.innerHTML = '<div class="empty-state"><i class="fas fa-shield-alt"></i> No alerts matching filters</div>';
        return;
    }
    
    container.innerHTML = filtered.map(alert => createAlertHTML(alert)).join('');
}

function createAlertHTML(alert) {
    const severityClass = (alert.severity || 'Medium').toLowerCase();
    const sourceTag = alert.source === 'snort' ? 'snort' : 'ids';
    const sourceLabel = alert.source === 'snort' ? 'Snort' : 'IDS';
    
    return `
        <div class="alert-item ${severityClass}">
            <div class="alert-left">
                <strong>${alert.rule_name || alert.description || 'Security Alert'}</strong>
                <div class="alert-meta">${alert.source_ip || 'Unknown'} → ${alert.dest_ip || 'Target'} • ${formatTime(alert.timestamp)}</div>
            </div>
            <div class="alert-right">
                <div class="badge-row">
                    <span class="sev ${severityClass}">${alert.severity || 'Medium'}</span>
                    <span class="src ${sourceTag}">${sourceLabel}</span>
                </div>
                <div class="alert-actions">
                    ${alert.status !== 'acknowledged' ? `<button class="btn btn-small" onclick="acknowledgeAlert('${alert.id}')">Ack</button>` : ''}
                    ${alert.source_ip && !alert.blocked ? `<button class="btn btn-red btn-small" onclick="blockAlertIP('${alert.source_ip}')">Block</button>` : ''}
                </div>
            </div>
        </div>
    `;
}

function addAlertToFeed(alert) {
    allAlerts.unshift(alert);
    renderAlerts();
}

async function acknowledgeAlert(alertId) {
    try {
        await fetch(`/api/blue/alerts/${alertId}/acknowledge`, { method: 'POST' });
        const alert = allAlerts.find(a => a.id === alertId);
        if (alert) alert.status = 'acknowledged';
        renderAlerts();
        showNotification('Alert acknowledged', 'success');
    } catch (err) {
        showNotification('Failed to acknowledge alert', 'error');
    }
}

async function blockAlertIP(ip) {
    if (!confirm(`Block IP ${ip}?`)) return;
    try {
        await fetch('/api/blue/firewall/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        showNotification(`IP ${ip} blocked`, 'success');
        loadBlockedIPs();
        updateMetrics();
    } catch (err) {
        showNotification('Failed to block IP', 'error');
    }
}

// ═══════════════════════════════════════════════════════════════════
// FIREWALL
// ═══════════════════════════════════════════════════════════════════

async function loadFirewallRules() {
    try {
        const res = await fetch('/api/blue/firewall/rules');
        const rules = await res.json();
        
        const container = document.getElementById('firewallRulesList');
        if (rules.length === 0) {
            container.innerHTML = '<div class="empty-state">No firewall rules</div>';
            return;
        }
        
        container.innerHTML = rules.map(rule => `
            <div class="rule-item">
                <div class="rule-info">
                    <h4>${rule.name || 'Rule'}</h4>
                    <p>${rule.action || 'allow'} ${rule.protocol || 'any'} ${rule.source_ip || 'any'}:${rule.source_port || '*'} → ${rule.dest_ip || 'any'}:${rule.dest_port || '*'}</p>
                </div>
                <div class="rule-actions">
                    <button class="btn btn-red btn-small" onclick="deleteFirewallRule('${rule.id}')"><i class="fas fa-trash"></i></button>
                </div>
            </div>
        `).join('');
    } catch (err) {
        console.error('[Firewall] Error:', err);
    }
}

async function loadBlockedIPs() {
    try {
        const res = await fetch('/api/blue/firewall/blocked');
        const blocked = await res.json();
        
        const container = document.getElementById('blockedIPsList');
        if (blocked.length === 0) {
            container.innerHTML = '<div class="empty-state" style="font-size:.82rem;opacity:.5;">No blocked IPs</div>';
            return;
        }
        
        container.innerHTML = blocked.map(entry => `
            <div class="blocked-ip-item">
                <span>${entry.ip}</span>
                <button class="btn btn-small" onclick="unblockIP('${entry.ip}')" style="padding:2px 8px;font-size:.72rem;"><i class="fas fa-times"></i></button>
            </div>
        `).join('');
    } catch (err) {
        console.error('[Blocked IPs] Error:', err);
    }
}

async function deleteFirewallRule(ruleId) {
    if (!confirm('Delete this firewall rule?')) return;
    try {
        await fetch(`/api/blue/firewall/rules/${ruleId}`, { method: 'DELETE' });
        loadFirewallRules();
        showNotification('Firewall rule deleted', 'success');
    } catch (err) {
        showNotification('Failed to delete rule', 'error');
    }
}

async function unblockIP(ip) {
    try {
        await fetch('/api/blue/firewall/unblock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        loadBlockedIPs();
        showNotification(`IP ${ip} unblocked`, 'success');
    } catch (err) {
        showNotification('Failed to unblock IP', 'error');
    }
}

// ═══════════════════════════════════════════════════════════════════
// IDS RULES
// ═══════════════════════════════════════════════════════════════════

async function loadIDSRules() {
    try {
        const res = await fetch('/api/blue/ids/rules');
        const rules = await res.json();
        
        const container = document.getElementById('rulesList');
        if (rules.length === 0) {
            container.innerHTML = '<div class="empty-state">No IDS rules</div>';
            return;
        }
        
        container.innerHTML = rules.map(rule => `
            <div class="rule-item">
                <div class="rule-info">
                    <h4>${rule.name}</h4>
                    <small>${rule.description || ''}</small>
                </div>
                <div class="rule-actions">
                    <button class="btn btn-small ${rule.enabled ? 'btn-blue' : ''}" onclick="toggleIDSRule('${rule.id}')">${rule.enabled ? 'On' : 'Off'}</button>
                    <button class="btn btn-red btn-small" onclick="deleteIDSRule('${rule.id}')"><i class="fas fa-trash"></i></button>
                </div>
            </div>
        `).join('');
    } catch (err) {
        console.error('[IDS Rules] Error:', err);
    }
}

async function toggleIDSRule(ruleId) {
    try {
        await fetch(`/api/blue/ids/rules/${ruleId}/toggle`, { method: 'POST' });
        loadIDSRules();
    } catch (err) {
        showNotification('Failed to toggle rule', 'error');
    }
}

async function deleteIDSRule(ruleId) {
    if (!confirm('Delete this IDS rule?')) return;
    try {
        await fetch(`/api/blue/ids/rules/${ruleId}`, { method: 'DELETE' });
        loadIDSRules();
        showNotification('IDS rule deleted', 'success');
    } catch (err) {
        showNotification('Failed to delete rule', 'error');
    }
}

// ═══════════════════════════════════════════════════════════════════
// LOGS
// ═══════════════════════════════════════════════════════════════════

async function loadLogs() {
    try {
        const res = await fetch('/api/blue/logs?limit=50');
        const logs = await res.json();
        
        const container = document.getElementById('logViewer');
        if (logs.length === 0) {
            container.innerHTML = '<div style="opacity:.4;">No logs yet</div>';
            return;
        }
        
        container.innerHTML = logs.reverse().map(log => {
            const typeClass = log.type || 'system';
            return `<div class="log-entry ${typeClass}"><span class="log-time">${formatTime(log.timestamp)}</span><span class="log-type">[${log.type || 'sys'}]</span><span class="log-msg">${log.message}</span></div>`;
        }).join('');
        
        container.scrollTop = container.scrollHeight;
    } catch (err) {
        console.error('[Logs] Error:', err);
    }
}

function addLogEntry(log) {
    const container = document.getElementById('logViewer');
    const typeClass = log.type || 'system';
    const entry = document.createElement('div');
    entry.className = `log-entry ${typeClass}`;
    entry.innerHTML = `<span class="log-time">${formatTime(log.timestamp)}</span><span class="log-type">[${log.type || 'sys'}]</span><span class="log-msg">${log.message}</span>`;
    container.appendChild(entry);
    container.scrollTop = container.scrollHeight;
    
    // Keep only last 100
    while (container.children.length > 100) {
        container.removeChild(container.firstChild);
    }
}

// ═══════════════════════════════════════════════════════════════════
// EVENT LISTENERS
// ═══════════════════════════════════════════════════════════════════

function attachEventListeners() {
    // Feed filters
    document.querySelectorAll('.pill[data-filter]').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.pill[data-filter]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilter.source = btn.dataset.filter;
            renderAlerts();
        });
    });
    
    document.getElementById('feedSeverity').addEventListener('change', (e) => {
        currentFilter.severity = e.target.value;
        renderAlerts();
    });
    
    // Block IP
    document.getElementById('blockIPBtn').addEventListener('click', async () => {
        const ip = document.getElementById('blockIPInput').value.trim();
        if (!ip) {
            showNotification('Enter an IP address', 'error');
            return;
        }
        
        try {
            await fetch('/api/blue/firewall/block', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip })
            });
            document.getElementById('blockIPInput').value = '';
            loadBlockedIPs();
            showNotification(`IP ${ip} blocked`, 'success');
        } catch (err) {
            showNotification('Failed to block IP', 'error');
        }
    });
    
    // Add firewall rule
    document.getElementById('addFirewallRuleBtn').addEventListener('click', () => {
        const name = prompt('Rule name:');
        if (!name) return;
        
        const action = prompt('Action (allow/block):', 'block');
        const sourceIP = prompt('Source IP (or "any"):', 'any');
        
        fetch('/api/blue/firewall/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, action, source_ip: sourceIP, protocol: 'tcp' })
        }).then(() => {
            loadFirewallRules();
            showNotification('Firewall rule added', 'success');
        }).catch(() => {
            showNotification('Failed to add rule', 'error');
        });
    });
    
    // Add IDS rule
    document.getElementById('addRuleBtn').addEventListener('click', () => {
        const name = prompt('IDS Rule name:');
        if (!name) return;
        
        const pattern = prompt('Detection pattern (regex):');
        if (!pattern) return;
        
        fetch('/api/blue/ids/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, pattern, severity: 'Medium', enabled: true })
        }).then(() => {
            loadIDSRules();
            showNotification('IDS rule added', 'success');
        }).catch(() => {
            showNotification('Failed to add rule', 'error');
        });
    });
    
    // Clear logs
    document.getElementById('clearLogsBtn').addEventListener('click', () => {
        document.getElementById('logViewer').innerHTML = '';
        showNotification('Logs cleared', 'success');
    });
    
    // Log search
    document.getElementById('logSearch').addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        document.querySelectorAll('.log-entry').forEach(entry => {
            entry.style.display = entry.textContent.toLowerCase().includes(query) ? 'block' : 'none';
        });
    });
    
    // Log type filter
    document.getElementById('logTypeFilter').addEventListener('change', (e) => {
        const type = e.target.value;
        document.querySelectorAll('.log-entry').forEach(entry => {
            if (!type) {
                entry.style.display = 'block';
            } else {
                entry.style.display = entry.classList.contains(type) ? 'block' : 'none';
            }
        });
    });
    
    // Generate PDF report
    document.getElementById('generateAuditReport').addEventListener('click', generatePDFReport);
    
    // Export JSON
    document.getElementById('exportReportJSON').addEventListener('click', exportReportJSON);
}

// ═══════════════════════════════════════════════════════════════════
// REPORTS
// ═══════════════════════════════════════════════════════════════════

async function generatePDFReport() {
    const btn = document.getElementById('generateAuditReport');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating…';
    
    try {
        const res = await fetch('/api/blue/report/pdf', { method: 'POST' });
        if (!res.ok) throw new Error('PDF generation failed');
        
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `SOC_Audit_Report_${Date.now()}.pdf`;
        a.click();
        window.URL.revokeObjectURL(url);
        
        showNotification('PDF report generated', 'success');
    } catch (err) {
        showNotification('Failed to generate PDF', 'error');
        console.error(err);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-file-pdf"></i> Generate PDF';
    }
}

function exportReportJSON() {
    const report = {
        generated_at: new Date().toISOString(),
        dashboard: dashboardData,
        alerts: allAlerts,
        summary: {
            total_alerts: allAlerts.length,
            snort_alerts: allAlerts.filter(a => a.source === 'snort').length,
            ids_alerts: allAlerts.filter(a => a.source === 'ids').length,
            critical: allAlerts.filter(a => a.severity === 'Critical').length,
            high: allAlerts.filter(a => a.severity === 'High').length,
            medium: allAlerts.filter(a => a.severity === 'Medium').length,
            low: allAlerts.filter(a => a.severity === 'Low').length
        }
    };
    
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `soc_report_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    
    showNotification('JSON report exported', 'success');
}

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

function formatTime(timestamp) {
    if (!timestamp) return 'Unknown';
    try {
        const d = new Date(timestamp);
        return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
        return 'Invalid';
    }
}

function showNotification(message, type = 'info') {
    // Simple console notification for now
    console.log(`[${type.toUpperCase()}] ${message}`);
    
    // You can add a toast UI here if needed
    const toast = document.createElement('div');
    toast.style.cssText = `position:fixed;top:20px;right:20px;background:${type==='success'?'#28a745':type==='error'?'#dc3545':'#17a2b8'};color:#fff;padding:12px 20px;border-radius:8px;z-index:9999;animation:slideIn .3s;`;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.animation = 'slideOut .3s';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}