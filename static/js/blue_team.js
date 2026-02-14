// ════════════════════════════════════════════════════════════════════
// BLUE TEAM — SOC Dashboard JavaScript (with Alert Correlation)
// ════════════════════════════════════════════════════════════════════

const socket = io('/blue');

// ─── STATE ───
let allIncidents = [];
let allAlerts = [];
let currentFilter = { source: 'all', severity: '', view: 'incidents' };  // Added view mode
let dashboardData = {};

// ─── INIT ───
document.addEventListener('DOMContentLoaded', () => {
    initWebSocket();
    loadDashboard();
    loadIncidents();  // Load correlated incidents instead of raw alerts
    loadFirewallRules();
    loadBlockedIPs();
    loadIDSRules();
    loadLogs();
    attachEventListeners();
    
    // Poll every 3s
    setInterval(loadDashboard, 3000);
    setInterval(loadIncidents, 2000);  // Refresh incidents frequently
    setInterval(checkSnortStatus, 15000);
    setInterval(autoCloseOldIncidents, 120000);  // Auto-close old incidents every 30s
});

// ═══════════════════════════════════════════════════════════════════
// WEBSOCKET
// ═══════════════════════════════════════════════════════════════════

function initWebSocket() {
    socket.on('connect', () => {
        console.log('[WS] Connected to Blue Team');
    });
    
    // New alert received - will be auto-correlated on backend
    socket.on('new_alert', (alert) => {
        console.log('[WS] IDS Alert:', alert);
        loadIncidents();  // Refresh incidents view
        updateMetrics();
    });
    
    // Snort alert
    socket.on('snort_alert', (alert) => {
        console.log('[WS] Snort Alert:', alert);
        loadIncidents();  // Refresh incidents view
        updateMetrics();
        showAlertToast(alert);  // Show brief toast notification
    });
    
    // Incident update
    socket.on('incident_update', (incident) => {
        console.log('[WS] Incident Updated:', incident);
        loadIncidents();
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
        document.getElementById('activeThreats').textContent = dashboardData.active_incidents || 0;  // Changed to incidents
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
// INCIDENTS VIEW (NEW - Correlated Alerts)
// ═══════════════════════════════════════════════════════════════════

async function loadIncidents() {
    try {
        const res = await fetch('/api/blue/incidents');
        allIncidents = await res.json();
        renderIncidents();
    } catch (err) {
        console.error('[Incidents] Error:', err);
    }
}

function renderIncidents() {
    const container = document.getElementById('alertFeed');
    
    // Filter incidents
    let filtered = allIncidents.filter(inc => {
        if (currentFilter.severity && inc.severity !== currentFilter.severity) return false;
        // Source filter for incidents (check if any alert source matches)
        if (currentFilter.source !== 'all') {
            if (!inc.sources || !inc.sources.includes(currentFilter.source)) return false;
        }
        return true;
    });
    
    if (filtered.length === 0) {
        container.innerHTML = '<div class="empty-state"><i class="fas fa-shield-alt"></i> No active incidents</div>';
        return;
    }
    
    container.innerHTML = filtered.map(incident => createIncidentHTML(incident)).join('');
}

function createIncidentHTML(incident) {
    const severityClass = (incident.severity || 'Medium').toLowerCase();
    const duration = incident.duration_seconds || 0;
    const durationText = duration > 60 ? `${Math.floor(duration / 60)}m ${duration % 60}s` : `${duration}s`;
    
    // Determine icon based on attack type
    const icons = {
        'sql_injection': 'fa-database',
        'brute_force': 'fa-key',
        'ddos': 'fa-bomb',
        'port_scanner': 'fa-search',
        'unknown': 'fa-exclamation-triangle'
    };
    const icon = icons[incident.attack_type] || icons.unknown;
    
    // Build source badges
    const sourceBadges = (incident.sources || ['unknown']).map(src => 
        `<span class="src ${src}">${src.toUpperCase()}</span>`
    ).join('');
    
    // Check if acknowledged or blocked
    const statusTags = [];
    if (incident.acknowledged) statusTags.push('<span class="status-tag ack">Acknowledged</span>');
    if (incident.blocked) statusTags.push('<span class="status-tag blocked">IP Blocked</span>');
    
    return `
        <div class="incident-card ${severityClass} ${incident.acknowledged ? 'acknowledged' : ''}" data-incident-id="${incident.id}">
            <div class="incident-header">
                <div class="incident-title">
                    <i class="fas ${icon}"></i>
                    <strong>${incident.description || 'Security Incident'}</strong>
                    <span class="incident-id">#${incident.id.substring(4, 12)}</span>
                </div>
                <div class="incident-meta">
                    <span class="sev ${severityClass}">${incident.severity}</span>
                    ${sourceBadges}
                </div>
            </div>
            
            <div class="incident-body">
                <div class="incident-stats">
                    <div class="stat">
                        <i class="fas fa-bell"></i>
                        <span><strong>${incident.alert_count}</strong> alerts</span>
                    </div>
                    <div class="stat">
                        <i class="fas fa-clock"></i>
                        <span><strong>${durationText}</strong> duration</span>
                    </div>
                    <div class="stat">
                        <i class="fas fa-network-wired"></i>
                        <span>${incident.source_ip} → ${incident.dest_ip}</span>
                    </div>
                </div>
                
                ${statusTags.length > 0 ? `<div class="status-tags">${statusTags.join('')}</div>` : ''}
                
                <div class="incident-timeline">
                    <small>First seen: ${formatTime(incident.first_seen)} | Last seen: ${formatTime(incident.last_seen)}</small>
                </div>
            </div>
            
            <div class="incident-actions">
                <button class="btn btn-small" onclick="viewIncidentDetails('${incident.id}')">
                    <i class="fas fa-info-circle"></i> Details
                </button>
                ${!incident.acknowledged ? `
                    <button class="btn btn-small" onclick="acknowledgeIncident('${incident.id}')">
                        <i class="fas fa-check"></i> Acknowledge
                    </button>
                ` : ''}
                ${!incident.blocked && incident.source_ip !== 'unknown' ? `
                    <button class="btn btn-red btn-small" onclick="blockIncidentIP('${incident.id}', '${incident.source_ip}')">
                        <i class="fas fa-ban"></i> Block IP
                    </button>
                ` : ''}
                <button class="btn btn-small" onclick="closeIncident('${incident.id}')">
                    <i class="fas fa-times"></i> Close
                </button>
            </div>
        </div>
    `;
}

async function viewIncidentDetails(incidentId) {
    try {
        const res = await fetch(`/api/blue/incidents/${incidentId}`);
        const incident = await res.json();
        
        // Create modal with full incident details
        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        modal.innerHTML = `
            <div class="modal-content incident-detail-modal">
                <div class="modal-header">
                    <h3><i class="fas fa-file-alt"></i> Incident Details: ${incident.description}</h3>
                    <button class="close-modal" onclick="this.closest('.modal-overlay').remove()">×</button>
                </div>
                <div class="modal-body">
                    <div class="detail-grid">
                        <div class="detail-item">
                            <strong>Incident ID:</strong>
                            <span>${incident.id}</span>
                        </div>
                        <div class="detail-item">
                            <strong>Attack Type:</strong>
                            <span>${incident.attack_type}</span>
                        </div>
                        <div class="detail-item">
                            <strong>Severity:</strong>
                            <span class="sev ${incident.severity.toLowerCase()}">${incident.severity}</span>
                        </div>
                        <div class="detail-item">
                            <strong>Source IP:</strong>
                            <span>${incident.source_ip}</span>
                        </div>
                        <div class="detail-item">
                            <strong>Destination:</strong>
                            <span>${incident.dest_ip}</span>
                        </div>
                        <div class="detail-item">
                            <strong>Alert Count:</strong>
                            <span>${incident.alert_count}</span>
                        </div>
                        <div class="detail-item">
                            <strong>Duration:</strong>
                            <span>${incident.duration_seconds}s</span>
                        </div>
                        <div class="detail-item">
                            <strong>Status:</strong>
                            <span>${incident.status}</span>
                        </div>
                    </div>
                    
                    <h4>Triggered Rules</h4>
                    <div class="rule-list">
                        ${incident.rule_names.map(rule => `<span class="rule-badge">${rule}</span>`).join('')}
                    </div>
                    
                    <h4>Detection Sources</h4>
                    <div class="source-list">
                        ${incident.sources.map(src => `<span class="src ${src}">${src.toUpperCase()}</span>`).join('')}
                    </div>
                    
                    <h4>Individual Alerts (${incident.alerts.length})</h4>
                    <div class="alert-list-detail">
                        ${incident.alerts.slice(0, 20).map(alert => `
                            <div class="alert-detail-item">
                                <small>${formatTime(alert.timestamp)}</small>
                                <strong>${alert.rule_name}</strong>
                                <span>${alert.source || 'IDS'}</span>
                            </div>
                        `).join('')}
                        ${incident.alerts.length > 20 ? `<p class="text-muted">... and ${incident.alerts.length - 20} more alerts</p>` : ''}
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    } catch (err) {
        showNotification('Failed to load incident details', 'error');
    }
}

async function acknowledgeIncident(incidentId) {
    try {
        await fetch(`/api/blue/incidents/${incidentId}/acknowledge`, { method: 'POST' });
        showNotification('Incident acknowledged', 'success');
        loadIncidents();
    } catch (err) {
        showNotification('Failed to acknowledge incident', 'error');
    }
}

async function blockIncidentIP(incidentId, ip) {
    if (!confirm(`Block IP ${ip} and mark incident as mitigated?`)) return;
    
    try {
        // Block the IP
        await fetch('/api/blue/firewall/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason: `Blocked from incident ${incidentId}` })
        });
        
        // Mark incident as blocked
        await fetch(`/api/blue/incidents/${incidentId}/block`, { method: 'POST' });
        
        showNotification(`IP ${ip} blocked`, 'success');
        loadBlockedIPs();
        loadIncidents();
        updateMetrics();
    } catch (err) {
        showNotification('Failed to block IP', 'error');
    }
}

async function closeIncident(incidentId) {
    if (!confirm('Close this incident?')) return;
    
    try {
        await fetch(`/api/blue/incidents/${incidentId}/close`, { method: 'POST' });
        showNotification('Incident closed', 'success');
        loadIncidents();
        updateMetrics();
    } catch (err) {
        showNotification('Failed to close incident', 'error');
    }
}

async function autoCloseOldIncidents() {
    try {
        await fetch('/api/blue/incidents/auto-close', { method: 'POST' });
    } catch (err) {
        console.error('[Auto-close] Error:', err);
    }
}

function showAlertToast(alert) {
    const toast = document.createElement('div');
    toast.className = 'alert-toast';
    toast.innerHTML = `
        <i class="fas fa-exclamation-circle"></i>
        <div>
            <strong>${alert.rule_name || 'New Alert'}</strong>
            <small>${alert.source_ip || 'Unknown'} detected</small>
        </div>
    `;
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.classList.add('fade-out');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
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
            container.innerHTML = '<div class="empty-state-small">No firewall rules</div>';
            return;
        }
        
        container.innerHTML = rules.map(rule => `
            <div class="rule-item ${rule.enabled ? '' : 'disabled'}">
                <div class="rule-left">
                    <strong>${rule.name}</strong>
                    <div class="rule-meta">${rule.action} | ${rule.protocol} | ${rule.source_ip}:${rule.port}</div>
                </div>
                <button class="btn btn-small btn-red" onclick="removeFirewallRule('${rule.id}')"><i class="fas fa-trash"></i></button>
            </div>
        `).join('');
    } catch (err) {
        console.error('[Firewall] Error:', err);
    }
}

async function removeFirewallRule(ruleId) {
    try {
        await fetch(`/api/blue/firewall/rules/${ruleId}`, { method: 'DELETE' });
        loadFirewallRules();
        showNotification('Rule removed', 'success');
    } catch (err) {
        showNotification('Failed to remove rule', 'error');
    }
}

async function loadBlockedIPs() {
    try {
        const res = await fetch('/api/blue/firewall/blocked');
        const blocked = await res.json();
        
        const container = document.getElementById('blockedIPsList');
        if (blocked.length === 0) {
            container.innerHTML = '<div class="empty-state-small">No blocked IPs</div>';
            return;
        }
        
        container.innerHTML = blocked.map(item => `
            <div class="blocked-ip-item">
                <div>
                    <strong>${item.ip}</strong>
                    <small>${item.reason || 'Security threat'}</small>
                </div>
                <button class="btn btn-small" onclick="unblockIP('${item.ip}')"><i class="fas fa-unlock"></i></button>
            </div>
        `).join('');
    } catch (err) {
        console.error('[Blocked IPs] Error:', err);
    }
}

async function unblockIP(ip) {
    if (!confirm(`Unblock IP ${ip}?`)) return;
    
    try {
        await fetch(`/api/blue/firewall/unblock/${ip}`, { method: 'POST' });
        loadBlockedIPs();
        showNotification(`IP ${ip} unblocked`, 'success');
    } catch (err) {
        showNotification('Failed to unblock IP', 'error');
    }
}

// ═══════════════════════════════════════════════════════════════════
// FIXED IDS RULES FUNCTION
// Replace the loadIDSRules() function in your blue_team.js with this:
// ═══════════════════════════════════════════════════════════════════

async function loadIDSRules() {
    try {
        const res = await fetch('/api/blue/ids/rules');
        const rules = await res.json();
        
        const container = document.getElementById('rulesList');
        container.innerHTML = rules.map(rule => {
            // Shorten long regex patterns for cleaner display
            let displayPattern = rule.pattern;
            if (displayPattern.length > 40) {
                displayPattern = displayPattern.substring(0, 40) + '...';
            }
            
            return `
                <div class="rule-item ${rule.enabled ? '' : 'disabled'}">
                    <div class="rule-left">
                        <strong>${rule.name}</strong>
                        <div class="rule-meta">
                            <span title="Full pattern: ${rule.pattern}">Pattern: ${displayPattern}</span>
                            <span style="margin-left: 16px; padding-left: 16px; border-left: 1px solid rgba(255,255,255,0.1);">Severity: ${rule.severity}</span>
                        </div>
                    </div>
                    <div class="rule-actions">
                        <button class="btn btn-small" onclick="toggleIDSRule('${rule.id}')">
                            ${rule.enabled ? 'Disable' : 'Enable'}
                        </button>
                        <button class="btn btn-small btn-red" onclick="removeIDSRule('${rule.id}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </div>
            `;
        }).join('');
    } catch (err) {
        console.error('[IDS] Error:', err);
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

async function removeIDSRule(ruleId) {
    try {
        await fetch(`/api/blue/ids/rules/${ruleId}`, { method: 'DELETE' });
        loadIDSRules();
        showNotification('Rule removed', 'success');
    } catch (err) {
        showNotification('Failed to remove rule', 'error');
    }
}

// ═══════════════════════════════════════════════════════════════════
// SYSTEM LOGS
// ═══════════════════════════════════════════════════════════════════

async function loadLogs() {
    try {
        const res = await fetch('/api/blue/logs');
        const logs = await res.json();
        
        const container = document.getElementById('logViewer');
        container.innerHTML = logs.slice(-100).map(log => {
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
            renderIncidents();
        });
    });
    
    document.getElementById('feedSeverity').addEventListener('change', (e) => {
        currentFilter.severity = e.target.value;
        renderIncidents();
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
        incidents: allIncidents,
        summary: {
            total_incidents: allIncidents.length,
            active_incidents: allIncidents.filter(i => i.status === 'active').length,
            critical: allIncidents.filter(i => i.severity === 'Critical').length,
            high: allIncidents.filter(i => i.severity === 'High').length,
            medium: allIncidents.filter(i => i.severity === 'Medium').length,
            low: allIncidents.filter(i => i.severity === 'Low').length
        }
    };
    
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `soc_incidents_${Date.now()}.json`;
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
    console.log(`[${type.toUpperCase()}] ${message}`);
    
    const toast = document.createElement('div');
    toast.style.cssText = `position:fixed;top:20px;right:20px;background:${type==='success'?'#28a745':type==='error'?'#dc3545':'#17a2b8'};color:#fff;padding:12px 20px;border-radius:8px;z-index:9999;animation:slideIn .3s;`;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.animation = 'slideOut .3s';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}