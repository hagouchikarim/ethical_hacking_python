// Blue Team JavaScript
const socket = io('/blue');
let trafficChart = null;
let alerts = [];
let logs = [];

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    setupEventListeners();
    connectWebSocket();
    loadDashboard();
    loadAlerts();
    loadLogs();
    loadIDSRules();
    loadFirewallRules();
    setupCharts();
    startDashboardRefresh();
});

// Setup event listeners
function setupEventListeners() {
    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => switchTab(e.target.dataset.tab));
    });
    
    // IDS sensitivity
    const sensitivity = document.getElementById('sensitivity');
    if (sensitivity) {
        sensitivity.addEventListener('input', (e) => {
            document.getElementById('sensitivityValue').textContent = e.target.value;
        });
    }
    
    // Block IP
    document.getElementById('blockIPBtn')?.addEventListener('click', blockIP);
    
    // Add rule buttons
    document.getElementById('addRuleBtn')?.addEventListener('click', () => addIDSRule());
    document.getElementById('addFirewallRuleBtn')?.addEventListener('click', () => addFirewallRule());
    
    // Alert filters
    document.getElementById('alertStatusFilter')?.addEventListener('change', loadAlerts);
    document.getElementById('alertSeverityFilter')?.addEventListener('change', loadAlerts);
    
    // Log filters
    document.getElementById('logSearch')?.addEventListener('input', loadLogs);
    document.getElementById('logTypeFilter')?.addEventListener('change', loadLogs);
    document.getElementById('logSeverityFilter')?.addEventListener('change', loadLogs);
    
    // Report generation
    document.getElementById('generatePostureReport')?.addEventListener('click', () => generateReport('posture'));
    document.getElementById('generateIncidentReport')?.addEventListener('click', () => generateReport('incident'));
    document.getElementById('generateComplianceReport')?.addEventListener('click', () => generateReport('compliance'));
}

// Connect WebSocket
function connectWebSocket() {
    socket.on('connect', () => {
        console.log('Connected to Blue Team server');
    });
    
    socket.on('security_alert', (alert) => {
        alerts.unshift(alert);
        displayAlert(alert);
        updateDashboard();
    });
    
    socket.on('log_update', (log) => {
        logs.unshift(log);
        displayLog(log);
        if (logs.length > 1000) logs.pop();
    });
}

// Load dashboard
async function loadDashboard() {
    try {
        const response = await fetch('/api/blue/dashboard');
        const data = await response.json();
        updateDashboardMetrics(data);
    } catch (error) {
        console.error('Error loading dashboard:', error);
    }
}

// Update dashboard metrics
function updateDashboardMetrics(data) {
    document.getElementById('securityScore').textContent = data.security_score;
    document.getElementById('activeThreats').textContent = data.active_threats;
    document.getElementById('totalAlerts').textContent = data.total_alerts;
    document.getElementById('blockedAttacks').textContent = data.blocked_attacks;
    
    const status = document.getElementById('systemStatus');
    if (data.system_status === 'operational') {
        status.innerHTML = '<i class="fas fa-circle"></i> Operational';
        status.style.color = '#28a745';
    } else {
        status.innerHTML = '<i class="fas fa-circle"></i> Compromised';
        status.style.color = '#dc3545';
    }
    
    // Update security score color
    const score = parseInt(data.security_score);
    const scoreElement = document.getElementById('securityScore');
    if (score >= 80) {
        scoreElement.style.color = '#28a745';
    } else if (score >= 50) {
        scoreElement.style.color = '#ffc107';
    } else {
        scoreElement.style.color = '#dc3545';
    }
}

// Load alerts
async function loadAlerts() {
    try {
        const statusFilter = document.getElementById('alertStatusFilter')?.value || '';
        const severityFilter = document.getElementById('alertSeverityFilter')?.value || '';
        
        let url = '/api/blue/alerts?';
        if (statusFilter) url += `status=${statusFilter}&`;
        if (severityFilter) url += `severity=${severityFilter}`;
        
        const response = await fetch(url);
        alerts = await response.json();
        displayAlerts();
    } catch (error) {
        console.error('Error loading alerts:', error);
    }
}

// Display alerts
function displayAlerts() {
    const feed = document.getElementById('alertFeed');
    const queue = document.getElementById('alertQueue');
    
    if (feed) {
        feed.innerHTML = '';
        alerts.slice(0, 10).forEach(alert => {
            const item = document.createElement('div');
            item.className = `alert-item ${alert.severity.toLowerCase()}`;
            item.innerHTML = `
                <div class="alert-header">
                    <strong>${alert.rule_name}</strong>
                    <span class="alert-severity">${alert.severity}</span>
                </div>
                <p>${alert.description}</p>
                <small>${new Date(alert.timestamp).toLocaleString()}</small>
            `;
            feed.appendChild(item);
        });
    }
    
    if (queue) {
        queue.innerHTML = '';
        alerts.forEach(alert => {
            const card = document.createElement('div');
            card.className = `alert-card ${alert.severity.toLowerCase()}`;
            card.innerHTML = `
                <div class="alert-header">
                    <h4>${alert.rule_name}</h4>
                    <span class="badge ${alert.severity.toLowerCase()}">${alert.severity}</span>
                </div>
                <p><strong>Source IP:</strong> ${alert.source_ip}</p>
                <p><strong>Description:</strong> ${alert.description}</p>
                <p><strong>Time:</strong> ${new Date(alert.timestamp).toLocaleString()}</p>
                <p><strong>Status:</strong> ${alert.status}</p>
                <div class="alert-actions">
                    <button class="btn btn-small btn-blue" onclick="acknowledgeAlert('${alert.id}')">
                        <i class="fas fa-check"></i> Acknowledge
                    </button>
                    <button class="btn btn-small btn-red" onclick="blockSourceIP('${alert.source_ip}')">
                        <i class="fas fa-ban"></i> Block IP
                    </button>
                </div>
            `;
            queue.appendChild(card);
        });
    }
}

// Display single alert
function displayAlert(alert) {
    const feed = document.getElementById('alertFeed');
    if (feed) {
        const item = document.createElement('div');
        item.className = `alert-item ${alert.severity.toLowerCase()}`;
        item.innerHTML = `
            <div class="alert-header">
                <strong>${alert.rule_name}</strong>
                <span class="alert-severity">${alert.severity}</span>
            </div>
            <p>${alert.description}</p>
            <small>${new Date(alert.timestamp).toLocaleString()}</small>
        `;
        feed.insertBefore(item, feed.firstChild);
        if (feed.children.length > 10) {
            feed.removeChild(feed.lastChild);
        }
    }
}

// Acknowledge alert
async function acknowledgeAlert(alertId) {
    try {
        await fetch(`/api/blue/alerts/${alertId}/acknowledge`, { method: 'POST' });
        loadAlerts();
    } catch (error) {
        console.error('Error acknowledging alert:', error);
    }
}

// Block source IP
async function blockSourceIP(ip) {
    try {
        await fetch('/api/blue/firewall/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        loadFirewallRules();
        alert(`IP ${ip} has been blocked`);
    } catch (error) {
        console.error('Error blocking IP:', error);
    }
}

// Load logs
async function loadLogs() {
    try {
        const search = document.getElementById('logSearch')?.value || '';
        const typeFilter = document.getElementById('logTypeFilter')?.value || '';
        const severityFilter = document.getElementById('logSeverityFilter')?.value || '';
        
        let url = '/api/blue/logs?limit=100';
        if (typeFilter) url += `&type=${typeFilter}`;
        if (severityFilter) url += `&severity=${severityFilter}`;
        
        const response = await fetch(url);
        logs = await response.json();
        
        // Filter by search term
        if (search) {
            logs = logs.filter(log => 
                log.message.toLowerCase().includes(search.toLowerCase())
            );
        }
        
        displayLogs();
    } catch (error) {
        console.error('Error loading logs:', error);
    }
}

// Display logs
function displayLogs() {
    const viewer = document.getElementById('logViewer');
    if (!viewer) return;
    
    viewer.innerHTML = '';
    logs.forEach(log => {
        const entry = document.createElement('div');
        entry.className = `log-entry ${log.severity || 'info'}`;
        entry.innerHTML = `
            <span class="log-time">[${new Date(log.timestamp).toLocaleTimeString()}]</span>
            <span class="log-type">[${log.type || 'system'}]</span>
            <span class="log-message">${log.message}</span>
        `;
        viewer.appendChild(entry);
    });
}

// Display single log
function displayLog(log) {
    const viewer = document.getElementById('logViewer');
    if (viewer) {
        const entry = document.createElement('div');
        entry.className = `log-entry ${log.severity || 'info'}`;
        entry.innerHTML = `
            <span class="log-time">[${new Date(log.timestamp).toLocaleTimeString()}]</span>
            <span class="log-type">[${log.type || 'system'}]</span>
            <span class="log-message">${log.message}</span>
        `;
        viewer.insertBefore(entry, viewer.firstChild);
        if (viewer.children.length > 100) {
            viewer.removeChild(viewer.lastChild);
        }
    }
}

// Load IDS rules
async function loadIDSRules() {
    try {
        const response = await fetch('/api/blue/ids/rules');
        const rules = await response.json();
        displayIDSRules(rules);
    } catch (error) {
        console.error('Error loading IDS rules:', error);
    }
}

// Display IDS rules
function displayIDSRules(rules) {
    const list = document.getElementById('rulesList');
    if (!list) return;
    
    list.innerHTML = '';
    rules.forEach(rule => {
        const item = document.createElement('div');
        item.className = 'rule-item';
        item.innerHTML = `
            <div class="rule-info">
                <h4>${rule.name}</h4>
                <p>${rule.description}</p>
                <small>Severity: ${rule.severity} | ${rule.enabled ? 'Enabled' : 'Disabled'}</small>
            </div>
            <div class="rule-actions">
                <button class="btn btn-small" onclick="toggleIDSRule('${rule.id}')">
                    <i class="fas fa-toggle-${rule.enabled ? 'on' : 'off'}"></i>
                </button>
                <button class="btn btn-small btn-red" onclick="deleteIDSRule('${rule.id}')">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `;
        list.appendChild(item);
    });
}

// Toggle IDS rule
async function toggleIDSRule(ruleId) {
    // This would require a toggle endpoint
    loadIDSRules();
}

// Delete IDS rule
async function deleteIDSRule(ruleId) {
    if (confirm('Are you sure you want to delete this rule?')) {
        try {
            await fetch(`/api/blue/ids/rules/${ruleId}`, { method: 'DELETE' });
            loadIDSRules();
        } catch (error) {
            console.error('Error deleting rule:', error);
        }
    }
}

// Add IDS rule
function addIDSRule() {
    const name = prompt('Rule name:');
    const pattern = prompt('Pattern (regex):');
    const severity = prompt('Severity (Critical/High/Medium/Low):', 'Medium');
    
    if (name && pattern) {
        fetch('/api/blue/ids/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, pattern, severity, enabled: true, description: 'Custom rule' })
        }).then(() => loadIDSRules());
    }
}

// Load firewall rules
async function loadFirewallRules() {
    try {
        const response = await fetch('/api/blue/firewall/rules');
        const rules = await response.json();
        displayFirewallRules(rules);
        
        // Also load blocked IPs
        const blockedIPs = rules.filter(r => r.action === 'block').map(r => r.source_ip);
        displayBlockedIPs(blockedIPs);
    } catch (error) {
        console.error('Error loading firewall rules:', error);
    }
}

// Display firewall rules
function displayFirewallRules(rules) {
    const list = document.getElementById('firewallRulesList');
    if (!list) return;
    
    list.innerHTML = '';
    rules.forEach(rule => {
        const item = document.createElement('div');
        item.className = 'rule-item';
        item.innerHTML = `
            <div class="rule-info">
                <h4>${rule.name}</h4>
                <p>${rule.action.toUpperCase()} - ${rule.source_ip} | ${rule.protocol} | Port: ${rule.port}</p>
                <small>${rule.enabled ? 'Enabled' : 'Disabled'}</small>
            </div>
            <div class="rule-actions">
                <button class="btn btn-small btn-red" onclick="deleteFirewallRule('${rule.id}')">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `;
        list.appendChild(item);
    });
}

// Display blocked IPs
function displayBlockedIPs(ips) {
    const list = document.getElementById('blockedIPsList');
    if (!list) return;
    
    list.innerHTML = '';
    [...new Set(ips)].forEach(ip => {
        const item = document.createElement('div');
        item.className = 'blocked-ip-item';
        item.innerHTML = `
            <span>${ip}</span>
            <button class="btn btn-small" onclick="unblockIP('${ip}')">
                <i class="fas fa-unlock"></i> Unblock
            </button>
        `;
        list.appendChild(item);
    });
}

// Delete firewall rule
async function deleteFirewallRule(ruleId) {
    if (confirm('Are you sure you want to delete this rule?')) {
        try {
            await fetch(`/api/blue/firewall/rules/${ruleId}`, { method: 'DELETE' });
            loadFirewallRules();
        } catch (error) {
            console.error('Error deleting rule:', error);
        }
    }
}

// Add firewall rule
function addFirewallRule() {
    const name = prompt('Rule name:');
    const action = prompt('Action (block/allow):', 'block');
    const sourceIP = prompt('Source IP (or "any"):', 'any');
    const protocol = prompt('Protocol (tcp/udp/all):', 'all');
    const port = prompt('Port (or "all"):', 'all');
    
    if (name && action) {
        fetch('/api/blue/firewall/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, action, source_ip: sourceIP, protocol, port, enabled: true })
        }).then(() => loadFirewallRules());
    }
}

// Block IP
async function blockIP() {
    const ip = document.getElementById('blockIPInput').value;
    if (!ip) {
        alert('Please enter an IP address');
        return;
    }
    
    try {
        await fetch('/api/blue/firewall/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        document.getElementById('blockIPInput').value = '';
        loadFirewallRules();
    } catch (error) {
        console.error('Error blocking IP:', error);
    }
}

// Unblock IP
async function unblockIP(ip) {
    // This would require an unblock endpoint
    alert(`Unblock functionality for ${ip} would be implemented here`);
}

// Setup charts
function setupCharts() {
    const ctx = document.getElementById('trafficChart');
    if (!ctx) return;
    
    // Set fixed height for canvas
    ctx.style.height = '300px';
    ctx.style.maxHeight = '300px';
    
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets/sec',
                data: [],
                borderColor: '#007bff',
                backgroundColor: 'rgba(0, 123, 255, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            aspectRatio: 2,
            plugins: {
                legend: {
                    display: true,
                    position: 'top'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                        stepSize: 20
                    }
                },
                x: {
                    ticks: {
                        maxRotation: 45,
                        minRotation: 45
                    }
                }
            },
            animation: {
                duration: 750
            }
        }
    });
    
    // Update chart periodically
    setInterval(() => {
        if (trafficChart && ctx.parentElement) {
            const now = new Date().toLocaleTimeString();
            const value = Math.floor(Math.random() * 100);
            
            trafficChart.data.labels.push(now);
            trafficChart.data.datasets[0].data.push(value);
            
            // Keep only last 15 data points to prevent growth
            if (trafficChart.data.labels.length > 15) {
                trafficChart.data.labels.shift();
                trafficChart.data.datasets[0].data.shift();
            }
            
            // Use update with mode to prevent full redraw
            trafficChart.update('none');
        }
    }, 2000);
}

// Switch tabs
function switchTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        if (btn.dataset.tab === tabName) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });
    
    document.querySelectorAll('.tab-content').forEach(content => {
        if (content.id === `${tabName}Tab`) {
            content.classList.add('active');
        } else {
            content.classList.remove('active');
        }
    });
}

// Generate report
function generateReport(type) {
    alert(`${type.charAt(0).toUpperCase() + type.slice(1)} report generation would be implemented here`);
}

// Update dashboard
function updateDashboard() {
    loadDashboard();
}

// Start dashboard refresh
function startDashboardRefresh() {
    setInterval(() => {
        loadDashboard();
        loadAlerts();
    }, 5000);
}
