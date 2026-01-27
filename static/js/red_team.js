// Red Team JavaScript
const socket = io('/red');
let currentAttack = null;
let currentAttackMeta = null;      // { id, type, target }
let lastCompletedAttack = null;    // fallback when history is empty
let attackHistory = [];

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    loadAttacks();
    setupEventListeners();
    connectWebSocket();
});

// Load available attacks
async function loadAttacks() {
    try {
        const response = await fetch('/api/red/attacks');
        const attacks = await response.json();
        displayAttacks(attacks);
        populateAttackSelect(attacks);
    } catch (error) {
        console.error('Error loading attacks:', error);
    }
}

// Display attack cards
function displayAttacks(attacks) {
    const grid = document.getElementById('attackGrid');
    grid.innerHTML = '';
    
    attacks.forEach(attack => {
        const card = document.createElement('div');
        card.className = 'attack-card';
        card.dataset.attackId = attack.id;
        card.innerHTML = `
            <h3>${attack.name}</h3>
            <p>${attack.description}</p>
            <div class="attack-meta">
                <span class="badge">${attack.category}</span>
                <span class="status ${attack.status}">${attack.status}</span>
            </div>
        `;
        card.addEventListener('click', () => selectAttack(attack.id));
        grid.appendChild(card);
    });
}

// Populate attack select dropdown
function populateAttackSelect(attacks) {
    const select = document.getElementById('attackType');
    attacks.forEach(attack => {
        const option = document.createElement('option');
        option.value = attack.id;
        option.textContent = attack.name;
        select.appendChild(option);
    });
    
    select.addEventListener('change', (e) => {
        loadAttackParameters(e.target.value);
    });
}

// Load attack parameters
function loadAttackParameters(attackType) {
    const paramGroup = document.getElementById('parameterGroup');
    paramGroup.innerHTML = '';
    
    const params = {
        'sql_injection': [
            { name: 'intensity', label: 'Intensity', type: 'select', options: ['low', 'medium', 'high'] },
            { name: 'payloads', label: 'Custom Payloads (comma-separated)', type: 'text', placeholder: 'Optional' }
        ],
        'brute_force': [
            { name: 'username', label: 'Username', type: 'text', placeholder: 'admin' },
            { name: 'max_attempts', label: 'Max Attempts', type: 'number', value: 100 }
        ],
        'port_scanner': [
            { name: 'port_range', label: 'Port Range', type: 'text', placeholder: '1-1000', value: '1-1000' },
            { name: 'scan_type', label: 'Scan Type', type: 'select', options: ['tcp', 'udp', 'syn'] }
        ],
        'ddos': [
            { name: 'duration', label: 'Duration (seconds)', type: 'number', value: 30 },
            { name: 'intensity', label: 'Intensity', type: 'select', options: ['low', 'medium', 'high'] },
            { name: 'attack_type', label: 'Attack Type', type: 'select', options: ['http_flood', 'tcp_syn', 'udp_flood'] }
        ]
    };
    
    if (params[attackType]) {
        params[attackType].forEach(param => {
            const group = document.createElement('div');
            group.className = 'form-group';
            
            const label = document.createElement('label');
            label.textContent = param.label + ':';
            
            let input;
            if (param.type === 'select') {
                input = document.createElement('select');
                input.className = 'form-control';
                input.name = param.name;
                param.options.forEach(opt => {
                    const option = document.createElement('option');
                    option.value = opt;
                    option.textContent = opt;
                    input.appendChild(option);
                });
            } else {
                input = document.createElement('input');
                input.type = param.type;
                input.className = 'form-control';
                input.name = param.name;
                input.placeholder = param.placeholder || '';
                if (param.value) input.value = param.value;
            }
            
            group.appendChild(label);
            group.appendChild(input);
            paramGroup.appendChild(group);
        });
    }
}

// Select attack
function selectAttack(attackId) {
    document.querySelectorAll('.attack-card').forEach(card => {
        card.classList.remove('selected');
    });
    document.querySelector(`[data-attack-id="${attackId}"]`).classList.add('selected');
    document.getElementById('attackType').value = attackId;
    loadAttackParameters(attackId);
}

// Setup event listeners
function setupEventListeners() {
    document.getElementById('launchBtn').addEventListener('click', launchAttack);
    document.getElementById('abortBtn').addEventListener('click', abortAttack);
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => switchTab(e.target.dataset.tab));
    });
    document.getElementById('exportPDF').addEventListener('click', exportPDF);
    document.getElementById('exportJSON').addEventListener('click', exportJSON);
    loadAttackHistory();
}

// Launch attack
async function launchAttack() {
    const attackType = document.getElementById('attackType').value;
    const target = document.getElementById('target').value;
    
    if (!attackType || !target) {
        alert('Please select an attack type and enter a target');
        return;
    }
    
    // Collect parameters
    const parameters = {};
    const paramInputs = document.querySelectorAll('#parameterGroup input, #parameterGroup select');
    paramInputs.forEach(input => {
        if (input.value && input.name) {
            if (input.type === 'number') {
                parameters[input.name] = parseInt(input.value);
            } else if (input.name === 'port_range') {
                const [start, end] = input.value.split('-').map(Number);
                parameters['port_range'] = (start && end) ? [start, end] : [1, 1000];
            } else if (input.name === 'payloads' && input.value.trim()) {
                parameters['payloads'] = input.value.split(',').map(p => p.trim()).filter(p => p);
            } else {
                parameters[input.name] = input.value;
            }
        }
    });
    
    try {
        const response = await fetch('/api/red/launch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ attack_type: attackType, target, parameters })
        });
        
        const data = await response.json();
        currentAttack = data.attack_id;
        currentAttackMeta = { id: data.attack_id, type: attackType, target };
        document.getElementById('abortBtn').disabled = false;
        document.getElementById('executionStatus').textContent = `Attack ${data.attack_id} running...`;
        addTerminalLine(`🚀 Launching attack: ${attackType} on ${target}`, 'info');
    } catch (error) {
        console.error('Error launching attack:', error);
        addTerminalLine(`❌ Error: ${error.message}`, 'error');
    }
}

// Abort attack
async function abortAttack() {
    if (!currentAttack) return;
    
    try {
        await fetch(`/api/red/abort/${currentAttack}`, { method: 'POST' });
        addTerminalLine('⏹️ Attack aborted by user', 'warning');
        document.getElementById('abortBtn').disabled = true;
    } catch (error) {
        console.error('Error aborting attack:', error);
    }
}

// WebSocket connection
function connectWebSocket() {
    socket.on('connect', () => {
        addTerminalLine('✅ Connected to Red Team server', 'success');
    });
    
    socket.on('attack_update', (data) => {
        if (data.attack_id === currentAttack) {
            handleAttackUpdate(data.update);
        }
    });
    
    socket.on('attack_complete', (data) => {
        if (data.attack_id === currentAttack) {
            handleAttackComplete(data.result);
            // keep a local copy of the last completed attack in case history is empty
            if (currentAttackMeta) {
                lastCompletedAttack = {
                    id: currentAttackMeta.id,
                    type: currentAttackMeta.type,
                    target: currentAttackMeta.target,
                    status: data.result.success ? 'completed' : 'failed',
                    start_time: new Date().toISOString(),
                    end_time: new Date().toISOString(),
                    result: data.result
                };
            }
            currentAttack = null;
            currentAttackMeta = null;
            document.getElementById('abortBtn').disabled = true;
            document.getElementById('executionStatus').textContent = 'Attack completed';
            loadAttackHistory();
        }
    });
    
    socket.on('attack_detected', (data) => {
        addTerminalLine(`⚠️ Attack detected by Blue Team! Alert: ${data.alert.rule_name}`, 'warning');
    });
    
    socket.on('attack_error', (data) => {
        addTerminalLine(`❌ Attack error: ${data.error}`, 'error');
    });
}

// Handle attack update
function handleAttackUpdate(update) {
    addTerminalLine(update.message, update.status === 'vulnerability_found' ? 'success' : 'info');
    
    if (update.progress !== undefined) {
        document.getElementById('progressBar').style.width = update.progress + '%';
        document.getElementById('progressText').textContent = update.progress + '%';
    }
    
    if (update.packets_sent !== undefined) {
        document.getElementById('packetCount').textContent = `Packets: ${update.packets_sent}`;
    }
    
    if (update.vulnerability) {
        displayVulnerability(update.vulnerability);
    }
    
    if (update.extracted_data) {
        displayCapturedData(update.extracted_data);
    }
}

// Handle attack complete
function handleAttackComplete(result) {
    addTerminalLine('✅ Attack completed', 'success');
    document.getElementById('progressBar').style.width = '100%';
    document.getElementById('progressText').textContent = '100%';
    
    // Update results
    document.getElementById('attackSummary').innerHTML = `
        <p><strong>Status:</strong> ${result.success ? 'Success' : 'Failed'}</p>
        <p><strong>Vulnerabilities Found:</strong> ${result.vulnerabilities_found?.length || 0}</p>
        <p><strong>Data Extracted:</strong> ${result.data_extracted?.length || 0}</p>
        <p><strong>Attempts:</strong> ${result.attempts || result.packets_sent || 0}</p>
    `;
}

// Add terminal line
function addTerminalLine(message, type = 'info') {
    const terminal = document.getElementById('terminalOutput');
    const line = document.createElement('div');
    line.className = `terminal-line ${type}`;
    line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

// Display vulnerability
function displayVulnerability(vuln) {
    const list = document.getElementById('vulnerabilitiesList');
    const item = document.createElement('div');
    item.className = 'result-card';
    item.innerHTML = `
        <h4>${vuln.type}</h4>
        <p><strong>Parameter:</strong> ${vuln.parameter}</p>
        <p><strong>Severity:</strong> ${vuln.severity}</p>
        <p><strong>Payload:</strong> <code>${vuln.payload}</code></p>
    `;
    list.appendChild(item);
}

// Display captured data
function displayCapturedData(data) {
    const container = document.getElementById('capturedData');
    const item = document.createElement('div');
    item.className = 'result-card';
    item.innerHTML = `
        <h4>${data.type}</h4>
        <pre>${JSON.stringify(data.data, null, 2)}</pre>
    `;
    container.appendChild(item);
}

// Switch tabs
function switchTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    document.getElementById(`${tabName}Tab`).classList.add('active');
}

// Load attack history
async function loadAttackHistory() {
    try {
        const response = await fetch('/api/red/history');
        attackHistory = await response.json();
        displayHistory();
    } catch (error) {
        console.error('Error loading history:', error);
    }
}

// Display history
function displayHistory() {
    const timeline = document.getElementById('historyTimeline');
    timeline.innerHTML = '';
    
    const filter = document.getElementById('historyFilter').value;
    const filtered = filter === 'all' 
        ? attackHistory 
        : attackHistory.filter(a => a.type === filter);
    
    filtered.reverse().forEach(attack => {
        const result = attack.result || {};

        // Per-attack metrics depending on type
        const vulnsCount = result.vulnerabilities_found?.length || 0;
        const dataItems = result.data_extracted?.length || 0;
        const credsFound = result.credentials_found ? 1 : 0;
        const openPorts = result.open_ports?.length || 0;
        const ddosPackets = result.packets_sent || 0;

        const item = document.createElement('div');
        item.className = 'history-item';
        item.innerHTML = `
            <h4>${attack.type.replace('_', ' ').toUpperCase()}</h4>
            <p><strong>Target:</strong> ${attack.target}</p>
            <p><strong>Status:</strong> ${attack.status}</p>
            <p><strong>Time:</strong> ${new Date(attack.start_time).toLocaleString()}</p>
            <p><strong>Key Results:</strong></p>
            <ul>
                ${vulnsCount ? `<li>Vulnerabilities: ${vulnsCount}</li>` : ''}
                ${dataItems ? `<li>Data extracted items: ${dataItems}</li>` : ''}
                ${credsFound ? `<li>Credentials found: ${credsFound}</li>` : ''}
                ${openPorts ? `<li>Open ports: ${openPorts}</li>` : ''}
                ${ddosPackets ? `<li>DDoS packets sent: ${ddosPackets}</li>` : ''}
                ${(!vulnsCount && !dataItems && !credsFound && !openPorts && !ddosPackets)
                    ? '<li>No notable findings</li>' : ''}
            </ul>
            <button class="btn btn-small" type="button">Toggle details</button>
            <pre class="history-details" style="display:none; margin-top:10px;">${JSON.stringify(result, null, 2)}</pre>
        `;

        // Toggle details view
        const toggleBtn = item.querySelector('button');
        const detailsEl = item.querySelector('.history-details');
        toggleBtn.addEventListener('click', () => {
            detailsEl.style.display = detailsEl.style.display === 'none' ? 'block' : 'none';
        });

        timeline.appendChild(item);
    });
}

// Helper: build structured report object from history
function buildReportData() {
    // Prefer server-side history; if empty, fall back to last completed attack in this session
    const sourceAttacks = attackHistory.length
        ? attackHistory
        : (lastCompletedAttack ? [lastCompletedAttack] : []);

    if (!sourceAttacks.length) {
        return null;
    }

    const summary = {
        total_attacks: sourceAttacks.length,
        by_type: {},
        total_vulnerabilities: 0,
        total_data_items: 0,
        total_credentials_found: 0,
        total_open_ports: 0,
        total_ddos_packets: 0
    };

    const detailed = sourceAttacks.map(attack => {
        const result = attack.result || {};
        const common = {
            id: attack.id,
            type: attack.type,
            target: attack.target,
            status: attack.status,
            start_time: attack.start_time,
            end_time: attack.end_time || null
        };

        const normalized = {
            ...common,
            // SQL Injection specific
            vulnerabilities: result.vulnerabilities_found || [],
            data_exfiltrated: result.data_extracted || [],
            // Brute force specific
            credentials_found: result.credentials_found || null,
            attempts: result.attempts || 0,
            // Port scanner specific
            open_ports: result.open_ports || [],
            closed_ports: result.closed_ports || [],
            filtered_ports: result.filtered_ports || [],
            // DDoS specific
            packets_sent: result.packets_sent || 0,
            bytes_sent: result.bytes_sent || 0,
            avg_response_time: (() => {
                if (result.target_response_time && result.target_response_time.length) {
                    const avg = result.target_response_time
                        .map(r => r.response_time)
                        .reduce((a, b) => a + b, 0) / result.target_response_time.length;
                    return avg;
                }
                return 0;
            })()
        };

        // Update summary
        const typeKey = attack.type;
        if (!summary.by_type[typeKey]) {
            summary.by_type[typeKey] = {
                count: 0,
                successes: 0,
                failures: 0,
                vulnerabilities: 0,
                data_items: 0
            };
        }
        const typeStats = summary.by_type[typeKey];
        typeStats.count += 1;
        if (result.success) typeStats.successes += 1;
        else typeStats.failures += 1;

        const vulnsCount = normalized.vulnerabilities.length;
        const dataItems = normalized.data_exfiltrated.length;
        const creds = normalized.credentials_found ? 1 : 0;
        const openPorts = normalized.open_ports.length;
        const ddosPackets = normalized.packets_sent;

        typeStats.vulnerabilities += vulnsCount;
        typeStats.data_items += dataItems;

        summary.total_vulnerabilities += vulnsCount;
        summary.total_data_items += dataItems;
        summary.total_credentials_found += creds;
        summary.total_open_ports += openPorts;
        summary.total_ddos_packets += ddosPackets;

        return normalized;
    });

    return {
        generated_at: new Date().toISOString(),
        summary,
        attacks: detailed
    };
}

// Export functions
function exportPDF() {
    const report = buildReportData();
    if (!report) {
        alert('No attacks in history to export.');
        return;
    }
    const w = window.open('', '_blank');
    if (!w) {
        alert('Popup blocked. Please allow popups for PDF export.');
        return;
    }

    const docTitle = 'Red Team Attack Report';
    const style = `
        <style>
            body { font-family: Arial, sans-serif; padding: 20px; }
            h1, h2, h3 { color: #333; }
            table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
            th, td { border: 1px solid #ccc; padding: 6px 8px; font-size: 12px; }
            th { background: #f0f0f0; }
            .section { margin-bottom: 25px; }
            .small { font-size: 11px; color: #666; }
            pre { font-size: 10px; background: #f9f9f9; padding: 8px; }
        </style>
    `;

    let html = `<html><head><title>${docTitle}</title>${style}</head><body>`;
    html += `<h1>${docTitle}</h1>`;
    html += `<p class="small">Generated at: ${report.generated_at}</p>`;

    // Summary section
    html += '<div class="section"><h2>Summary</h2>';
    html += '<table><tbody>';
    html += `<tr><th>Total attacks</th><td>${report.summary.total_attacks}</td></tr>`;
    html += `<tr><th>Total vulnerabilities</th><td>${report.summary.total_vulnerabilities}</td></tr>`;
    html += `<tr><th>Total data items exfiltrated</th><td>${report.summary.total_data_items}</td></tr>`;
    html += `<tr><th>Total credentials found</th><td>${report.summary.total_credentials_found}</td></tr>`;
    html += `<tr><th>Total open ports discovered</th><td>${report.summary.total_open_ports}</td></tr>`;
    html += `<tr><th>Total DDoS packets sent</th><td>${report.summary.total_ddos_packets}</td></tr>`;
    html += '</tbody></table></div>';

    // Per-type stats
    html += '<div class="section"><h2>By Attack Type</h2>';
    html += '<table><thead><tr><th>Type</th><th>Count</th><th>Successes</th><th>Failures</th><th>Vulns</th><th>Data Items</th></tr></thead><tbody>';
    Object.entries(report.summary.by_type).forEach(([type, stats]) => {
        html += `<tr>
            <td>${type.replace('_', ' ')}</td>
            <td>${stats.count}</td>
            <td>${stats.successes}</td>
            <td>${stats.failures}</td>
            <td>${stats.vulnerabilities}</td>
            <td>${stats.data_items}</td>
        </tr>`;
    });
    html += '</tbody></table></div>';

    // Detailed per-attack section
    html += '<div class="section"><h2>Attack Details</h2>';
    report.attacks.forEach(a => {
        html += `<h3>${a.type.replace('_', ' ').toUpperCase()} - ${a.id}</h3>`;
        html += '<table><tbody>';
        html += `<tr><th>Target</th><td>${a.target}</td></tr>`;
        html += `<tr><th>Status</th><td>${a.status}</td></tr>`;
        html += `<tr><th>Start time</th><td>${a.start_time}</td></tr>`;
        if (a.end_time) html += `<tr><th>End time</th><td>${a.end_time}</td></tr>`;
        html += `<tr><th>Vulnerabilities</th><td>${a.vulnerabilities.length}</td></tr>`;
        html += `<tr><th>Data items</th><td>${a.data_exfiltrated.length}</td></tr>`;
        if (a.credentials_found) {
            html += `<tr><th>Credentials found</th><td>${a.credentials_found.username} / ${a.credentials_found.password}</td></tr>`;
        }
        if (a.open_ports.length) {
            html += `<tr><th>Open ports</th><td>${a.open_ports.map(p => p.port).join(', ')}</td></tr>`;
        }
        if (a.packets_sent) {
            html += `<tr><th>DDoS packets sent</th><td>${a.packets_sent}</td></tr>`;
        }
        if (a.avg_response_time) {
            html += `<tr><th>Avg response time</th><td>${a.avg_response_time.toFixed(2)} s</td></tr>`;
        }
        html += '</tbody></table>';

        if (a.vulnerabilities.length) {
            html += '<strong>Vulnerabilities:</strong><pre>' + JSON.stringify(a.vulnerabilities, null, 2) + '</pre>';
        }
        if (a.data_exfiltrated.length) {
            html += '<strong>Data exfiltrated:</strong><pre>' + JSON.stringify(a.data_exfiltrated, null, 2) + '</pre>';
        }
    });
    html += '</div>';

    html += '</body></html>';

    w.document.open();
    w.document.write(html);
    w.document.close();
    w.focus();
    w.print(); // User can choose "Save as PDF"
}

function exportJSON() {
    const report = buildReportData();
    if (!report) {
        alert('No attacks in history to export.');
        return;
    }
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'attack_report.json';
    a.click();
}

// Filter history
document.getElementById('historyFilter')?.addEventListener('change', loadAttackHistory);
