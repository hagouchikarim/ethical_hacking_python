// Red Team JavaScript
const socket = io('/red');
let currentAttack = null;
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
            currentAttack = null;
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
        const item = document.createElement('div');
        item.className = 'history-item';
        item.innerHTML = `
            <h4>${attack.type.replace('_', ' ').toUpperCase()}</h4>
            <p><strong>Target:</strong> ${attack.target}</p>
            <p><strong>Status:</strong> ${attack.status}</p>
            <p><strong>Time:</strong> ${new Date(attack.start_time).toLocaleString()}</p>
        `;
        timeline.appendChild(item);
    });
}

// Export functions
function exportPDF() {
    alert('PDF export functionality would be implemented here');
}

function exportJSON() {
    const data = {
        history: attackHistory,
        timestamp: new Date().toISOString()
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'attack_report.json';
    a.click();
}

// Filter history
document.getElementById('historyFilter')?.addEventListener('change', loadAttackHistory);
