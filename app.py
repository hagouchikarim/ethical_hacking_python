from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import json
import time
import threading
from datetime import datetime
import random
import os

# Import attack modules
from attacks.sql_injection import SQLInjectionAttack
from attacks.brute_force import BruteForceAttack
from attacks.port_scanner import PortScannerAttack
from attacks.ddos import DDoSAttack

# Import defense modules
from defense.ids import IntrusionDetectionSystem
from defense.firewall import Firewall
from defense.log_analyzer import LogAnalyzer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ethical-hacking-project-2026'
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize defense systems
ids = IntrusionDetectionSystem()
firewall = Firewall()
log_analyzer = LogAnalyzer()

# Global state
attack_history = []
active_attacks = {}
security_alerts = []
system_logs = []
security_score = 100

# Attack registry
ATTACK_MODULES = {
    'sql_injection': SQLInjectionAttack,
    'brute_force': BruteForceAttack,
    'port_scanner': PortScannerAttack,
    'ddos': DDoSAttack
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/red-team')
def red_team():
    return render_template('red_team.html')

@app.route('/blue-team')
def blue_team():
    return render_template('blue_team.html')

# Red Team API Endpoints
@app.route('/api/red/attacks', methods=['GET'])
def get_attacks():
    """Get available attack types"""
    attacks = [
        {
            'id': 'sql_injection',
            'name': 'SQL Injection',
            'description': 'Exploit SQL vulnerabilities in web applications',
            'category': 'Web Application',
            'severity': 'High',
            'status': 'ready'
        },
        {
            'id': 'brute_force',
            'name': 'Brute Force',
            'description': 'Attempt to crack passwords through repeated login attempts',
            'category': 'Authentication',
            'severity': 'Medium',
            'status': 'ready'
        },
        {
            'id': 'port_scanner',
            'name': 'Port Scanner',
            'description': 'Scan target for open ports and services',
            'category': 'Reconnaissance',
            'severity': 'Low',
            'status': 'ready'
        },
        {
            'id': 'ddos',
            'name': 'DDoS Attack',
            'description': 'Overwhelm target with traffic to cause denial of service',
            'category': 'Network',
            'severity': 'Critical',
            'status': 'ready'
        }
    ]
    return jsonify(attacks)

@app.route('/api/red/launch', methods=['POST'])
def launch_attack():
    """Launch an attack"""
    data = request.json
    attack_type = data.get('attack_type')
    target = data.get('target')
    parameters = data.get('parameters', {})
    
    if attack_type not in ATTACK_MODULES:
        return jsonify({'error': 'Invalid attack type'}), 400
    
    attack_id = f"{attack_type}_{int(time.time())}"
    
    # Create attack instance
    attack_class = ATTACK_MODULES[attack_type]
    attack = attack_class(target, parameters)
    
    # Store attack
    active_attacks[attack_id] = {
        'id': attack_id,
        'type': attack_type,
        'target': target,
        'parameters': parameters,
        'status': 'running',
        'start_time': datetime.now().isoformat(),
        'attack': attack
    }
    
    # Start attack in background thread
    thread = threading.Thread(target=run_attack, args=(attack_id, attack, target))
    thread.daemon = True
    thread.start()
    
    return jsonify({'attack_id': attack_id, 'status': 'launched'})

def run_attack(attack_id, attack, target):
    """Execute attack and emit real-time updates"""
    try:
        # Generate log entry
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': 'attack',
            'attack_id': attack_id,
            'attack_type': attack.__class__.__name__,
            'target': target,
            'message': f'Attack {attack_id} initiated'
        }
        system_logs.append(log_entry)
        socketio.emit('log_update', log_entry, namespace='/blue')
        
        # Execute attack
        for update in attack.execute():
            socketio.emit('attack_update', {
                'attack_id': attack_id,
                'update': update
            }, namespace='/red')
            
            # Check if IDS detects the attack
            if ids.detect_attack(update, attack_id):
                alert = ids.generate_alert(update, attack_id)
                security_alerts.append(alert)
                socketio.emit('security_alert', alert, namespace='/blue')
                socketio.emit('attack_detected', {
                    'attack_id': attack_id,
                    'alert': alert
                }, namespace='/red')
            
            # Add to logs
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'type': 'attack',
                'attack_id': attack_id,
                'attack_type': attack.__class__.__name__,
                'target': target,
                'message': update.get('message', 'Attack in progress')
            }
            system_logs.append(log_entry)
            socketio.emit('log_update', log_entry, namespace='/blue')
            
            time.sleep(0.5)  # Simulate attack progression
        
        # Attack completed
        result = attack.get_results()
        active_attacks[attack_id]['status'] = 'completed'
        active_attacks[attack_id]['result'] = result
        active_attacks[attack_id]['end_time'] = datetime.now().isoformat()
        
        attack_history.append(active_attacks[attack_id].copy())
        
        socketio.emit('attack_complete', {
            'attack_id': attack_id,
            'result': result
        }, namespace='/red')
        
    except Exception as e:
        active_attacks[attack_id]['status'] = 'failed'
        active_attacks[attack_id]['error'] = str(e)
        socketio.emit('attack_error', {
            'attack_id': attack_id,
            'error': str(e)
        }, namespace='/red')

@app.route('/api/red/status/<attack_id>', methods=['GET'])
def get_attack_status(attack_id):
    """Get attack status"""
    if attack_id in active_attacks:
        attack = active_attacks[attack_id]
        return jsonify({
            'id': attack_id,
            'status': attack['status'],
            'result': attack.get('result'),
            'error': attack.get('error')
        })
    return jsonify({'error': 'Attack not found'}), 404

@app.route('/api/red/history', methods=['GET'])
def get_attack_history():
    """Get attack history"""
    return jsonify(attack_history)

@app.route('/api/red/abort/<attack_id>', methods=['POST'])
def abort_attack(attack_id):
    """Abort a running attack"""
    if attack_id in active_attacks:
        active_attacks[attack_id]['status'] = 'aborted'
        if hasattr(active_attacks[attack_id]['attack'], 'abort'):
            active_attacks[attack_id]['attack'].abort()
        return jsonify({'status': 'aborted'})
    return jsonify({'error': 'Attack not found'}), 404

# Blue Team API Endpoints
@app.route('/api/blue/dashboard', methods=['GET'])
def get_dashboard():
    """Get security dashboard data"""
    global security_score
    
    # Calculate security score based on alerts and blocked attacks
    blocked_count = len([a for a in security_alerts if a.get('blocked', False)])
    total_alerts = len(security_alerts)
    critical_alerts = len([a for a in security_alerts if a.get('severity') == 'Critical'])
    
    # Reduce score based on threats
    security_score = max(0, 100 - (critical_alerts * 10) - (total_alerts * 2))
    
    return jsonify({
        'security_score': security_score,
        'active_threats': len([a for a in security_alerts if a.get('status') == 'active']),
        'total_alerts': total_alerts,
        'blocked_attacks': blocked_count,
        'system_status': 'operational' if security_score > 50 else 'compromised'
    })

@app.route('/api/blue/alerts', methods=['GET'])
def get_alerts():
    """Get security alerts"""
    status_filter = request.args.get('status')
    severity_filter = request.args.get('severity')
    
    alerts = security_alerts.copy()
    
    if status_filter:
        alerts = [a for a in alerts if a.get('status') == status_filter]
    if severity_filter:
        alerts = [a for a in alerts if a.get('severity') == severity_filter]
    
    return jsonify(alerts)

@app.route('/api/blue/alerts/<alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    for alert in security_alerts:
        if alert.get('id') == alert_id:
            alert['status'] = 'acknowledged'
            return jsonify({'status': 'acknowledged'})
    return jsonify({'error': 'Alert not found'}), 404

@app.route('/api/blue/logs', methods=['GET'])
def get_logs():
    """Get system logs"""
    source_filter = request.args.get('source')
    type_filter = request.args.get('type')
    limit = int(request.args.get('limit', 100))
    
    logs = system_logs[-limit:] if limit else system_logs
    
    if source_filter:
        logs = [l for l in logs if source_filter.lower() in str(l.get('source', '')).lower()]
    if type_filter:
        logs = [l for l in logs if l.get('type') == type_filter]
    
    return jsonify(logs)

@app.route('/api/blue/ids/rules', methods=['GET'])
def get_ids_rules():
    """Get IDS rules"""
    return jsonify(ids.get_rules())

@app.route('/api/blue/ids/rules', methods=['POST'])
def add_ids_rule():
    """Add IDS rule"""
    data = request.json
    rule_id = ids.add_rule(data)
    return jsonify({'rule_id': rule_id, 'status': 'added'})

@app.route('/api/blue/ids/rules/<rule_id>', methods=['DELETE'])
def delete_ids_rule(rule_id):
    """Delete IDS rule"""
    ids.remove_rule(rule_id)
    return jsonify({'status': 'deleted'})

@app.route('/api/blue/firewall/rules', methods=['GET'])
def get_firewall_rules():
    """Get firewall rules"""
    return jsonify(firewall.get_rules())

@app.route('/api/blue/firewall/rules', methods=['POST'])
def add_firewall_rule():
    """Add firewall rule"""
    data = request.json
    rule_id = firewall.add_rule(data)
    return jsonify({'rule_id': rule_id, 'status': 'added'})

@app.route('/api/blue/firewall/rules/<rule_id>', methods=['DELETE'])
def delete_firewall_rule(rule_id):
    """Delete firewall rule"""
    firewall.remove_rule(rule_id)
    return jsonify({'status': 'deleted'})

@app.route('/api/blue/firewall/block', methods=['POST'])
def block_ip():
    """Block an IP address"""
    data = request.json
    ip = data.get('ip')
    firewall.block_ip(ip)
    return jsonify({'status': 'blocked'})

# WebSocket events
@socketio.on('connect', namespace='/red')
def red_team_connect():
    emit('connected', {'message': 'Connected to Red Team interface'})

@socketio.on('connect', namespace='/blue')
def blue_team_connect():
    emit('connected', {'message': 'Connected to Blue Team interface'})

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('attacks', exist_ok=True)
    os.makedirs('defense', exist_ok=True)
    
    socketio.run(app, debug=True, port=5000)
