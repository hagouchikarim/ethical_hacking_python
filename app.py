from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import json
import time
import threading
from datetime import datetime
import random
import os
from defense.report_generator import generate_soc_report
from flask import send_file

# Import attack modules
from attacks.sql_injection import SQLInjectionAttack
from attacks.brute_force import BruteForceAttack
from attacks.port_scanner import PortScannerAttack
from attacks.ddos import DDoSAttack

# Import defense modules
from defense.ids import IntrusionDetectionSystem
from defense.firewall import Firewall
from defense.log_analyzer import LogAnalyzer
from defense.snort_monitor import SnortMonitor  # NEW: Import Snort monitor

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ethical-hacking-project-2026'
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize defense systems
ids = IntrusionDetectionSystem()
firewall = Firewall()
log_analyzer = LogAnalyzer()
snort_monitor = None  # NEW: Will be initialized on startup

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
    thread = threading.Thread(target=run_attack, args=(attack_id, attack, target, attack_type))
    thread.daemon = True
    thread.start()
    
    return jsonify({'attack_id': attack_id, 'status': 'launched'})

def run_attack(attack_id, attack, target, attack_type):
    """Execute attack and emit real-time updates"""
    try:
        # Generate log entry
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': 'attack',
            'attack_id': attack_id,
            'attack_type': attack_type,
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
                'attack_type': attack_type,
                'target': target,
                'message': update.get('message', 'Attack in progress')
            }
            system_logs.append(log_entry)
            socketio.emit('log_update', log_entry, namespace='/blue')
            
            time.sleep(0.5)  # Simulate attack progression
        
        # Attack completed - check for Snort correlations
        result = attack.get_results()
        active_attacks[attack_id]['status'] = 'completed'
        active_attacks[attack_id]['result'] = result
        active_attacks[attack_id]['end_time'] = datetime.now().isoformat()
        
        # NEW: Correlate with Snort alerts
        if snort_monitor and snort_monitor.running:
            time.sleep(2)  # Give Snort time to process
            correlated_alerts = snort_monitor.correlate_with_attack(attack_id, attack_type)
            
            if correlated_alerts:
                active_attacks[attack_id]['snort_detections'] = len(correlated_alerts)
                
                # Emit correlation notification
                socketio.emit('attack_correlation', {
                    'attack_id': attack_id,
                    'snort_alerts': len(correlated_alerts),
                    'message': f'Snort detected {len(correlated_alerts)} suspicious activities related to this attack'
                }, namespace='/blue')
                
                print(f"[Correlation] Attack {attack_id} correlated with {len(correlated_alerts)} Snort alerts")
        
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
    
    # NEW: Include Snort statistics
    snort_stats = snort_monitor.get_stats() if snort_monitor else {}
    snort_alerts = snort_stats.get('total_alerts', 0)
    
    # Reduce score based on threats
    security_score = max(0, 100 - (critical_alerts * 10) - (total_alerts * 2) - (snort_alerts * 1))
    
    return jsonify({
        'security_score': security_score,
        'active_threats': len([a for a in security_alerts if a.get('status') == 'active']),
        'total_alerts': total_alerts,
        'blocked_attacks': blocked_count,
        'system_status': 'operational' if security_score > 50 else 'compromised',
        'snort_enabled': snort_monitor.running if snort_monitor else False,
        'snort_alerts': snort_alerts
    })

@app.route('/api/blue/report/pdf', methods=['POST'])
def generate_pdf_report():
    """Generate comprehensive SOC audit report as PDF"""
    try:
        # Gather all data
        dashboard = {
            'security_score': security_score,
            'active_threats': len([a for a in security_alerts if a.get('status') == 'active']),
            'total_alerts': len(security_alerts),
            'snort_alerts': snort_monitor.get_stats().get('total_alerts', 0) if snort_monitor else 0,
            'blocked_attacks': len(firewall.get_blocked_ips()),
            'system_status': 'operational' if security_score > 50 else 'compromised',
            'snort_enabled': snort_monitor.running if snort_monitor else False
        }
        
        # Combine all alerts (IDS + Snort)
        all_alerts = security_alerts.copy()
        if snort_monitor:
            all_alerts.extend(snort_monitor.get_alerts(limit=100))
        
        # Get Snort stats
        snort_stats = snort_monitor.get_stats() if snort_monitor else {}
        
        # Generate PDF
        pdf_buffer = generate_soc_report(
            dashboard_data=dashboard,
            alerts=all_alerts,
            logs=system_logs[-100:],  # Last 100 logs
            firewall_rules=firewall.get_rules(),
            blocked_ips=firewall.get_blocked_ips(),
            snort_stats=snort_stats
        )
        
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'SOC_Audit_Report_{int(time.time())}.pdf'
        )
        
    except Exception as e:
        print(f"[PDF Report] Error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/blue/alerts', methods=['GET'])
def get_alerts():
    """Get security alerts (combined IDS + Snort)"""
    status_filter = request.args.get('status')
    severity_filter = request.args.get('severity')
    source_filter = request.args.get('source')  # NEW: 'ids' or 'snort'
    
    # Combine IDS alerts and Snort alerts
    all_alerts = security_alerts.copy()
    
    # NEW: Add Snort alerts
    if snort_monitor:
        snort_alerts = snort_monitor.get_alerts(limit=100)
        all_alerts.extend(snort_alerts)
    
    # Apply filters
    if status_filter:
        all_alerts = [a for a in all_alerts if a.get('status') == status_filter]
    if severity_filter:
        all_alerts = [a for a in all_alerts if a.get('severity') == severity_filter]
    if source_filter:
        all_alerts = [a for a in all_alerts if a.get('source') == source_filter]
    
    # Sort by timestamp (most recent first)
    all_alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    return jsonify(all_alerts)

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

# NEW: Snort-specific endpoints
@app.route('/api/blue/snort/status', methods=['GET'])
def get_snort_status():
    """Get Snort monitor status"""
    if not snort_monitor:
        return jsonify({'error': 'Snort monitor not initialized'}), 503
    
    stats = snort_monitor.get_stats()
    return jsonify(stats)

@app.route('/api/blue/snort/alerts', methods=['GET'])
def get_snort_alerts():
    """Get Snort alerts only"""
    if not snort_monitor:
        return jsonify([])
    
    attack_type = request.args.get('attack_type')
    severity = request.args.get('severity')
    limit = int(request.args.get('limit', 50))
    
    alerts = snort_monitor.get_alerts(limit=limit, attack_type=attack_type, severity=severity)
    return jsonify(alerts)

@app.route('/api/blue/snort/start', methods=['POST'])
def start_snort_monitor():
    """Start Snort monitoring"""
    global snort_monitor
    
    if not snort_monitor:
        return jsonify({'error': 'Snort monitor not initialized'}), 503
    
    if snort_monitor.running:
        return jsonify({'status': 'already_running'})
    
    snort_monitor.start_monitoring()
    return jsonify({'status': 'started'})

@app.route('/api/blue/snort/stop', methods=['POST'])
def stop_snort_monitor():
    """Stop Snort monitoring"""
    if not snort_monitor:
        return jsonify({'error': 'Snort monitor not initialized'}), 503
    
    snort_monitor.stop_monitoring()
    return jsonify({'status': 'stopped'})

@app.route('/api/blue/snort/clear', methods=['POST'])
def clear_snort_alerts():
    """Clear Snort alerts (for testing)"""
    if not snort_monitor:
        return jsonify({'error': 'Snort monitor not initialized'}), 503
    
    snort_monitor.clear_alerts()
    return jsonify({'status': 'cleared'})

# Existing IDS endpoints
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

@app.route('/api/blue/ids/rules/<rule_id>/toggle', methods=['POST'])
def toggle_ids_rule(rule_id):
    """Enable/disable an IDS rule"""
    enabled = ids.toggle_rule(rule_id)
    if enabled is None:
        return jsonify({'error': 'Rule not found'}), 404
    # Audit log
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'type': 'system',
        'source': 'ids',
        'message': f'IDS rule {rule_id} toggled to {"enabled" if enabled else "disabled"}'
    }
    system_logs.append(log_entry)
    return jsonify({'status': 'toggled', 'enabled': enabled})

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
    # Audit log
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'type': 'system',
        'source': 'firewall',
        'message': f'IP blocked: {ip}'
    }
    system_logs.append(log_entry)
    return jsonify({'status': 'blocked'})

@app.route('/api/blue/firewall/unblock', methods=['POST'])
def unblock_ip():
    """Unblock an IP address"""
    data = request.json
    ip = data.get('ip')
    firewall.unblock_ip(ip)
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'type': 'system',
        'source': 'firewall',
        'message': f'IP unblocked: {ip}'
    }
    system_logs.append(log_entry)
    return jsonify({'status': 'unblocked'})

@app.route('/api/blue/firewall/blocked', methods=['GET'])
def get_blocked_ips():
    """Get blocked IPs"""
    return jsonify(firewall.get_blocked_ips())

# WebSocket events
@socketio.on('connect', namespace='/red')
def red_team_connect():
    emit('connected', {'message': 'Connected to Red Team interface'})

@socketio.on('connect', namespace='/blue')
def blue_team_connect():
    emit('connected', {'message': 'Connected to Blue Team interface'})
    
    # NEW: Send Snort status on connect
    if snort_monitor:
        stats = snort_monitor.get_stats()
        emit('snort_status', stats)

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('attacks', exist_ok=True)
    os.makedirs('defense', exist_ok=True)
    
    # NEW: Initialize Snort monitor
    print("[Startup] Initializing Snort Monitor...")
    snort_monitor = SnortMonitor(
        alert_file='/var/log/snort/alert_fast.txt',
        socketio=socketio
    )
    
    # Start monitoring automatically
    snort_monitor.start_monitoring()
    print(f"[Startup] Snort Monitor initialized and started")
    
    socketio.run(app, debug=True, port=5000, host='0.0.0.0')