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
from defense.snort_monitor import SnortMonitor
from defense.alert_correlator import AlertCorrelator

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ethical-hacking-project-2026'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialize defense systems
ids = IntrusionDetectionSystem()
firewall = Firewall()
log_analyzer = LogAnalyzer()
snort_monitor = None
alert_correlator = AlertCorrelator()

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
    
    # Get attacker IP from request
    attacker_ip = request.remote_addr
    
    # CRITICAL FIX: Check firewall BEFORE creating attack
    if not firewall.check_packet(attacker_ip):
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': 'system',
            'source': 'firewall',
            'message': f'🚫 BLOCKED: Attack from {attacker_ip} - IP is blacklisted'
        }
        system_logs.append(log_entry)
        socketio.emit('log_update', log_entry, namespace='/blue')
        
        return jsonify({
            'error': f'Attack blocked by firewall - IP {attacker_ip} is blacklisted',
            'blocked': True
        }), 403
    
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
        'attack': attack,
        'attacker_ip': attacker_ip
    }
    
    # Start attack in background thread
    thread = threading.Thread(target=run_attack, args=(attack_id, attack, target, attack_type, attacker_ip))
    thread.daemon = True
    thread.start()
    
    return jsonify({'attack_id': attack_id, 'status': 'launched'})

def run_attack(attack_id, attack, target, attack_type, attacker_ip):
    """Execute attack and emit real-time updates"""
    try:
        # Initial log entry (without 'update' variable)
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': 'attack',
            'attack_id': attack_id,
            'attack_type': attack_type,
            'target': target,
            'source_ip': attacker_ip,
            'message': f'🚀 Starting {attack_type} attack on {target} from {attacker_ip}'
        }
        system_logs.append(log_entry)
        socketio.emit('log_update', log_entry, namespace='/blue')
        
        # Execute attack
        for update in attack.execute():
            # Check firewall again during execution (in case IP was blocked mid-attack)
            if not firewall.check_packet(attacker_ip):
                log_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'type': 'system',
                    'source': 'firewall',
                    'message': f'🚫 BLOCKED: Attack {attack_id} terminated - IP {attacker_ip} was blacklisted'
                }
                system_logs.append(log_entry)
                socketio.emit('log_update', log_entry, namespace='/blue')
                
                socketio.emit('attack_error', {
                    'attack_id': attack_id,
                    'error': f'Attack blocked - IP {attacker_ip} was blacklisted during execution'
                }, namespace='/red')
                
                active_attacks[attack_id]['status'] = 'blocked'
                active_attacks[attack_id]['blocked_by'] = 'firewall'
                attack.abort()
                return
            
            # Emit update to Red Team
            socketio.emit('attack_update', {
                'attack_id': attack_id,
                'update': update
            }, namespace='/red')
            
            # Check if IDS detects the attack
            if ids.detect_attack(update, attack_id):
                    alert = ids.generate_alert(update, attack_id, source_ip=attacker_ip)
                    alert['source_ip'] = attacker_ip
                    alert['dest_ip'] = target
                    alert['attack_id'] = attack_id
                    security_alerts.append(alert)
                
                    # Correlate alert into incident
                    incident_id, is_new = alert_correlator.correlate_alert(alert)
                    
                    # Emit alert to Blue Team
                    socketio.emit('new_alert', alert, namespace='/blue')
                    
                    if is_new:
                        print(f"[IDS] NEW INCIDENT {incident_id}: {alert['rule_name']}")
                    else:
                        print(f"[IDS] Alert correlated to incident {incident_id}")
                    
                    # Log IDS detection
                    log_entry = {
                        'timestamp': datetime.now().isoformat(),
                        'type': 'system',
                        'source': 'ids',
                        'message': f'🚨 IDS ALERT: {alert["rule_name"]} - {attacker_ip}'
                    }
                    system_logs.append(log_entry)
                    socketio.emit('log_update', log_entry, namespace='/blue')
        
        # Attack completed
        active_attacks[attack_id]['status'] = 'completed'
        active_attacks[attack_id]['end_time'] = datetime.now().isoformat()
        active_attacks[attack_id]['results'] = attack.get_results()
        
        # Add to history
        attack_history.append({
            'id': attack_id,
            'type': attack_type,
            'target': target,
            'attacker_ip': attacker_ip,
            'start_time': active_attacks[attack_id]['start_time'],
            'end_time': active_attacks[attack_id]['end_time'],
            'status': 'completed',
            'results': attack.get_results()
        })
        
        # Correlate with Snort
        if snort_monitor:
            correlated = snort_monitor.correlate_with_attack(attack_id, attack_type)
            if correlated:
                print(f"[Correlation] {len(correlated)} Snort alerts correlated with attack {attack_id}")
                socketio.emit('attack_correlation', {
                    'attack_id': attack_id,
                    'snort_alerts': len(correlated)
                }, namespace='/blue')
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': 'attack',
            'attack_id': attack_id,
            'message': f'✅ Attack {attack_id} completed'
        }
        system_logs.append(log_entry)
        socketio.emit('log_update', log_entry, namespace='/blue')
        
    except Exception as e:
        print(f"[ERROR] Attack execution failed: {e}")
        import traceback
        traceback.print_exc()
        
        active_attacks[attack_id]['status'] = 'failed'
        active_attacks[attack_id]['error'] = str(e)
        
        socketio.emit('attack_error', {
            'attack_id': attack_id,
            'error': str(e)
        }, namespace='/red')

@app.route('/api/red/abort/<attack_id>', methods=['POST'])
def abort_attack(attack_id):
    """Abort a running attack"""
    if attack_id in active_attacks:
        attack = active_attacks[attack_id].get('attack')
        if attack:
            attack.abort()
        active_attacks[attack_id]['status'] = 'aborted'
        return jsonify({'status': 'aborted'})
    return jsonify({'error': 'Attack not found'}), 404

@app.route('/api/red/results/<attack_id>', methods=['GET'])
def get_attack_results(attack_id):
    """Get results for a completed attack"""
    if attack_id in active_attacks:
        return jsonify(active_attacks[attack_id])
    
    # Check history
    for attack in attack_history:
        if attack['id'] == attack_id:
            return jsonify(attack)
    
    return jsonify({'error': 'Attack not found'}), 404

@app.route('/api/red/history', methods=['GET'])
def get_attack_history():
    """Get attack history"""
    return jsonify(attack_history)

# Blue Team API Endpoints
@app.route('/api/blue/dashboard', methods=['GET'])
def get_dashboard():
    """Get Blue Team dashboard data"""
    global security_score
    
    # Calculate security score
    total_alerts = len(security_alerts)
    critical_alerts = len([a for a in security_alerts if a.get('severity') == 'Critical'])
    
    # Reduce score based on alerts
    security_score = max(0, 100 - (critical_alerts * 10) - (total_alerts * 2))
    
    # Get active incidents count
    active_incidents = len([i for i in alert_correlator.get_active_incidents() if i.get('status') == 'active'])
    
    # Check system status
    system_status = 'compromised' if security_score < 50 else 'operational'
    
    dashboard_data = {
        'security_score': security_score,
        'active_threats': len([a for a in active_attacks.values() if a['status'] == 'running']),
        'active_incidents': active_incidents,
        'total_alerts': len(security_alerts),
        'snort_alerts': len([a for a in security_alerts if a.get('source') == 'snort']),
        'blocked_attacks': len(firewall.get_blocked_ips()),
        'system_status': system_status,
        'snort_enabled': snort_monitor.running if snort_monitor else False
    }
    
    return jsonify(dashboard_data)

@app.route('/api/blue/alerts', methods=['GET'])
def get_alerts():
    """Get security alerts"""
    severity = request.args.get('severity')
    
    filtered = security_alerts
    if severity:
        filtered = [a for a in filtered if a.get('severity') == severity]
    
    return jsonify(filtered)

@app.route('/api/blue/logs', methods=['GET'])
def get_logs():
    """Get system logs"""
    return jsonify(system_logs[-100:])

# Snort API endpoints
@app.route('/api/blue/snort/status', methods=['GET'])
def get_snort_status():
    """Get Snort monitoring status"""
    if snort_monitor:
        return jsonify(snort_monitor.get_stats())
    return jsonify({'error': 'Snort monitor not initialized'}), 500

@app.route('/api/blue/snort/alerts', methods=['GET'])
def get_snort_alerts():
    """Get Snort alerts"""
    if snort_monitor:
        limit = int(request.args.get('limit', 100))
        attack_type = request.args.get('attack_type')
        severity = request.args.get('severity')
        
        alerts = snort_monitor.get_alerts(limit=limit, attack_type=attack_type, severity=severity)
        return jsonify(alerts)
    return jsonify([])

# IDS endpoints
@app.route('/api/blue/ids/rules', methods=['GET'])
def get_ids_rules():
    """Get IDS rules"""
    return jsonify(ids.get_rules())

@app.route('/api/blue/ids/rules', methods=['POST'])
def add_ids_rule():
    """Add new IDS rule"""
    data = request.json
    rule_id = ids.add_rule(data)
    return jsonify({'rule_id': rule_id, 'status': 'created'})

@app.route('/api/blue/ids/rules/<rule_id>', methods=['DELETE'])
def delete_ids_rule(rule_id):
    """Delete IDS rule"""
    ids.remove_rule(rule_id)
    return jsonify({'status': 'deleted'})

@app.route('/api/blue/ids/rules/<rule_id>/toggle', methods=['POST'])
def toggle_ids_rule(rule_id):
    """Toggle IDS rule"""
    enabled = ids.toggle_rule(rule_id)
    return jsonify({'status': 'toggled', 'enabled': enabled})

# Firewall endpoints
@app.route('/api/blue/firewall/rules', methods=['GET'])
def get_firewall_rules():
    """Get firewall rules"""
    return jsonify(firewall.get_rules())

@app.route('/api/blue/firewall/rules', methods=['POST'])
def add_firewall_rule():
    """Add new firewall rule"""
    data = request.json
    rule_id = firewall.add_rule(data)
    return jsonify({'rule_id': rule_id, 'status': 'created'})

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
    reason = data.get('reason', 'Manual block from Blue Team')
    
    if not ip:
        return jsonify({'error': 'IP address required'}), 400
    
    rule_id = firewall.block_ip(ip, reason)
    
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'type': 'system',
        'source': 'firewall',
        'message': f'🚫 Blocked IP: {ip}'
    }
    system_logs.append(log_entry)
    socketio.emit('log_update', log_entry, namespace='/blue')
    
    return jsonify({'status': 'blocked', 'rule_id': rule_id})

@app.route('/api/blue/firewall/unblock/<ip>', methods=['POST'])
def unblock_ip(ip):
    """FIXED: Unblock an IP address - now accepts IP in URL path"""
    if not ip:
        return jsonify({'error': 'IP address required'}), 400
    
    firewall.unblock_ip(ip)
    
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'type': 'system',
        'source': 'firewall',
        'message': f'✅ Unblocked IP: {ip}'
    }
    system_logs.append(log_entry)
    socketio.emit('log_update', log_entry, namespace='/blue')
    
    return jsonify({'status': 'unblocked', 'ip': ip})

@app.route('/api/blue/firewall/blocked', methods=['GET'])
def get_blocked_ips():
    """Get blocked IPs"""
    return jsonify(firewall.get_blocked_ips())

@app.route('/api/blue/report/generate', methods=['POST'])
def generate_report():
    """FIXED: Generate SOC audit report with correct endpoint"""
    try:
        report_data = {
            'generated_at': datetime.now().isoformat(),
            'security_score': security_score,
            'alerts': security_alerts,
            'snort_alerts': snort_monitor.get_alerts(limit=500) if snort_monitor else [],
            'attack_history': attack_history,
            'firewall_rules': firewall.get_rules(),
            'blocked_ips': firewall.get_blocked_ips(),
            'ids_rules': ids.get_rules(),
            'logs': system_logs[-500:]
        }
        
        pdf_path = generate_soc_report(report_data)
        return send_file(pdf_path, as_attachment=True, download_name='soc_audit_report.pdf')
    except Exception as e:
        print(f"[ERROR] Report generation failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# FIXED: Add PDF endpoint that blue_team.js is calling
@app.route('/api/blue/report/pdf', methods=['POST'])
def generate_pdf_report():
    """Generate PDF report (alternative endpoint)"""
    return generate_report()

@app.route('/api/blue/report/export', methods=['GET'])
def export_report_json():
    """Export report as JSON"""
    report_data = {
        'generated_at': datetime.now().isoformat(),
        'security_score': security_score,
        'alerts': security_alerts,
        'snort_alerts': snort_monitor.get_alerts(limit=500) if snort_monitor else [],
        'attack_history': attack_history,
        'firewall_rules': firewall.get_rules(),
        'blocked_ips': firewall.get_blocked_ips(),
        'ids_rules': ids.get_rules(),
        'logs': system_logs[-500:]
    }
    
    return jsonify(report_data)

# ═══════════════════════════════════════════════════════════════════
# INCIDENT CORRELATION ROUTES
# ═══════════════════════════════════════════════════════════════════

@app.route('/api/blue/incidents', methods=['GET'])
def get_incidents():
    """Get correlated incidents"""
    try:
        alert_correlator.auto_close_old_incidents(max_age_seconds=300)
        incidents = alert_correlator.get_active_incidents()
        
        status_filter = request.args.get('status')
        severity_filter = request.args.get('severity')
        
        if status_filter:
            incidents = [i for i in incidents if i.get('status') == status_filter]
        if severity_filter:
            incidents = [i for i in incidents if i.get('severity') == severity_filter]
        
        return jsonify(incidents)
    except Exception as e:
        print(f"[ERROR] Get incidents failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify([])

@app.route('/api/blue/incidents/<incident_id>', methods=['GET'])
def get_incident_details(incident_id):
    """Get full incident details"""
    try:
        incident = alert_correlator.get_incident(incident_id)
        if not incident:
            return jsonify({'error': 'Incident not found'}), 404
        return jsonify(incident)
    except Exception as e:
        print(f"[ERROR] Get incident details failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/blue/incidents/<incident_id>/acknowledge', methods=['POST'])
def acknowledge_incident(incident_id):
    """Acknowledge incident"""
    try:
        success = alert_correlator.acknowledge_incident(incident_id)
        if success:
            incident = alert_correlator.get_incident(incident_id)
            socketio.emit('incident_update', incident, namespace='/blue')
            return jsonify({'status': 'acknowledged'})
        return jsonify({'error': 'Incident not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blue/incidents/<incident_id>/close', methods=['POST'])
def close_incident(incident_id):
    """Close incident"""
    try:
        success = alert_correlator.close_incident(incident_id)
        if success:
            return jsonify({'status': 'closed'})
        return jsonify({'error': 'Incident not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blue/incidents/<incident_id>/block', methods=['POST'])
def block_incident_source(incident_id):
    """Mark incident as blocked"""
    try:
        success = alert_correlator.block_incident(incident_id)
        if success:
            return jsonify({'status': 'blocked'})
        return jsonify({'error': 'Incident not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blue/incidents/auto-close', methods=['POST'])
def auto_close_incidents():
    """Auto-close old incidents"""
    try:
        closed_count = alert_correlator.auto_close_old_incidents(max_age_seconds=300)
        return jsonify({'closed_count': closed_count, 'status': 'success'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/snort-alert', methods=['POST'])
def receive_snort_alert():
    """FIXED: Receive Snort alerts from Kali forwarder with better error handling"""
    try:
        data = request.get_json()
        alert_line = data.get('alert_line', '')
        
        print(f"[Snort API] Received alert from {request.remote_addr}: {alert_line[:100]}")
        
        if not snort_monitor:
            print("[Snort API] ERROR: Snort monitor not initialized!")
            return jsonify({'status': 'error', 'message': 'Snort monitor not initialized'}), 500
        
        if alert_line:
            alert = snort_monitor._process_alert_line(alert_line)
            
            if alert:
                print(f"[Snort API] Alert parsed successfully: {alert['rule_name']}")
                
                # Correlate alert into incident
                incident_id, is_new = alert_correlator.correlate_alert(alert)
                
                # Emit to dashboard
                socketio.emit('snort_alert', alert, namespace='/blue')
                
                if is_new:
                    print(f"[Snort] NEW INCIDENT {incident_id}: {alert['rule_name']}")
                else:
                    print(f"[Snort] Alert correlated to incident {incident_id}")
                
                return jsonify({
                    'status': 'success', 
                    'alert_id': alert.get('id'), 
                    'incident_id': incident_id
                }), 200
            else:
                print(f"[Snort API] Failed to parse alert: {alert_line[:100]}")
                return jsonify({'status': 'parse_error', 'message': 'Failed to parse alert'}), 400
        
        return jsonify({'status': 'no_alert'}), 200
    
    except Exception as e:
        print(f"[Snort API] Error processing alert: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500

# WebSocket events
@socketio.on('connect', namespace='/red')
def red_team_connect():
    print(f"[WebSocket] Red Team client connected: {request.sid}")
    emit('connected', {'message': 'Connected to Red Team interface'})

@socketio.on('connect', namespace='/blue')
def blue_team_connect():
    print(f"[WebSocket] Blue Team client connected: {request.sid}")
    emit('connected', {'message': 'Connected to Blue Team interface'})
    
    # Send Snort status on connect
    if snort_monitor:
        stats = snort_monitor.get_stats()
        emit('snort_status', stats)

@socketio.on('disconnect', namespace='/red')
def red_team_disconnect():
    print(f"[WebSocket] Red Team client disconnected: {request.sid}")

@socketio.on('disconnect', namespace='/blue')
def blue_team_disconnect():
    print(f"[WebSocket] Blue Team client disconnected: {request.sid}")

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('attacks', exist_ok=True)
    os.makedirs('defense', exist_ok=True)
    os.makedirs('reports', exist_ok=True)
    
    # FIXED: Initialize Snort monitor to receive remote alerts
    print("[Startup] Initializing Snort Monitor (remote mode)...")
    # Even though we're on Windows, we still need the monitor object to process incoming alerts
    snort_monitor = SnortMonitor(alert_file='/var/log/snort/alert_fast.txt', socketio=socketio)
    # Don't start monitoring the local file, we'll receive alerts via HTTP from Kali
    print(f"[Startup] Snort Monitor initialized (waiting for HTTP alerts from Kali)")
    
    print("\n" + "="*60)
    print("🛡️  ETHICAL HACKING PLATFORM STARTING")
    print("="*60)
    print(f"🔴 Red Team:  http://0.0.0.0:5000/red-team")
    print(f"🔵 Blue Team: http://0.0.0.0:5000/blue-team")
    print(f"📡 Snort API: http://0.0.0.0:5000/api/snort-alert")
    print("="*60 + "\n")
    
    socketio.run(app, debug=True, port=5000, host='0.0.0.0', allow_unsafe_werkzeug=True)