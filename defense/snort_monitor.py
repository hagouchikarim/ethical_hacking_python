"""
Snort 3 Monitor Module
Real-time monitoring of Snort alerts and integration with Blue Team dashboard
"""
import os
import re
import time
import threading
from datetime import datetime
from collections import defaultdict

class SnortMonitor:
    def __init__(self, alert_file='/var/log/snort/alert_fast.txt', socketio=None):
        self.alert_file = alert_file
        self.socketio = socketio
        self.running = False
        self.monitor_thread = None
        self.alerts = []
        self.last_alert_time = None  # Track when last alert was received
        self.last_heartbeat_time = None  # Track when forwarder last checked in
        self.stats = {
            'total_alerts': 0,
            'alerts_by_type': defaultdict(int),
            'alerts_by_severity': defaultdict(int),
            'blocked_ips': set(),
            'attack_correlations': {}
        }
        
        # Alert pattern for Snort 3 alert_fast.txt format
        # Example: 01/30-12:34:56.789012 [**] [1:1000001:2] SQL Injection - OR 1=1 Pattern [**] [Priority: 0] {TCP} 192.168.11.112:54321 -> 172.17.0.2:80
        self.alert_pattern = re.compile(
            r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+'
            r'\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+'
            r'([^\[]+?)\s+\[\*\*\]'
            r'.*?\{(\w+)\}\s*'
            r'([\d\.a-fA-F:]+?)(?::(\d+))?\s*->\s*'   # src_ip optionally :port
            r'([\d\.a-fA-F:]+?)(?::(\d+))?$'           # dst_ip optionally :port
        )
        
        # Map SIDs to attack types
        self.sid_to_attack_type = {
            # SQL Injection (1000001-1000010)
            1000001: 'sql_injection',
            1000002: 'sql_injection',
            1000003: 'sql_injection',
            1000004: 'sql_injection',
            1000005: 'sql_injection',
            1000006: 'sql_injection',
            1000007: 'sql_injection',
            
            # Brute Force (1000011-1000020)
            1000011: 'brute_force',
            1000012: 'brute_force',
            1000013: 'brute_force',
            1000014: 'brute_force',
            1000015: 'brute_force',
            
            # Port Scan (1000021-1000030)
            1000021: 'port_scanner',
            1000022: 'port_scanner',
            1000023: 'port_scanner',
            1000024: 'port_scanner',
            1000025: 'port_scanner',
            1000041: 'port_scanner',
            1000026: 'port_scanner',
            
            # DDoS (1000031-1000040)
            1000031: 'ddos',
            1000032: 'ddos',
            1000033: 'ddos',
            1000034: 'ddos',
            1000035: 'ddos',
        }
        
        # Map attack types to severity
        self.attack_severity = {
            'sql_injection': 'Critical',
            'brute_force': 'High',
            'ddos': 'Critical',
            'port_scanner': 'Medium'
        }
    
    def start_monitoring(self):
        """Start monitoring Snort alerts in background thread"""
        if self.running:
            print("[SnortMonitor] Already running")
            return
        
        # Check if alert file exists
        if not os.path.exists(self.alert_file):
            print(f"[SnortMonitor] Alert file not found: {self.alert_file}")
            print("[SnortMonitor] Creating file and waiting for Snort to write...")
            # Create empty file
            try:
                os.makedirs(os.path.dirname(self.alert_file), exist_ok=True)
                open(self.alert_file, 'a').close()
            except Exception as e:
                print(f"[SnortMonitor] Error creating alert file: {e}")
                return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        print(f"[SnortMonitor] Started monitoring {self.alert_file}")
    
    def stop_monitoring(self):
        """Stop monitoring Snort alerts"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        print("[SnortMonitor] Stopped monitoring")
    
    def _monitor_loop(self):
        """Main monitoring loop - tail -f equivalent"""
        try:
            # Open file and seek to end
            with open(self.alert_file, 'r') as f:
                # Go to end of file
                f.seek(0, os.SEEK_END)
                
                while self.running:
                    line = f.readline()
                    
                    if line:
                        # Process new alert
                        self._process_alert_line(line.strip())
                    else:
                        # No new data, sleep briefly
                        time.sleep(0.1)
        
        except Exception as e:
            print(f"[SnortMonitor] Error in monitoring loop: {e}")
            self.running = False
    
    def _process_alert_line(self, line):
        """Parse and process a single Snort alert line"""
        match = self.alert_pattern.match(line)
        
        if not match:
            # Try to extract at least the message
            if '[**]' in line:
                print(f"[SnortMonitor] ⚠️ PARSE FAILED: {line}")
            return
        
        # Extract alert components
        timestamp_str = match.group(1)
        gid = int(match.group(2))
        sid = int(match.group(3))
        rev = int(match.group(4))
        message = match.group(5).strip()
        protocol = match.group(6)
        src_ip = match.group(7) or 'Unknown'
        src_port = match.group(8) or '0'
        dst_ip = match.group(9) or 'Unknown'
        dst_port = match.group(10) or '0'
        
        # Determine attack type
        attack_type = self.sid_to_attack_type.get(sid, 'unknown')
        severity = self.attack_severity.get(attack_type, 'Medium')
        
        # Create alert object
        alert = {
            'id': f"snort_{int(time.time() * 1000)}_{sid}",
            'timestamp': datetime.now().isoformat(),
            'source': 'snort',
            'severity': severity,
            'rule_name': message,
            'description': f"Snort detected: {message}",
            'source_ip': src_ip,
            'source_port': src_port,
            'dest_ip': dst_ip,
            'dest_port': dst_port,
            'protocol': protocol,
            'attack_type': attack_type,
            'sid': sid,
            'gid': gid,
            'rev': rev,
            'status': 'active',
            'blocked': False,
            'acknowledged': False,
            'raw_alert': line
        }
        
        # Store alert
        self.alerts.append(alert)
        self.stats['total_alerts'] += 1
        self.stats['alerts_by_type'][attack_type] += 1
        self.stats['alerts_by_severity'][severity] += 1
        self.last_alert_time = time.time()  # Update last activity time
        
        # Log to console
        print(f"[SnortMonitor] ALERT: {message} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Type: {attack_type}")
        
        # Emit to Blue Team dashboard via WebSocket
        if self.socketio:
            try:
                self.socketio.emit('snort_alert', alert, namespace='/blue')
                print(f"[SnortMonitor] Emitted alert to Blue Team dashboard")
            except Exception as e:
                print(f"[SnortMonitor] Error emitting alert: {e}")
        
        return alert
    
    def _parse_snort_timestamp(self, timestamp_str):
        """Convert Snort timestamp (MM/DD-HH:MM:SS.microseconds) to ISO format"""
        try:
            # timestamp_str example: "01/30-12:34:56.789012"
            date_part, time_part = timestamp_str.split('-')
            month, day = date_part.split('/')
            
            # Get current year
            current_year = datetime.now().year
            
            # Construct datetime
            dt_str = f"{current_year}-{month}-{day} {time_part}"
            dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S.%f")
            
            return dt.isoformat()
        except Exception as e:
            print(f"[SnortMonitor] Error parsing timestamp '{timestamp_str}': {e}")
            return datetime.now().isoformat()
    
    def get_alerts(self, limit=100, attack_type=None, severity=None):
        """Get recent alerts with optional filtering"""
        filtered = self.alerts
        
        if attack_type:
            filtered = [a for a in filtered if a.get('attack_type') == attack_type]
        
        if severity:
            filtered = [a for a in filtered if a.get('severity') == severity]
        
        # Return most recent first
        return list(reversed(filtered[-limit:]))
    
    def get_stats(self):
        """Get monitoring statistics"""
        # Consider Snort "running" if either:
        # 1. Local monitoring thread is active (self.running), OR
        # 2. We've received a heartbeat from forwarder in the last 30 seconds
        is_active = self.running
        
        if not is_active and self.last_heartbeat_time:
            # Check if last heartbeat was within 30 seconds
            time_since_heartbeat = time.time() - self.last_heartbeat_time
            is_active = time_since_heartbeat < 60  # 60 seconds timeout
        
        return {
            'total_alerts': self.stats['total_alerts'],
            'alerts_by_type': dict(self.stats['alerts_by_type']),
            'alerts_by_severity': dict(self.stats['alerts_by_severity']),
            'blocked_ips_count': len(self.stats['blocked_ips']),
            'is_running': is_active,
            'alert_file': self.alert_file,
            'file_exists': os.path.exists(self.alert_file)
        }
    
    def correlate_with_attack(self, attack_id, attack_type):
        """Correlate Snort alerts with Red Team attack"""
        # Find alerts matching this attack type in last 60 seconds
        recent_cutoff = datetime.now().timestamp() - 60
        
        correlated = []
        for alert in reversed(self.alerts):
            alert_time = datetime.fromisoformat(alert['timestamp']).timestamp()
            
            if alert_time < recent_cutoff:
                break
            
            if alert.get('attack_type') == attack_type:
                correlated.append(alert)
        
        if correlated:
            self.stats['attack_correlations'][attack_id] = {
                'attack_type': attack_type,
                'alerts_detected': len(correlated),
                'first_detection': correlated[-1]['timestamp'],
                'last_detection': correlated[0]['timestamp'],
                'alert_ids': [a['id'] for a in correlated]
            }
        
        return correlated
    
    def clear_alerts(self):
        """Clear all stored alerts (for testing)"""
        self.alerts = []
        self.stats['total_alerts'] = 0
        self.stats['alerts_by_type'] = defaultdict(int)
        self.stats['alerts_by_severity'] = defaultdict(int)
        print("[SnortMonitor] Alerts cleared")
    
    def update_heartbeat(self):
        """Update heartbeat timestamp - called when forwarder checks in"""
        self.last_heartbeat_time = time.time()
    
    def test_parsing(self, sample_line):
        """Test alert parsing with a sample line"""
        print(f"[SnortMonitor] Testing parsing...")
        print(f"Input: {sample_line}")
        
        alert = self._process_alert_line(sample_line)
        
        if alert:
            print(f"Successfully parsed:")
            print(f"  - Message: {alert['rule_name']}")
            print(f"  - Source: {alert['source_ip']}:{alert['source_port']}")
            print(f"  - Dest: {alert['dest_ip']}:{alert['dest_port']}")
            print(f"  - Attack Type: {alert['attack_type']}")
            print(f"  - Severity: {alert['severity']}")
        else:
            print("Failed to parse")
        
        return alert


# Standalone testing
if __name__ == '__main__':
    print("=== Snort Monitor Test ===")
    
    monitor = SnortMonitor(alert_file='/var/log/snort/alert_fast.txt')
    
    # Test with sample Snort 3 alert
    sample_alert = "01/30-12:34:56.789012 [**] [1:1000001:2] SQL Injection - OR 1=1 Pattern [**] [Priority: 0] {TCP} 192.168.11.112:54321 -> 172.17.0.2:80"
    
    print("\n--- Testing Alert Parsing ---")
    monitor.test_parsing(sample_alert)
    
    print("\n--- Starting Monitor ---")
    monitor.start_monitoring()
    
    print("Monitoring for 30 seconds... Generate some attacks!")
    time.sleep(30)
    
    print("\n--- Statistics ---")
    stats = monitor.get_stats()
    for key, value in stats.items():
        print(f"{key}: {value}")
    
    print("\n--- Recent Alerts ---")
    alerts = monitor.get_alerts(limit=10)
    for alert in alerts:
        print(f"{alert['timestamp']} - {alert['rule_name']} ({alert['severity']})")
    
    monitor.stop_monitoring()
    print("\nTest complete!")