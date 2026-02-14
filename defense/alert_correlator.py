"""
Alert Correlation Engine
Groups and correlates security alerts for realistic SOC operations
"""
from datetime import datetime, timedelta
from collections import defaultdict
import uuid

class AlertCorrelator:
    def __init__(self):
        self.incidents = {}  # incident_id -> incident data
        self.alert_to_incident = {}  # alert_id -> incident_id
        self.correlation_window = 120  # seconds
        
    def correlate_alert(self, alert):
        """
        Correlate a new alert with existing incidents or create new incident
        Returns: (incident_id, is_new_incident)
        """
        alert_id = alert.get('id')
        timestamp = datetime.fromisoformat(alert.get('timestamp', datetime.now().isoformat()))
        
        # Check if alert already correlated
        if alert_id in self.alert_to_incident:
            incident_id = self.alert_to_incident[alert_id]
            return incident_id, False
        
        # Try to find matching incident
        matching_incident = self._find_matching_incident(alert, timestamp)
        
        if matching_incident:
            # Add alert to existing incident
            incident_id = matching_incident
            self._add_alert_to_incident(incident_id, alert)
            return incident_id, False
        else:
            # Create new incident
            incident_id = self._create_incident(alert)
            return incident_id, True
    
    def _find_matching_incident(self, alert, alert_time):
        """Find an existing incident that matches this alert"""
        attack_type = self._extract_attack_type(alert)
        source_ip = alert.get('source_ip', 'unknown')
        dest_ip = alert.get('dest_ip', 'unknown')
        
        # Look for active incidents within time window
        for incident_id, incident in self.incidents.items():
            if incident.get('status') != 'active':
                continue
            
            # Check if within time window
            incident_time = datetime.fromisoformat(incident['last_seen'])
            if (alert_time - incident_time).total_seconds() > self.correlation_window:
                continue
            
            # Match criteria: same attack type, source IP, and dest IP
            if (incident.get('attack_type') == attack_type and
                incident.get('source_ip') == source_ip and
                incident.get('dest_ip') == dest_ip):
                return incident_id
        
        return None
    
    def _create_incident(self, alert):
        """Create a new incident from an alert"""
        incident_id = f"INC_{int(datetime.now().timestamp() * 1000)}"
        attack_type = self._extract_attack_type(alert)
        
        incident = {
            'id': incident_id,
            'attack_type': attack_type,
            'source_ip': alert.get('source_ip', 'unknown'),
            'dest_ip': alert.get('dest_ip', 'unknown'),
            'severity': alert.get('severity', 'Medium'),
            'first_seen': alert.get('timestamp'),
            'last_seen': alert.get('timestamp'),
            'status': 'active',
            'alert_count': 1,
            'alerts': [alert],
            'sources': {alert.get('source', 'unknown')},
            'rule_names': set([alert.get('rule_name', 'Unknown')]),
            'acknowledged': False,
            'blocked': False,
            'red_team_attack_id': alert.get('attack_id'),  # Link to Red Team attack
            'description': self._generate_description(alert, attack_type)
        }
        
        self.incidents[incident_id] = incident
        self.alert_to_incident[alert.get('id')] = incident_id
        
        return incident_id
    
    def _add_alert_to_incident(self, incident_id, alert):
        """Add an alert to an existing incident"""
        incident = self.incidents[incident_id]
        
        # Update incident
        incident['alert_count'] += 1
        incident['alerts'].append(alert)
        incident['last_seen'] = alert.get('timestamp')
        incident['sources'].add(alert.get('source', 'unknown'))
        incident['rule_names'].add(alert.get('rule_name', 'Unknown'))
        
        # Escalate severity if needed
        severity_levels = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        current_severity = severity_levels.get(incident['severity'], 2)
        alert_severity = severity_levels.get(alert.get('severity', 'Medium'), 2)
        
        if alert_severity > current_severity:
            incident['severity'] = alert.get('severity')
        
        # Track alert-to-incident mapping
        self.alert_to_incident[alert.get('id')] = incident_id
    
    def _extract_attack_type(self, alert):
        """Extract attack type from alert"""
        # Check attack_type field first
        if 'attack_type' in alert:
            return alert['attack_type']
        
        # Infer from rule name or description
        rule_name = alert.get('rule_name', '').lower()
        description = alert.get('description', '').lower()
        text = rule_name + ' ' + description
        
        if 'sql' in text or 'injection' in text:
            return 'sql_injection'
        elif 'brute' in text or 'login' in text or 'password' in text:
            return 'brute_force'
        elif 'port' in text or 'scan' in text:
            return 'port_scanner'
        elif 'ddos' in text or 'flood' in text or 'denial' in text:
            return 'ddos'
        else:
            return 'unknown'
    
    def _generate_description(self, alert, attack_type):
        """Generate human-readable incident description"""
        attack_names = {
            'sql_injection': 'SQL Injection Attack',
            'brute_force': 'Brute Force Attack',
            'port_scanner': 'Port Scanning Activity',
            'ddos': 'DDoS Attack',
            'unknown': 'Security Incident'
        }
        
        return attack_names.get(attack_type, 'Security Incident')
    
    def get_active_incidents(self):
        """Get all active incidents"""
        active = []
        for incident in self.incidents.values():
            if incident.get('status') == 'active':
                # Convert sets to lists for JSON serialization
                incident_copy = incident.copy()
                incident_copy['sources'] = list(incident['sources'])
                incident_copy['rule_names'] = list(incident['rule_names'])
                
                # Calculate duration
                first = datetime.fromisoformat(incident['first_seen'])
                last = datetime.fromisoformat(incident['last_seen'])
                incident_copy['duration_seconds'] = int((last - first).total_seconds())
                
                # Don't include full alerts list (too large), just count
                incident_copy['sample_alerts'] = incident['alerts'][:3]  # First 3 alerts as samples
                del incident_copy['alerts']
                
                active.append(incident_copy)
        
        # Sort by severity and last_seen
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        active.sort(key=lambda x: (severity_order.get(x['severity'], 4), x['last_seen']), reverse=True)
        
        return active
    
    def get_incident(self, incident_id):
        """Get full incident details including all alerts"""
        incident = self.incidents.get(incident_id)
        if not incident:
            return None
        
        incident_copy = incident.copy()
        incident_copy['sources'] = list(incident['sources'])
        incident_copy['rule_names'] = list(incident['rule_names'])
        
        # Calculate duration
        first = datetime.fromisoformat(incident['first_seen'])
        last = datetime.fromisoformat(incident['last_seen'])
        incident_copy['duration_seconds'] = int((last - first).total_seconds())
        
        return incident_copy
    
    def acknowledge_incident(self, incident_id):
        """Mark an incident as acknowledged"""
        if incident_id in self.incidents:
            self.incidents[incident_id]['acknowledged'] = True
            self.incidents[incident_id]['acknowledged_at'] = datetime.now().isoformat()
            return True
        return False
    
    def close_incident(self, incident_id):
        """Close an incident"""
        if incident_id in self.incidents:
            self.incidents[incident_id]['status'] = 'closed'
            self.incidents[incident_id]['closed_at'] = datetime.now().isoformat()
            return True
        return False
    
    def block_incident(self, incident_id):
        """Mark incident source as blocked"""
        if incident_id in self.incidents:
            self.incidents[incident_id]['blocked'] = True
            self.incidents[incident_id]['blocked_at'] = datetime.now().isoformat()
            return True
        return False
    
    def auto_close_old_incidents(self, max_age_seconds=300):
        """Auto-close incidents that haven't had new alerts in a while"""
        now = datetime.now()
        closed_count = 0
        
        for incident_id, incident in self.incidents.items():
            if incident.get('status') != 'active':
                continue
            
            last_seen = datetime.fromisoformat(incident['last_seen'])
            age = (now - last_seen).total_seconds()
            
            if age > max_age_seconds:
                self.close_incident(incident_id)
                closed_count += 1
        
        return closed_count
    
    def get_statistics(self):
        """Get correlation statistics"""
        stats = {
            'total_incidents': len(self.incidents),
            'active_incidents': len([i for i in self.incidents.values() if i.get('status') == 'active']),
            'closed_incidents': len([i for i in self.incidents.values() if i.get('status') == 'closed']),
            'total_correlated_alerts': len(self.alert_to_incident),
            'incidents_by_type': defaultdict(int),
            'incidents_by_severity': defaultdict(int)
        }
        
        for incident in self.incidents.values():
            stats['incidents_by_type'][incident.get('attack_type', 'unknown')] += 1
            stats['incidents_by_severity'][incident.get('severity', 'Medium')] += 1
        
        return dict(stats)