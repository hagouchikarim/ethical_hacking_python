"""
Intrusion Detection System (IDS)
Detects suspicious activities and generates alerts
"""
import re
from datetime import datetime
import uuid

class IntrusionDetectionSystem:
    def __init__(self):
        self.rules = [
            {
                'id': 'rule_001',
                'name': 'SQL Injection Detection',
                'pattern': r"('|(OR|AND)\s+\d+\s*=\s*\d+|UNION\s+SELECT|--|#|/\*|\*/)",
                'severity': 'High',
                'enabled': True,
                'description': 'Detects SQL injection attempts'
            },
            {
                'id': 'rule_002',
                'name': 'Brute Force Detection',
                'pattern': r'(failed.*login|authentication.*failed|invalid.*credentials)',
                'severity': 'Medium',
                'enabled': True,
                'description': 'Detects multiple failed login attempts'
            },
            {
                'id': 'rule_003',
                'name': 'Port Scan Detection',
                'pattern': r'(port.*scan|scanning.*ports|reconnaissance)',
                'severity': 'Low',
                'enabled': True,
                'description': 'Detects port scanning activities'
            },
            {
                'id': 'rule_004',
                'name': 'DDoS Detection',
                'pattern': r'(flooding|ddos|denial.*service|high.*traffic)',
                'severity': 'Critical',
                'enabled': True,
                'description': 'Detects denial of service attacks'
            },
            {
                'id': 'rule_005',
                'name': 'Suspicious Payload',
                'pattern': r'(<script|javascript:|eval\(|base64_decode)',
                'severity': 'High',
                'enabled': True,
                'description': 'Detects malicious payloads'
            }
        ]
        self.detection_count = 0
    
    def detect_attack(self, attack_update, attack_id):
        """Detect if an attack update matches any IDS rules"""
        message = str(attack_update.get('message', '')).lower()
        status = str(attack_update.get('status', '')).lower()
        
        for rule in self.rules:
            if not rule['enabled']:
                continue
            
            # Check pattern match
            if re.search(rule['pattern'], message, re.IGNORECASE) or \
               re.search(rule['pattern'], status, re.IGNORECASE):
                self.detection_count += 1
                return True
        
        return False
    
    def generate_alert(self, attack_update, attack_id):
        """Generate a security alert"""
        # Find matching rule
        message = str(attack_update.get('message', '')).lower()
        matched_rule = None
        
        for rule in self.rules:
            if not rule['enabled']:
                continue
            if re.search(rule['pattern'], message, re.IGNORECASE):
                matched_rule = rule
                break
        
        if not matched_rule:
            matched_rule = {
                'name': 'Unknown Threat',
                'severity': 'Medium',
                'description': 'Suspicious activity detected'
            }
        
        alert = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'severity': matched_rule['severity'],
            'rule_name': matched_rule['name'],
            'description': matched_rule['description'],
            'source_ip': attack_update.get('target', 'Unknown'),
            'attack_id': attack_id,
            'message': attack_update.get('message', ''),
            'status': 'active',
            'blocked': False,
            'acknowledged': False
        }
        
        return alert
    
    def get_rules(self):
        """Get all IDS rules"""
        return self.rules
    
    def add_rule(self, rule_data):
        """Add a new IDS rule"""
        rule_id = f"rule_{len(self.rules) + 1:03d}"
        rule = {
            'id': rule_id,
            'name': rule_data.get('name', 'Custom Rule'),
            'pattern': rule_data.get('pattern', ''),
            'severity': rule_data.get('severity', 'Medium'),
            'enabled': rule_data.get('enabled', True),
            'description': rule_data.get('description', '')
        }
        self.rules.append(rule)
        return rule_id
    
    def remove_rule(self, rule_id):
        """Remove an IDS rule"""
        self.rules = [r for r in self.rules if r['id'] != rule_id]
    
    def toggle_rule(self, rule_id):
        """Enable/disable an IDS rule"""
        for rule in self.rules:
            if rule['id'] == rule_id:
                rule['enabled'] = not rule['enabled']
                return rule['enabled']
        return None
