"""
Firewall Module
Manages firewall rules and IP blocking
"""
from datetime import datetime
import uuid

class Firewall:
    def __init__(self):
        self.rules = [
            {
                'id': 'fw_001',
                'name': 'Block Known Malicious IPs',
                'action': 'block',
                'source_ip': '192.168.1.100',
                'protocol': 'all',
                'port': 'all',
                'enabled': True,
                'created': datetime.now().isoformat()
            },
            {
                'id': 'fw_002',
                'name': 'Allow HTTP/HTTPS',
                'action': 'allow',
                'source_ip': 'any',
                'protocol': 'tcp',
                'port': '80,443',
                'enabled': True,
                'created': datetime.now().isoformat()
            }
        ]
        self.blocked_ips = set(['192.168.1.100'])
        self.stats = {
            'packets_blocked': 0,
            'packets_allowed': 0,
            'rules_triggered': {}
        }
    
    def check_packet(self, source_ip, protocol='tcp', port=None):
        """Check if a packet should be allowed or blocked"""
        # Check blocked IPs first
        if source_ip in self.blocked_ips:
            self.stats['packets_blocked'] += 1
            return False
        
        # Check rules
        for rule in self.rules:
            if not rule['enabled']:
                continue
            
            # Check IP match
            if rule['source_ip'] != 'any' and rule['source_ip'] != source_ip:
                continue
            
            # Check protocol
            if rule['protocol'] != 'all' and rule['protocol'] != protocol:
                continue
            
            # Check port
            if rule['port'] != 'all':
                allowed_ports = [int(p) for p in rule['port'].split(',')]
                if port and port not in allowed_ports:
                    continue
            
            # Apply action
            if rule['action'] == 'block':
                self.stats['packets_blocked'] += 1
                rule_id = rule['id']
                self.stats['rules_triggered'][rule_id] = self.stats['rules_triggered'].get(rule_id, 0) + 1
                return False
            elif rule['action'] == 'allow':
                self.stats['packets_allowed'] += 1
                return True
        
        # Default allow
        self.stats['packets_allowed'] += 1
        return True
    
    def block_ip(self, ip):
        """Block an IP address"""
        self.blocked_ips.add(ip)
        
        # Add rule if not exists
        rule_id = f"fw_block_{ip.replace('.', '_')}"
        rule = {
            'id': rule_id,
            'name': f'Block IP: {ip}',
            'action': 'block',
            'source_ip': ip,
            'protocol': 'all',
            'port': 'all',
            'enabled': True,
            'created': datetime.now().isoformat()
        }
        self.rules.append(rule)
        return rule_id
    
    def unblock_ip(self, ip):
        """Unblock an IP address"""
        self.blocked_ips.discard(ip)
        # Remove blocking rules for this IP
        self.rules = [r for r in self.rules if not (r['source_ip'] == ip and r['action'] == 'block')]
    
    def get_rules(self):
        """Get all firewall rules"""
        return self.rules
    
    def add_rule(self, rule_data):
        """Add a new firewall rule"""
        rule_id = f"fw_{len(self.rules) + 1:03d}"
        rule = {
            'id': rule_id,
            'name': rule_data.get('name', 'Custom Rule'),
            'action': rule_data.get('action', 'block'),
            'source_ip': rule_data.get('source_ip', 'any'),
            'protocol': rule_data.get('protocol', 'all'),
            'port': rule_data.get('port', 'all'),
            'enabled': rule_data.get('enabled', True),
            'created': datetime.now().isoformat()
        }
        self.rules.append(rule)
        return rule_id
    
    def remove_rule(self, rule_id):
        """Remove a firewall rule"""
        self.rules = [r for r in self.rules if r['id'] != rule_id]
    
    def get_stats(self):
        """Get firewall statistics"""
        return self.stats
    
    def get_blocked_ips(self):
        """Get list of blocked IPs"""
        return list(self.blocked_ips)
