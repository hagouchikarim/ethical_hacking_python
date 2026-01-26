"""
Port Scanner Attack Module
Simulates port scanning reconnaissance attacks
"""
import time
import random
from datetime import datetime

class PortScannerAttack:
    def __init__(self, target, parameters):
        self.target = target
        self.parameters = parameters
        port_range = parameters.get('port_range', (1, 1000))
        # Handle both list and tuple formats
        if isinstance(port_range, list):
            self.port_range = tuple(port_range)
        else:
            self.port_range = port_range if isinstance(port_range, tuple) else (1, 1000)
        self.scan_type = parameters.get('scan_type', 'tcp')  # tcp, udp, syn
        self.aborted = False
        self.results = {
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'services_detected': [],
            'total_scanned': 0
        }
        
        # Common ports and services
        self.common_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
        }
    
    def execute(self):
        """Execute port scan"""
        start_port, end_port = self.port_range
        total_ports = end_port - start_port + 1
        
        yield {
            'message': f'Starting {self.scan_type.upper()} port scan on {self.target}',
            'progress': 0,
            'status': 'initializing',
            'ports_scanned': 0
        }
        
        time.sleep(0.5)
        
        # Simulate scanning ports
        ports_to_scan = list(range(start_port, min(end_port + 1, start_port + 100)))  # Limit for demo
        
        for i, port in enumerate(ports_to_scan):
            if self.aborted:
                yield {'message': 'Scan aborted', 'status': 'aborted'}
                break
            
            self.results['total_scanned'] += 1
            
            # Simulate port status (30% open, 60% closed, 10% filtered)
            rand = random.random()
            
            if rand < 0.3:  # Open port
                service = self.common_services.get(port, 'Unknown')
                port_info = {
                    'port': port,
                    'status': 'open',
                    'service': service,
                    'protocol': self.scan_type.upper(),
                    'timestamp': datetime.now().isoformat()
                }
                self.results['open_ports'].append(port_info)
                self.results['services_detected'].append(service)
                
                yield {
                    'message': f'🔓 Port {port} ({service}) is OPEN',
                    'progress': int((i + 1) / len(ports_to_scan) * 100),
                    'status': 'port_found',
                    'port': port_info,
                    'ports_scanned': i + 1
                }
            elif rand < 0.9:  # Closed port
                self.results['closed_ports'].append(port)
            else:  # Filtered port
                self.results['filtered_ports'].append(port)
                yield {
                    'message': f'🔒 Port {port} is FILTERED (firewall may be blocking)',
                    'progress': int((i + 1) / len(ports_to_scan) * 100),
                    'status': 'filtered',
                    'port': port,
                    'ports_scanned': i + 1
                }
            
            time.sleep(0.1)
        
        # Summary
        yield {
            'message': f'Scan completed. Found {len(self.results["open_ports"])} open ports',
            'progress': 100,
            'status': 'completed',
            'ports_scanned': self.results['total_scanned'],
            'open_ports_count': len(self.results['open_ports']),
            'summary': {
                'open': len(self.results['open_ports']),
                'closed': len(self.results['closed_ports']),
                'filtered': len(self.results['filtered_ports'])
            }
        }
    
    def get_results(self):
        """Get scan results"""
        return self.results
    
    def abort(self):
        """Abort the scan"""
        self.aborted = True
