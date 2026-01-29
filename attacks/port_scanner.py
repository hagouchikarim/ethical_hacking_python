"""
Port Scanner Attack Module
Performs REAL port scanning with accurate results
"""
import socket
import time
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
        
        # Extract IP from URL if provided
        if 'http://' in self.target or 'https://' in self.target:
            self.target_ip = self.target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
        else:
            self.target_ip = self.target
        
        self.scan_type = parameters.get('scan_type', 'tcp')
        self.aborted = False
        self.results = {
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'services_detected': [],
            'total_scanned': 0,
            'target_ip': self.target_ip
        }
        
        # Common ports and services
        self.common_services = {
            20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
            27017: 'MongoDB', 9000: 'PHP-FPM'
        }
    
    def execute(self):
        """Execute port scan"""
        start_port, end_port = self.port_range
        
        yield {
            'message': f'🚀 Starting REAL {self.scan_type.upper()} port scan on {self.target_ip}',
            'progress': 0,
            'status': 'initializing',
            'ports_scanned': 0
        }
        
        yield {
            'message': f'🎯 Target: {self.target_ip} | Port range: {start_port}-{end_port}',
            'progress': 5,
            'status': 'configured'
        }
        
        time.sleep(0.3)
        
        # Limit scan for demo (max 200 ports)
        ports_to_scan = list(range(start_port, min(end_port + 1, start_port + 200)))
        total_ports = len(ports_to_scan)
        
        for i, port in enumerate(ports_to_scan):
            if self.aborted:
                yield {'message': 'Scan aborted', 'status': 'aborted'}
                break
            
            self.results['total_scanned'] += 1
            
            # Perform REAL port scan
            port_status, banner = self._scan_port_with_banner(self.target_ip, port)
            
            if port_status == 'open':
                service = self.common_services.get(port, 'Unknown')
                
                # Use banner info if available
                if banner:
                    service = f"{service} - {banner[:40]}"
                
                port_info = {
                    'port': port,
                    'status': 'open',
                    'service': service,
                    'banner': banner,
                    'protocol': self.scan_type.upper(),
                    'timestamp': datetime.now().isoformat()
                }
                self.results['open_ports'].append(port_info)
                self.results['services_detected'].append(service)
                
                yield {
                    'message': f'🔓 OPEN: Port {port} ({service})',
                    'progress': 5 + int((i + 1) / total_ports * 90),
                    'status': 'port_found',
                    'port': port_info,
                    'ports_scanned': i + 1
                }
                
            elif port_status == 'closed':
                self.results['closed_ports'].append(port)
                
            elif port_status == 'filtered':
                self.results['filtered_ports'].append(port)
                
                # Report filtered ports occasionally
                if len(self.results['filtered_ports']) % 10 == 0:
                    yield {
                        'message': f'🔒 Detected {len(self.results["filtered_ports"])} filtered ports (firewall active)',
                        'progress': 5 + int((i + 1) / total_ports * 90),
                        'status': 'filtered_detected',
                        'ports_scanned': i + 1
                    }
            
            # Small delay to avoid overwhelming target
            time.sleep(0.02)
        
        # Generate summary
        open_count = len(self.results['open_ports'])
        closed_count = len(self.results['closed_ports'])
        filtered_count = len(self.results['filtered_ports'])
        
        # Determine if target has strong security
        security_level = "WEAK" if open_count > 10 else "MODERATE" if open_count > 5 else "STRONG"
        
        yield {
            'message': f'✅ Scan complete! Open: {open_count} | Closed: {closed_count} | Filtered: {filtered_count} | Security: {security_level}',
            'progress': 100,
            'status': 'completed',
            'ports_scanned': self.results['total_scanned'],
            'open_ports_count': open_count,
            'security_assessment': security_level,
            'summary': {
                'open': open_count,
                'closed': closed_count,
                'filtered': filtered_count
            }
        }
    
    def _scan_port_with_banner(self, target, port):
        """Scan port and attempt to grab banner"""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            
            # Try to connect
            result = sock.connect_ex((target, port))
            
            if result == 0:
                # Port is open, try to grab banner
                banner = None
                try:
                    sock.settimeout(1)
                    
                    # Send probe for common services
                    if port in [21, 22, 25, 110]:  # Services that send banner
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    elif port in [80, 8080]:  # HTTP
                        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip().split('\n')[0]
                    
                    if banner:
                        banner = banner[:100]  # Limit length
                except:
                    pass
                
                sock.close()
                return 'open', banner
            else:
                sock.close()
                return 'closed', None
                
        except socket.timeout:
            return 'filtered', None
        except socket.error as e:
            if 'refused' in str(e).lower():
                return 'closed', None
            return 'filtered', None
        except Exception:
            return 'closed', None
    
    def get_results(self):
        """Get scan results"""
        return self.results
    
    def abort(self):
        """Abort the scan"""
        self.aborted = True