"""
SQL Injection Attack Module
Simulates SQL injection attacks against web applications
"""
import time
import random
from datetime import datetime

class SQLInjectionAttack:
    def __init__(self, target, parameters):
        self.target = target
        self.parameters = parameters
        self.intensity = parameters.get('intensity', 'medium')
        self.payloads = parameters.get('payloads', [])
        self.aborted = False
        self.results = {
            'vulnerabilities_found': [],
            'data_extracted': [],
            'success': False,
            'attempts': 0
        }
        
        # Default payloads if none provided
        if not self.payloads:
            self.payloads = [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "admin' --",
                "' UNION SELECT NULL--",
                "1' AND '1'='1",
                "1' AND '1'='2",
                "' OR 1=1#",
                "admin'/*",
                "' OR 'x'='x",
                "' AND 1=1--"
            ]
    
    def execute(self):
        """Execute SQL injection attack"""
        yield {
            'message': f'Starting SQL Injection attack on {self.target}',
            'progress': 0,
            'status': 'initializing',
            'packets_sent': 0
        }
        
        total_payloads = len(self.payloads)
        attempts = 0
        
        for i, payload in enumerate(self.payloads):
            if self.aborted:
                yield {'message': 'Attack aborted', 'status': 'aborted'}
                break
            
            attempts += 1
            self.results['attempts'] = attempts
            
            # Simulate payload injection
            yield {
                'message': f'Testing payload: {payload[:30]}...',
                'progress': int((i + 1) / total_payloads * 100),
                'status': 'testing',
                'payload': payload,
                'packets_sent': attempts
            }
            
            time.sleep(0.3)
            
            # Simulate vulnerability detection (30% chance)
            if random.random() < 0.3:
                vulnerability = {
                    'type': 'SQL Injection',
                    'payload': payload,
                    'parameter': random.choice(['username', 'password', 'id', 'search']),
                    'severity': random.choice(['High', 'Critical']),
                    'timestamp': datetime.now().isoformat()
                }
                self.results['vulnerabilities_found'].append(vulnerability)
                
                yield {
                    'message': f'⚠️ Vulnerability detected! Parameter: {vulnerability["parameter"]}',
                    'progress': int((i + 1) / total_payloads * 100),
                    'status': 'vulnerability_found',
                    'vulnerability': vulnerability,
                    'packets_sent': attempts
                }
                
                # Simulate data extraction
                if random.random() < 0.5:
                    extracted_data = {
                        'type': random.choice(['user_credentials', 'database_schema', 'table_names']),
                        'data': self._simulate_data_extraction(),
                        'timestamp': datetime.now().isoformat()
                    }
                    self.results['data_extracted'].append(extracted_data)
                    
                    yield {
                        'message': f'📊 Data extracted: {extracted_data["type"]}',
                        'progress': int((i + 1) / total_payloads * 100),
                        'status': 'data_extracted',
                        'extracted_data': extracted_data,
                        'packets_sent': attempts
                    }
            
            time.sleep(0.2)
        
        # Final results
        self.results['success'] = len(self.results['vulnerabilities_found']) > 0
        
        yield {
            'message': f'Attack completed. Found {len(self.results["vulnerabilities_found"])} vulnerabilities',
            'progress': 100,
            'status': 'completed',
            'packets_sent': attempts,
            'vulnerabilities_count': len(self.results['vulnerabilities_found'])
        }
    
    def _simulate_data_extraction(self):
        """Simulate extracting data from database"""
        sample_data = {
            'user_credentials': [
                {'username': 'admin', 'password': '5f4dcc3b5aa765d61d8327deb882cf99'},
                {'username': 'user1', 'password': '098f6bcd4621d373cade4e832627b4f6'}
            ],
            'database_schema': {
                'tables': ['users', 'products', 'orders', 'payments'],
                'columns': ['id', 'username', 'email', 'password_hash']
            },
            'table_names': ['users', 'admin', 'sessions', 'config']
        }
        return random.choice(list(sample_data.values()))
    
    def get_results(self):
        """Get attack results"""
        return self.results
    
    def abort(self):
        """Abort the attack"""
        self.aborted = True
