"""
DDoS Attack Module
Simulates Distributed Denial of Service attacks
"""
import time
import random
from datetime import datetime

class DDoSAttack:
    def __init__(self, target, parameters):
        self.target = target
        self.parameters = parameters
        self.duration = parameters.get('duration', 30)  # seconds
        self.intensity = parameters.get('intensity', 'medium')  # low, medium, high
        self.attack_type = parameters.get('attack_type', 'http_flood')  # http_flood, tcp_syn, udp_flood
        self.aborted = False
        self.results = {
            'packets_sent': 0,
            'bytes_sent': 0,
            'requests_per_second': 0,
            'target_response_time': [],
            'success': False,
            'start_time': None,
            'end_time': None
        }
        
        # Intensity multipliers
        self.intensity_multipliers = {
            'low': 10,
            'medium': 50,
            'high': 200
        }
    
    def execute(self):
        """Execute DDoS attack"""
        self.results['start_time'] = datetime.now().isoformat()
        requests_per_second = self.intensity_multipliers.get(self.intensity, 50)
        
        yield {
            'message': f'Starting {self.attack_type.upper()} DDoS attack on {self.target}',
            'progress': 0,
            'status': 'initializing',
            'packets_sent': 0,
            'requests_per_second': 0
        }
        
        time.sleep(0.5)
        
        start_time = time.time()
        packet_count = 0
        
        while (time.time() - start_time) < self.duration and not self.aborted:
            elapsed = time.time() - start_time
            progress = int((elapsed / self.duration) * 100)
            
            # Simulate sending packets
            packets_this_second = random.randint(
                int(requests_per_second * 0.8),
                int(requests_per_second * 1.2)
            )
            
            for _ in range(packets_this_second):
                packet_count += 1
                self.results['packets_sent'] += 1
                self.results['bytes_sent'] += random.randint(100, 1500)
                
                # Simulate target response time degradation
                if packet_count % 10 == 0:
                    response_time = random.uniform(0.5, 5.0) * (1 + elapsed / self.duration)
                    self.results['target_response_time'].append({
                        'timestamp': datetime.now().isoformat(),
                        'response_time': response_time
                    })
            
            self.results['requests_per_second'] = packets_this_second
            
            yield {
                'message': f'Flooding target with {packets_this_second} req/s',
                'progress': min(progress, 99),
                'status': 'flooding',
                'packets_sent': self.results['packets_sent'],
                'bytes_sent': self.results['bytes_sent'],
                'requests_per_second': packets_this_second,
                'elapsed_time': int(elapsed)
            }
            
            time.sleep(1)
        
        # Check if attack was successful (target overwhelmed)
        avg_response_time = sum([r['response_time'] for r in self.results['target_response_time']]) / max(len(self.results['target_response_time']), 1)
        self.results['success'] = avg_response_time > 3.0 or self.results['packets_sent'] > 1000
        
        self.results['end_time'] = datetime.now().isoformat()
        
        yield {
            'message': f'Attack completed. Sent {self.results["packets_sent"]} packets',
            'progress': 100,
            'status': 'completed',
            'packets_sent': self.results['packets_sent'],
            'bytes_sent': self.results['bytes_sent'],
            'success': self.results['success'],
            'avg_response_time': avg_response_time
        }
    
    def get_results(self):
        """Get attack results"""
        return self.results
    
    def abort(self):
        """Abort the attack"""
        self.aborted = True
