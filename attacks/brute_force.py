"""
Brute Force Attack Module
Simulates brute force password cracking attacks
"""
import time
import random
from datetime import datetime

class BruteForceAttack:
    def __init__(self, target, parameters):
        self.target = target
        self.parameters = parameters
        self.username = parameters.get('username', 'admin')
        self.wordlist = parameters.get('wordlist', [])
        self.max_attempts = parameters.get('max_attempts', 100)
        self.aborted = False
        self.results = {
            'attempts': 0,
            'success': False,
            'credentials_found': None,
            'failed_attempts': []
        }
        
        # Default wordlist if none provided
        if not self.wordlist:
            self.wordlist = [
                'password', '123456', 'admin', 'root', 'password123',
                'admin123', '12345678', 'qwerty', 'letmein', 'welcome',
                'monkey', '1234567', 'dragon', 'master', 'hello',
                'freedom', 'whatever', 'qazwsx', 'trustno1', 'jordan23'
            ]
    
    def execute(self):
        """Execute brute force attack"""
        yield {
            'message': f'Starting Brute Force attack on {self.target}',
            'progress': 0,
            'status': 'initializing',
            'attempts': 0
        }
        
        time.sleep(0.5)
        
        for i, password in enumerate(self.wordlist[:self.max_attempts]):
            if self.aborted:
                yield {'message': 'Attack aborted', 'status': 'aborted'}
                break
            
            self.results['attempts'] = i + 1
            
            # Simulate login attempt
            yield {
                'message': f'Attempting: {self.username} / {password}',
                'progress': int((i + 1) / min(len(self.wordlist), self.max_attempts) * 100),
                'status': 'trying',
                'username': self.username,
                'password': password,
                'attempts': i + 1
            }
            
            time.sleep(0.4)
            
            # Simulate success (5% chance, or if password is in common list)
            success_chance = 0.05
            if password in ['password', 'admin', '123456', 'admin123']:
                success_chance = 0.8
            
            if random.random() < success_chance:
                self.results['success'] = True
                self.results['credentials_found'] = {
                    'username': self.username,
                    'password': password,
                    'timestamp': datetime.now().isoformat()
                }
                
                yield {
                    'message': f'✅ SUCCESS! Credentials found: {self.username} / {password}',
                    'progress': 100,
                    'status': 'success',
                    'credentials': self.results['credentials_found'],
                    'attempts': i + 1
                }
                break
            else:
                self.results['failed_attempts'].append({
                    'username': self.username,
                    'password': password,
                    'timestamp': datetime.now().isoformat()
                })
                
                # Simulate account lockout after many attempts
                if (i + 1) % 10 == 0:
                    yield {
                        'message': f'⚠️ Warning: {i + 1} failed attempts detected',
                        'progress': int((i + 1) / min(len(self.wordlist), self.max_attempts) * 100),
                        'status': 'warning',
                        'attempts': i + 1
                    }
            
            time.sleep(0.3)
        
        if not self.results['success']:
            yield {
                'message': f'Attack completed. No valid credentials found after {self.results["attempts"]} attempts',
                'progress': 100,
                'status': 'failed',
                'attempts': self.results['attempts']
            }
    
    def get_results(self):
        """Get attack results"""
        return self.results
    
    def abort(self):
        """Abort the attack"""
        self.aborted = True
