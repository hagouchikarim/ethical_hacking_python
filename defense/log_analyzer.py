"""
Log Analyzer Module
Analyzes system logs for security events
"""
from datetime import datetime
import re

class LogAnalyzer:
    def __init__(self):
        self.patterns = {
            'authentication_failure': r'(failed|invalid|denied).*auth',
            'privilege_escalation': r'(sudo|su|root|admin).*access',
            'file_access': r'(read|write|delete).*file',
            'network_connection': r'(connect|disconnect|established)',
            'error': r'(error|exception|failed|critical)'
        }
    
    def analyze_log(self, log_entry):
        """Analyze a single log entry"""
        message = str(log_entry.get('message', '')).lower()
        analysis = {
            'categories': [],
            'severity': 'info',
            'keywords': []
        }
        
        for category, pattern in self.patterns.items():
            if re.search(pattern, message, re.IGNORECASE):
                analysis['categories'].append(category)
                if category in ['authentication_failure', 'privilege_escalation']:
                    analysis['severity'] = 'warning'
                elif category == 'error':
                    analysis['severity'] = 'error'
        
        # Extract keywords
        keywords = re.findall(r'\b[a-z]{4,}\b', message)
        analysis['keywords'] = list(set(keywords[:5]))
        
        return analysis
    
    def correlate_events(self, logs, time_window=300):
        """Correlate related security events"""
        correlations = []
        
        # Group logs by time window
        time_groups = {}
        for log in logs:
            timestamp = datetime.fromisoformat(log.get('timestamp', datetime.now().isoformat()))
            window_key = int(timestamp.timestamp() / time_window)
            
            if window_key not in time_groups:
                time_groups[window_key] = []
            time_groups[window_key].append(log)
        
        # Find correlations
        for window, window_logs in time_groups.items():
            if len(window_logs) > 3:
                # Multiple events in short time - potential attack
                attack_types = set()
                sources = set()
                
                for log in window_logs:
                    if log.get('type') == 'attack':
                        attack_types.add(log.get('attack_type', 'unknown'))
                    sources.add(log.get('source_ip', 'unknown'))
                
                if len(attack_types) > 0 or len(sources) > 0:
                    correlations.append({
                        'timestamp': window_logs[0].get('timestamp'),
                        'event_count': len(window_logs),
                        'attack_types': list(attack_types),
                        'sources': list(sources),
                        'severity': 'high' if len(attack_types) > 0 else 'medium'
                    })
        
        return correlations
    
    def search_logs(self, logs, query, filters=None):
        """Search logs with filters"""
        results = []
        query_lower = query.lower()
        
        for log in logs:
            # Text search
            if query_lower not in str(log.get('message', '')).lower():
                continue
            
            # Apply filters
            if filters:
                if 'severity' in filters and log.get('severity') != filters['severity']:
                    continue
                if 'type' in filters and log.get('type') != filters['type']:
                    continue
                if 'source' in filters and filters['source'].lower() not in str(log.get('source_ip', '')).lower():
                    continue
            
            results.append(log)
        
        return results
