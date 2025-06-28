import re
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict, Counter
from models.log_entry import LogEntry

class ThreatDetector:
    """AI-based threat detection for log analysis"""
    
    def __init__(self):
        # Threat patterns and signatures
        self.threat_patterns = {
            'sql_injection': [
                r'(?i)(union\s+select|drop\s+table|insert\s+into|delete\s+from)',
                r'(?i)(or\s+1\s*=\s*1|or\s+\'1\'\s*=\s*\'1\')',
                r'(?i)(;.*--|/\*.*\*/)',
                r'(?i)(exec\s*\(|eval\s*\()',
            ],
            'xss_attack': [
                r'(?i)(<script[^>]*>.*</script>)',
                r'(?i)(javascript:)',
                r'(?i)(onload\s*=|onerror\s*=|onclick\s*=)',
                r'(?i)(alert\s*\(|confirm\s*\(|prompt\s*\()',
            ],
            'path_traversal': [
                r'(?i)(\.\./|\.\.\\)',
                r'(?i)(/etc/passwd|/etc/shadow|/proc/)',
                r'(?i)(c:\\windows\\system32|c:\\windows\\win.ini)',
            ],
            'authentication_failure': [
                r'(?i)(authentication\s+failed|login\s+failed|invalid\s+credentials)',
                r'(?i)(wrong\s+password|incorrect\s+username)',
                r'(?i)(access\s+denied|unauthorized\s+access)',
            ],
            'brute_force': [
                r'(?i)(too\s+many\s+failed\s+attempts)',
                r'(?i)(account\s+locked|temporarily\s+blocked)',
                r'(?i)(multiple\s+failed\s+logins)',
            ],
            'data_exfiltration': [
                r'(?i)(large\s+data\s+transfer|bulk\s+download)',
                r'(?i)(export\s+data|download\s+all)',
                r'(?i)(sensitive\s+data|confidential)',
            ],
            'system_intrusion': [
                r'(?i)(root\s+access|privilege\s+escalation)',
                r'(?i)(backdoor|trojan|malware)',
                r'(?i)(unauthorized\s+process|suspicious\s+activity)',
            ],
            'network_attack': [
                r'(?i)(ddos|dos|flood|spam)',
                r'(?i)(port\s+scan|network\s+scan)',
                r'(?i)(syn\s+flood|udp\s+flood)',
            ],
            'file_manipulation': [
                r'(?i)(file\s+upload|file\s+modification)',
                r'(?i)(executable\s+file|script\s+file)',
                r'(?i)(suspicious\s+file|malicious\s+file)',
            ],
            'api_abuse': [
                r'(?i)(rate\s+limit\s+exceeded|too\s+many\s+requests)',
                r'(?i)(api\s+key\s+invalid|unauthorized\s+api)',
                r'(?i)(endpoint\s+not\s+found|method\s+not\s+allowed)',
            ]
        }
        
        # Anomaly detection thresholds
        self.anomaly_thresholds = {
            'error_rate': 0.1,  # 10% error rate threshold
            'consecutive_errors': 5,  # 5 consecutive errors
            'time_window': 300,  # 5 minutes window for burst detection
            'request_frequency': 100,  # 100 requests per minute threshold
        }
        
        # Risk scoring weights
        self.risk_weights = {
            'sql_injection': 9,
            'xss_attack': 8,
            'path_traversal': 7,
            'authentication_failure': 6,
            'brute_force': 8,
            'data_exfiltration': 9,
            'system_intrusion': 10,
            'network_attack': 7,
            'file_manipulation': 6,
            'api_abuse': 5,
        }
    
    def analyze_threats(self, log_entries: List[LogEntry]) -> Dict[str, Any]:
        """Perform comprehensive threat analysis on log entries"""
        if not log_entries:
            return {
                'threats': [],
                'risk_score': 0,
                'anomalies': [],
                'summary': 'No logs to analyze'
            }
        
        # Pattern-based threat detection
        pattern_threats = self._detect_pattern_threats(log_entries)
        
        # Anomaly detection
        anomalies = self._detect_anomalies(log_entries)
        
        # Behavioral analysis
        behavioral_threats = self._analyze_behavior(log_entries)
        
        # Combine all threats
        all_threats = pattern_threats + behavioral_threats
        
        # Calculate overall risk score
        risk_score = self._calculate_risk_score(all_threats, anomalies)
        
        # Generate threat summary
        summary = self._generate_summary(all_threats, anomalies, risk_score)
        
        return {
            'threats': all_threats,
            'anomalies': anomalies,
            'risk_score': risk_score,
            'summary': summary,
            'statistics': {
                'total_threats': len(all_threats),
                'high_risk_threats': len([t for t in all_threats if t.get('severity') == 'high']),
                'medium_risk_threats': len([t for t in all_threats if t.get('severity') == 'medium']),
                'low_risk_threats': len([t for t in all_threats if t.get('severity') == 'low']),
                'anomalies_detected': len(anomalies)
            }
        }
    
    def _detect_pattern_threats(self, log_entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Detect threats based on known patterns"""
        threats = []
        
        for entry in log_entries:
            entry_threats = []
            
            for threat_type, patterns in self.threat_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, entry.message, re.IGNORECASE):
                        threat = {
                            'type': threat_type,
                            'severity': self._get_threat_severity(threat_type),
                            'message': entry.message,
                            'timestamp': entry.timestamp.isoformat() if isinstance(entry.timestamp, datetime) else str(entry.timestamp),
                            'source': entry.source,
                            'line_number': entry.line_number,
                            'confidence': 0.9,  # High confidence for pattern matches
                            'pattern_matched': pattern
                        }
                        entry_threats.append(threat)
                        break  # Only report first match per threat type
            
            threats.extend(entry_threats)
        
        return threats
    
    def _detect_anomalies(self, log_entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Detect anomalies in log patterns"""
        anomalies = []
        
        if not log_entries:
            return anomalies
        
        # Calculate error rate
        error_count = sum(1 for entry in log_entries if entry.level.upper() == 'ERROR')
        error_rate = error_count / len(log_entries)
        
        if error_rate > self.anomaly_thresholds['error_rate']:
            anomalies.append({
                'type': 'high_error_rate',
                'severity': 'medium',
                'description': f'High error rate detected: {error_rate:.2%}',
                'value': error_rate,
                'threshold': self.anomaly_thresholds['error_rate']
            })
        
        # Detect consecutive errors
        consecutive_errors = 0
        max_consecutive = 0
        
        for entry in log_entries:
            if entry.level.upper() == 'ERROR':
                consecutive_errors += 1
                max_consecutive = max(max_consecutive, consecutive_errors)
            else:
                consecutive_errors = 0
        
        if max_consecutive >= self.anomaly_thresholds['consecutive_errors']:
            anomalies.append({
                'type': 'consecutive_errors',
                'severity': 'high',
                'description': f'Consecutive errors detected: {max_consecutive}',
                'value': max_consecutive,
                'threshold': self.anomaly_thresholds['consecutive_errors']
            })
        
        # Time-based anomaly detection
        time_anomalies = self._detect_time_anomalies(log_entries)
        anomalies.extend(time_anomalies)
        
        return anomalies
    
    def _detect_time_anomalies(self, log_entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Detect anomalies based on timing patterns"""
        anomalies = []
        
        if len(log_entries) < 2:
            return anomalies
        
        # Group logs by time windows
        time_windows = defaultdict(list)
        window_size = timedelta(seconds=self.anomaly_thresholds['time_window'])
        
        for entry in log_entries:
            if isinstance(entry.timestamp, datetime):
                window_start = entry.timestamp.replace(second=entry.timestamp.second - (entry.timestamp.second % self.anomaly_thresholds['time_window']))
                time_windows[window_start].append(entry)
        
        # Check for burst activity
        for window_start, entries in time_windows.items():
            if len(entries) > self.anomaly_thresholds['request_frequency']:
                anomalies.append({
                    'type': 'burst_activity',
                    'severity': 'medium',
                    'description': f'High activity burst detected: {len(entries)} entries in {self.anomaly_thresholds["time_window"]}s',
                    'value': len(entries),
                    'threshold': self.anomaly_thresholds['request_frequency'],
                    'window_start': window_start.isoformat()
                })
        
        return anomalies
    
    def _analyze_behavior(self, log_entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Analyze behavioral patterns for threats"""
        behavioral_threats = []
        
        # Analyze authentication patterns
        auth_threats = self._analyze_auth_behavior(log_entries)
        behavioral_threats.extend(auth_threats)
        
        # Analyze access patterns
        access_threats = self._analyze_access_behavior(log_entries)
        behavioral_threats.extend(access_threats)
        
        # Analyze data access patterns
        data_threats = self._analyze_data_behavior(log_entries)
        behavioral_threats.extend(data_threats)
        
        return behavioral_threats
    
    def _analyze_auth_behavior(self, log_entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Analyze authentication behavior for suspicious patterns"""
        threats = []
        
        # Count authentication-related entries
        auth_entries = [entry for entry in log_entries if 'auth' in entry.message.lower() or 'login' in entry.message.lower()]
        
        if len(auth_entries) > 10:  # Threshold for suspicious auth activity
            threats.append({
                'type': 'suspicious_auth_activity',
                'severity': 'medium',
                'message': f'High number of authentication attempts: {len(auth_entries)}',
                'timestamp': datetime.now().isoformat(),
                'confidence': 0.7
            })
        
        return threats
    
    def _analyze_access_behavior(self, log_entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Analyze access patterns for suspicious behavior"""
        threats = []
        
        # Look for unusual access patterns
        access_entries = [entry for entry in log_entries if any(word in entry.message.lower() for word in ['access', 'permission', 'denied', 'unauthorized'])]
        
        if len(access_entries) > 5:
            threats.append({
                'type': 'unusual_access_patterns',
                'severity': 'medium',
                'message': f'Unusual access patterns detected: {len(access_entries)} access-related entries',
                'timestamp': datetime.now().isoformat(),
                'confidence': 0.6
            })
        
        return threats
    
    def _analyze_data_behavior(self, log_entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Analyze data access patterns for potential data exfiltration"""
        threats = []
        
        # Look for data-related activities
        data_entries = [entry for entry in log_entries if any(word in entry.message.lower() for word in ['data', 'export', 'download', 'transfer', 'copy'])]
        
        if len(data_entries) > 3:
            threats.append({
                'type': 'potential_data_exfiltration',
                'severity': 'high',
                'message': f'Potential data exfiltration activity: {len(data_entries)} data-related entries',
                'timestamp': datetime.now().isoformat(),
                'confidence': 0.8
            })
        
        return threats
    
    def _get_threat_severity(self, threat_type: str) -> str:
        """Get severity level for threat type"""
        high_severity = ['sql_injection', 'data_exfiltration', 'system_intrusion']
        medium_severity = ['xss_attack', 'brute_force', 'path_traversal', 'network_attack']
        
        if threat_type in high_severity:
            return 'high'
        elif threat_type in medium_severity:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_risk_score(self, threats: List[Dict[str, Any]], anomalies: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score"""
        score = 0.0
        
        # Add threat scores
        for threat in threats:
            threat_type = threat.get('type', '')
            weight = self.risk_weights.get(threat_type, 5)
            confidence = threat.get('confidence', 0.5)
            score += weight * confidence
        
        # Add anomaly scores
        for anomaly in anomalies:
            severity = anomaly.get('severity', 'low')
            if severity == 'high':
                score += 10
            elif severity == 'medium':
                score += 5
            else:
                score += 2
        
        # Normalize score to 0-100 range
        max_possible_score = sum(self.risk_weights.values()) + len(anomalies) * 10
        normalized_score = min(100, (score / max_possible_score) * 100) if max_possible_score > 0 else 0
        
        return round(normalized_score, 2)
    
    def _generate_summary(self, threats: List[Dict[str, Any]], anomalies: List[Dict[str, Any]], risk_score: float) -> str:
        """Generate human-readable threat summary"""
        if not threats and not anomalies:
            return "No threats or anomalies detected. Logs appear normal."
        
        summary_parts = []
        
        if threats:
            threat_types = Counter(threat['type'] for threat in threats)
            summary_parts.append(f"Detected {len(threats)} threats: {', '.join(f'{count} {type_}' for type_, count in threat_types.most_common())}")
        
        if anomalies:
            summary_parts.append(f"Found {len(anomalies)} anomalies")
        
        if risk_score > 70:
            summary_parts.append("HIGH RISK - Immediate attention required")
        elif risk_score > 40:
            summary_parts.append("MEDIUM RISK - Investigation recommended")
        else:
            summary_parts.append("LOW RISK - Monitor for changes")
        
        return ". ".join(summary_parts) 