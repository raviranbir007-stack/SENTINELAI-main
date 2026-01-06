import logging
from typing import Dict, Any, List
import re

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """Enhanced local anomaly detector with improved heuristics"""
    
    def __init__(self):
        self.threshold = 0.7
        self.suspicious_patterns = [
            r'(?:cmd|powershell|bash|sh)\.exe',  # Shell execution
            r'(?:eval|exec|system|shell_exec)',  # Code execution
            r'(?:\.\./|\.\.\\)',  # Path traversal
            r'(?:union|select|insert|update|delete|drop).*(?:from|into|table)',  # SQL injection
            r'<script[^>]*>',  # XSS
            r'(?:0x[0-9a-f]+)',  # Hex patterns
        ]
        self.malicious_ports = [31337, 12345, 6667, 6666]  # Known backdoor ports
        logger.info("Enhanced AnomalyDetector initialized")
        
    def detect(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomalies in data with comprehensive analysis"""
        anomaly_score = 0.0
        anomalies_found = 0
        details = []
        
        # Check for suspicious patterns in target
        target = str(data.get('target', ''))
        for pattern in self.suspicious_patterns:
            if re.search(pattern, target, re.IGNORECASE):
                anomaly_score += 0.15
                anomalies_found += 1
                details.append(f"Suspicious pattern detected: {pattern}")
        
        # Check for malicious ports
        if 'port' in data and data['port'] in self.malicious_ports:
            anomaly_score += 0.3
            anomalies_found += 1
            details.append(f"Malicious port detected: {data['port']}")
        
        # Check threat indicators
        threat_indicators = data.get('threat_indicators', [])
        if threat_indicators:
            critical_count = sum(1 for t in threat_indicators if t.get('severity') == 'critical')
            high_count = sum(1 for t in threat_indicators if t.get('severity') == 'high')
            anomaly_score += (critical_count * 0.2 + high_count * 0.1)
            anomalies_found += len(threat_indicators)
            details.append(f"Threat indicators found: {len(threat_indicators)} (Critical: {critical_count}, High: {high_count})")
        
        # Check verdict
        verdict = data.get('verdict', 'unknown')
        if verdict == 'malicious':
            anomaly_score += 0.4
            anomalies_found += 1
            details.append("Verdict: Malicious")
        elif verdict == 'suspicious':
            anomaly_score += 0.2
            details.append("Verdict: Suspicious")
        
        # Normalize score
        anomaly_score = min(anomaly_score, 1.0)
        
        return {
            "anomalies_found": anomalies_found,
            "anomaly_score": round(anomaly_score, 3),
            "is_anomalous": anomaly_score >= self.threshold,
            "details": " | ".join(details) if details else "No significant anomalies detected",
            "source": "enhanced_local_detector",
            "confidence": 0.85 if anomalies_found > 0 else 0.6
        }

# Singleton instance
_detector_instance = None

def get_anomaly_detector():
    """Get anomaly detector instance"""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = AnomalyDetector()
    return _detector_instance
