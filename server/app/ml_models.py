import logging
from typing import Dict, Any

# Optional numpy import - models work without it (minimal storage mode)
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.info("NumPy not available - using minimal ML mode")

logger = logging.getLogger(__name__)

class AnomalyDetectionModel:
    """Enhanced local anomaly detection model with advanced pattern recognition"""
    
    def __init__(self):
        self.threshold = 0.8
        logger.info(f"AnomalyDetectionModel initialized (NumPy: {NUMPY_AVAILABLE})")
        
    def predict(self, features) -> Dict[str, Any]:
        """Predict anomalies using enhanced rule-based approach
        
        Args:
            features: Either Dict[str, Any] or List[Dict[str, Any]]
        """
        # Handle list input (batch prediction)
        if isinstance(features, list):
            return [self.predict(f) for f in features]
            
        # Enhanced anomaly detection
        score = 0.2
        anomaly_factors = []
        
        # Check for threat indicators
        threat_indicators = features.get('threat_indicators', [])
        if threat_indicators:
            score += len(threat_indicators) * 0.15
            anomaly_factors.append(f"{len(threat_indicators)} threat indicators")
            
        # Check verdict
        verdict = features.get('verdict', 'unknown')
        if verdict == 'malicious':
            score += 0.4
            anomaly_factors.append("Malicious verdict")
        elif verdict == 'suspicious':
            score += 0.2
            anomaly_factors.append("Suspicious verdict")
            
        # Check for unusual behavior patterns
        scan_type = features.get('scan_type', '')
        if scan_type in ['file', 'hash']:
            # File-specific anomaly checks
            file_size = features.get('file_size', 0)
            if file_size > 10 * 1024 * 1024:  # > 10MB
                score += 0.1
                anomaly_factors.append("Large file size")
        
        # Check API results
        api_results = features.get('api_results', {})
        if api_results:
            apis_flagged = sum(1 for api, result in api_results.items() 
                             if isinstance(result, dict) and result.get('malicious', False))
            if apis_flagged > 0:
                score += apis_flagged * 0.15
                anomaly_factors.append(f"{apis_flagged} APIs flagged as malicious")
        
        # Normalize score
        score = min(score, 1.0)
        
        return {
            "is_anomaly": score > self.threshold,
            "score": round(score, 3),
            "confidence": 0.8 if len(anomaly_factors) > 0 else 0.6,
            "factors": anomaly_factors,
            "source": "enhanced_local_model"
        }

class ThreatPredictionModel:
    """Enhanced local threat prediction model with advanced heuristics"""
    
    def __init__(self):
        self.threshold = 0.7
        logger.info(f"ThreatPredictionModel initialized (NumPy: {NUMPY_AVAILABLE})")
        
    def predict(self, features) -> Dict[str, Any]:
        """Predict threats using enhanced rule-based approach
        
        Args:
            features: Either Dict[str, Any] or List[Dict[str, Any]]
        """
        # Handle list input (batch prediction)
        if isinstance(features, list):
            return [self.predict(f) for f in features]
            
        # Enhanced threat prediction
        probability = 0.1
        threat_level = "safe"
        factors = []
        
        # Analyze threat indicators with weighted scoring
        threat_indicators = features.get('threat_indicators', [])
        if threat_indicators:
            critical_count = sum(1 for t in threat_indicators if t.get('severity') == 'critical')
            high_count = sum(1 for t in threat_indicators if t.get('severity') == 'high')
            medium_count = sum(1 for t in threat_indicators if t.get('severity') == 'medium')
            
            probability += critical_count * 0.3
            probability += high_count * 0.2
            probability += medium_count * 0.1
            
            if critical_count > 0:
                factors.append(f"{critical_count} critical indicators")
            if high_count > 0:
                factors.append(f"{high_count} high indicators")
            
        # Analyze verdict
        verdict = features.get('verdict', 'unknown')
        if verdict == 'malicious':
            probability = max(probability, 0.9)
            threat_level = "critical"
            factors.append("Malicious verdict")
        elif verdict == 'suspicious':
            probability = max(probability, 0.6)
            threat_level = "suspicious"
            factors.append("Suspicious verdict")
        elif verdict == 'safe':
            probability = min(probability, 0.3)
            
        # Analyze malicious score from APIs
        malicious_score = features.get('malicious_score', 0)
        if malicious_score > 0:
            probability += malicious_score * 0.4
            factors.append(f"Malicious score: {malicious_score}")
        
        # Analyze detection ratio
        detection_ratio = features.get('detection_ratio', '0/0')
        if '/' in str(detection_ratio):
            try:
                detected, total = map(int, detection_ratio.split('/'))
                if total > 0:
                    ratio = detected / total
                    if ratio > 0.3:
                        probability += ratio * 0.3
                        factors.append(f"Detection ratio: {detected}/{total}")
            except:
                pass
        
        # Cap probability
        probability = min(probability, 0.99)
        
        # Determine threat level
        if probability >= 0.8:
            threat_level = "critical"
        elif probability >= 0.6:
            threat_level = "high"
        elif probability >= 0.4:
            threat_level = "suspicious"
        else:
            threat_level = "safe"
            
        return {
            "is_threat": probability > self.threshold,
            "probability": round(probability, 3),
            "threat_level": threat_level,
            "confidence": 0.75 if len(factors) > 0 else 0.5,
            "factors": factors,
            "source": "enhanced_local_model"
        }

# Singleton instances
_anomaly_model = None
_threat_model = None

def get_anomaly_model():
    """Get anomaly detection model instance"""
    global _anomaly_model
    if _anomaly_model is None:
        _anomaly_model = AnomalyDetectionModel()
    return _anomaly_model

def get_threat_model():
    """Get threat prediction model instance"""
    global _threat_model
    if _threat_model is None:
        _threat_model = ThreatPredictionModel()
    return _threat_model
