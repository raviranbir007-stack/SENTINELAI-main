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
    """Local anomaly detection model (minimal mode - no heavy ML dependencies)"""
    
    def __init__(self):
        self.threshold = 0.8
        logger.info(f"AnomalyDetectionModel initialized (NumPy: {NUMPY_AVAILABLE})")
        
    def predict(self, features) -> Dict[str, Any]:
        """Predict anomalies using rule-based approach
        
        Args:
            features: Either Dict[str, Any] or List[Dict[str, Any]]
        """
        # Handle list input (batch prediction)
        if isinstance(features, list):
            return [self.predict(f) for f in features]
            
        # Rule-based anomaly detection without numpy
        score = 0.5
        
        # Simple heuristics
        if features.get('threat_indicators', []):
            score = 0.8
        if features.get('verdict') == 'malicious':
            score = 0.9
            
        return {
            "is_anomaly": score > self.threshold,
            "score": score,
            "confidence": 0.7,
            "source": "local_model_minimal"
        }

class ThreatPredictionModel:
    """Local threat prediction model (minimal mode)"""
    
    def __init__(self):
        self.threshold = 0.7
        logger.info(f"ThreatPredictionModel initialized (NumPy: {NUMPY_AVAILABLE})")
        logger.info(f"ThreatPredictionModel initialized (NumPy: {NUMPY_AVAILABLE})")
        
    def predict(self, features) -> Dict[str, Any]:
        """Predict threats using rule-based approach
        
        Args:
            features: Either Dict[str, Any] or List[Dict[str, Any]]
        """
        # Handle list input (batch prediction)
        if isinstance(features, list):
            return [self.predict(f) for f in features]
            
        # Rule-based threat prediction
        probability = 0.3
        
        # Analyze threat indicators
        threat_count = len(features.get('threat_indicators', []))
        if threat_count > 0:
            probability = min(0.3 + (threat_count * 0.2), 0.9)
            
        verdict = features.get('verdict', 'unknown')
        if verdict == 'malicious':
            probability = 0.9
        elif verdict == 'suspicious':
            probability = 0.6
            
        return {
            "is_threat": probability > self.threshold,
            "probability": probability,
            "confidence": 0.6,
            "source": "local_model_minimal"
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
