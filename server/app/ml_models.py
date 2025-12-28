import logging
from typing import Dict, Any
import numpy as np

logger = logging.getLogger(__name__)

class AnomalyDetectionModel:
    """Local anomaly detection model"""
    
    def __init__(self):
        self.threshold = 0.8
        
    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Predict anomalies"""
        return {
            "is_anomaly": False,
            "score": 0.5,
            "confidence": 0.7,
            "source": "local_model"
        }

class ThreatPredictionModel:
    """Local threat prediction model"""
    
    def __init__(self):
        self.threshold = 0.7
        
    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Predict threats"""
        return {
            "is_threat": False,
            "probability": 0.3,
            "confidence": 0.6,
            "source": "local_model"
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
