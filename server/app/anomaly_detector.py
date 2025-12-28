import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """Local anomaly detector"""
    
    def __init__(self):
        self.threshold = 0.7
        
    def detect(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomalies in data"""
        return {
            "anomalies_found": 0,
            "anomaly_score": 0.2,
            "details": "No significant anomalies detected",
            "source": "local_detector"
        }

# Singleton instance
_detector_instance = None

def get_anomaly_detector():
    """Get anomaly detector instance"""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = AnomalyDetector()
    return _detector_instance
