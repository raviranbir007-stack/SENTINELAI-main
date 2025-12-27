from typing import List


class ThreatPredictor:
    """Threat prediction model"""

    @staticmethod
    async def predict_attack_vector(threat_indicators: List[str]) -> str:
        """Predict likely attack vector"""
        return "network"

    @staticmethod
    async def predict_severity(threat_data: dict) -> float:
        """Predict threat severity (0-1)"""
        return 0.85
