import logging
from typing import Dict, Any, List, Union, overload

# Optional numpy import - models work without it (minimal storage mode)
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.info("NumPy not available - using minimal ML mode")

logger = logging.getLogger(__name__)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return float(default)
        return float(value)
    except Exception:
        return float(default)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return int(default)
        return int(value)
    except Exception:
        return int(default)


def _normalize_text(value: Any, max_len: int = 256) -> str:
    return str(value or "").strip().lower()[:max_len]


def _severity_value(value: Any) -> float:
    severity = _normalize_text(value)
    if severity == "critical":
        return 0.32
    if severity == "high":
        return 0.22
    if severity == "medium":
        return 0.12
    if severity == "low":
        return 0.04
    return 0.0


def _iter_dict_values(mapping: Any):
    if isinstance(mapping, dict):
        return mapping.values()
    return []

class AnomalyDetectionModel:
    """Enhanced local anomaly detection model with advanced pattern recognition"""
    
    def __init__(self):
        self.threshold = 0.8
        logger.info(f"AnomalyDetectionModel initialized (NumPy: {NUMPY_AVAILABLE})")
        
    @overload
    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        ...

    @overload
    def predict(self, features: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        ...

    def predict(self, features: Union[Dict[str, Any], List[Dict[str, Any]]]) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """Predict anomalies using enhanced rule-based approach.

        Supports single-item dict input or a list of dicts for batch prediction.
        """
        if isinstance(features, list):
            return [self._predict_single(f) for f in features]

        return self._predict_single(features)

    def _predict_single(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Internal single-item prediction implementation."""
        # Enhanced anomaly detection
        score = 0.12
        anomaly_factors = []
        signal_breakdown: Dict[str, float] = {}

        indicator_values = features.get('threat_indicators', [])
        indicator_count = len(indicator_values) if isinstance(indicator_values, list) else _safe_int(features.get('threat_indicator_count', 0))
        severity_pressure = 0.0
        if isinstance(indicator_values, list):
            for indicator in indicator_values:
                if isinstance(indicator, dict):
                    severity_pressure += _severity_value(indicator.get('severity'))
        elif indicator_count:
            severity_pressure += min(0.30, indicator_count * 0.05)

        if indicator_count:
            indicator_score = min(0.30, 0.05 + indicator_count * 0.06)
            score += indicator_score
            signal_breakdown['indicator_volume'] = round(indicator_score, 3)
            anomaly_factors.append(f"{indicator_count} threat indicators")

        if severity_pressure > 0:
            severity_score = min(0.24, severity_pressure)
            score += severity_score
            signal_breakdown['indicator_severity'] = round(severity_score, 3)

        verdict = _normalize_text(features.get('verdict', 'unknown'))
        if verdict == 'malicious':
            score += 0.38
            signal_breakdown['verdict'] = 0.38
            anomaly_factors.append("Malicious verdict")
        elif verdict == 'suspicious':
            score += 0.2
            signal_breakdown['verdict'] = 0.2
            anomaly_factors.append("Suspicious verdict")

        confidence = _safe_float(features.get('confidence', 0.0))
        if confidence >= 0.9:
            score += 0.08
            signal_breakdown['confidence'] = 0.08
        elif confidence >= 0.75:
            score += 0.04
            signal_breakdown['confidence'] = 0.04

        corroboration_count = _safe_int(features.get('corroboration_count', 0))
        if corroboration_count >= 4:
            score += 0.16
            signal_breakdown['corroboration'] = 0.16
            anomaly_factors.append(f"Strong corroboration across {corroboration_count} sources")
        elif corroboration_count >= 2:
            score += 0.10
            signal_breakdown['corroboration'] = 0.10
            anomaly_factors.append(f"Corroboration across {corroboration_count} sources")

        recent_events = _safe_int(features.get('recent_related_events_10m', 0))
        if recent_events >= 8:
            score += 0.18
            signal_breakdown['burst_activity'] = 0.18
            anomaly_factors.append(f"High burst activity in last 10m ({recent_events} events)")
        elif recent_events >= 4:
            score += 0.12
            signal_breakdown['burst_activity'] = 0.12
            anomaly_factors.append(f"Elevated burst activity in last 10m ({recent_events} events)")

        behavioral_sequence_length = _safe_int(features.get('behavioral_sequence_length', 0))
        if behavioral_sequence_length >= 6:
            score += 0.08
            signal_breakdown['behavioral_chain'] = 0.08
            anomaly_factors.append(f"Long behavioral sequence ({behavioral_sequence_length} events)")

        if features.get('attack_chain_detected'):
            score += 0.16
            signal_breakdown['attack_chain'] = 0.16
            anomaly_factors.append("Phishing/download/C2 attack chain detected")

        scan_type = _normalize_text(features.get('scan_type', ''))
        if scan_type in ['file', 'hash']:
            file_size = _safe_int(features.get('file_size', 0))
            if file_size > 10 * 1024 * 1024:
                score += 0.1
                signal_breakdown['file_size'] = 0.10
                anomaly_factors.append("Large file size")
            if _safe_float(features.get('file_entropy', 0.0)) >= 7.2:
                score += 0.08
                signal_breakdown['file_entropy'] = 0.08
                anomaly_factors.append("High file entropy")
        elif scan_type in ['url', 'domain', 'ip']:
            text_blob = " ".join(
                _normalize_text(features.get(field, ""))
                for field in ['input', 'target', 'source_ip', 'source_domain', 'destination_ip', 'attack_type', 'description']
            )
            suspicious_markers = ["cmd.exe", "powershell", "../", "..\\", "union select", "<script", "eval(", "exec(", "wget ", "curl "]
            marker_hits = sum(1 for marker in suspicious_markers if marker in text_blob)
            if marker_hits:
                marker_score = min(0.20, 0.05 + marker_hits * 0.04)
                score += marker_score
                signal_breakdown['text_markers'] = round(marker_score, 3)
                anomaly_factors.append(f"Suspicious payload markers ({marker_hits})")

        api_results = features.get('api_results', {})
        if api_results:
            malicious_hits = 0
            suspicious_hits = 0
            for result in _iter_dict_values(api_results):
                if not isinstance(result, dict):
                    continue
                if result.get('malicious', False) is True:
                    malicious_hits += 1
                if result.get('suspicious', False) is True:
                    suspicious_hits += 1
                score = max(score, _safe_float(result.get('confidence', 0.0)) * 0.95)
            if malicious_hits > 0:
                api_score = min(0.30, malicious_hits * 0.12)
                score += api_score
                signal_breakdown['api_malicious'] = round(api_score, 3)
                anomaly_factors.append(f"{malicious_hits} APIs flagged as malicious")
            if suspicious_hits > 0:
                api_score = min(0.16, suspicious_hits * 0.06)
                score += api_score
                signal_breakdown['api_suspicious'] = round(api_score, 3)

        baseline_adjustment = features.get('baseline_adjustment', {})
        if isinstance(baseline_adjustment, dict):
            z_score = _safe_float(baseline_adjustment.get('z_score', 0.0))
            if z_score >= 3.0:
                score += 0.14
                signal_breakdown['baseline_spike'] = 0.14
                anomaly_factors.append(f"Behavioral spike detected (z={z_score:.2f})")
            elif z_score >= 1.8:
                score += 0.08
                signal_breakdown['baseline_spike'] = 0.08
                anomaly_factors.append(f"Behavioral deviation detected (z={z_score:.2f})")

        score = min(score, 1.0)
        if score >= 0.85:
            risk_level = "critical"
        elif score >= 0.7:
            risk_level = "high"
        elif score >= 0.5:
            risk_level = "medium"
        else:
            risk_level = "low"

        # CRITICAL FIX: Ensure confidence calculation is valid and bounded
        base_conf = 0.62
        try:
            base_conf = float(base_conf or 0.62)
        except (TypeError, ValueError):
            base_conf = 0.62

        factors_boost = 0.0
        try:
            factors_boost = min(0.30, float(0.05 * len(anomaly_factors) if anomaly_factors else 0))
        except (TypeError, ValueError):
            factors_boost = 0.0

        score_boost = 0.0
        try:
            score_boost = float(0.08 if float(score or 0.0) >= 0.85 else 0.0)
        except (TypeError, ValueError):
            score_boost = 0.0

        # Calculate and strictly bound confidence to [0, 1]
        confidence = base_conf + factors_boost + score_boost
        confidence = max(0.0, min(0.98, float(confidence or 0.0)))

        return {
            "is_anomaly": score > self.threshold,
            "score": round(score, 3),
            "confidence": confidence,
            "factors": anomaly_factors,
            "risk_level": risk_level,
            "signal_breakdown": signal_breakdown,
            "source": "enhanced_local_model"
        }

class ThreatPredictionModel:
    """Enhanced local threat prediction model with advanced heuristics"""
    
    def __init__(self):
        self.threshold = 0.7
        logger.info(f"ThreatPredictionModel initialized (NumPy: {NUMPY_AVAILABLE})")
        
    @overload
    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        ...

    @overload
    def predict(self, features: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        ...

    def predict(self, features: Union[Dict[str, Any], List[Dict[str, Any]]]) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """Predict threats using enhanced rule-based approach.

        Supports single-item dict input or a list of dicts for batch prediction.
        """
        if isinstance(features, list):
            return [self._predict_single(f) for f in features]

        return self._predict_single(features)

    def _predict_single(self, features: Dict[str, Any]) -> Dict[str, Any]:
        # Enhanced threat prediction
        probability = 0.08
        threat_level = "safe"
        factors = []
        signal_breakdown: Dict[str, float] = {}

        threat_indicators = features.get('threat_indicators', [])
        indicator_count = len(threat_indicators) if isinstance(threat_indicators, list) else _safe_int(features.get('threat_indicator_count', 0))
        critical_count = 0
        high_count = 0
        medium_count = 0
        
        # Analyze threat indicators with weighted scoring
        if isinstance(threat_indicators, list):
            for indicator in threat_indicators:
                if not isinstance(indicator, dict):
                    continue
                severity = _normalize_text(indicator.get('severity'))
                if severity == 'critical':
                    critical_count += 1
                elif severity == 'high':
                    high_count += 1
                elif severity == 'medium':
                    medium_count += 1

        if indicator_count:
            indicator_boost = min(0.24, indicator_count * 0.04)
            probability += indicator_boost
            signal_breakdown['indicator_volume'] = round(indicator_boost, 3)
            factors.append(f"{indicator_count} threat indicators")

        if critical_count > 0:
            critical_boost = min(0.34, critical_count * 0.22)
            probability += critical_boost
            signal_breakdown['critical_indicators'] = round(critical_boost, 3)
            factors.append(f"{critical_count} critical indicators")
        if high_count > 0:
            high_boost = min(0.22, high_count * 0.14)
            probability += high_boost
            signal_breakdown['high_indicators'] = round(high_boost, 3)
            factors.append(f"{high_count} high indicators")
        if medium_count > 0:
            medium_boost = min(0.12, medium_count * 0.06)
            probability += medium_boost
            signal_breakdown['medium_indicators'] = round(medium_boost, 3)
            
        # Analyze verdict
        verdict = _normalize_text(features.get('verdict', 'unknown'))
        if verdict == 'malicious':
            probability = max(probability, 0.92)
            threat_level = "critical"
            factors.append("Malicious verdict")
        elif verdict == 'suspicious':
            probability = max(probability, 0.6)
            threat_level = "suspicious"
            factors.append("Suspicious verdict")
        elif verdict == 'safe':
            probability = min(probability, 0.3)
            
        # Analyze malicious score from APIs
        malicious_score = _safe_float(features.get('malicious_score', 0))
        if malicious_score > 0:
            api_boost = min(0.32, malicious_score * 0.42)
            probability += api_boost
            signal_breakdown['malicious_score'] = round(api_boost, 3)
            factors.append(f"Malicious score: {malicious_score}")

        confidence = _safe_float(features.get('confidence', 0.0))
        if confidence >= 0.9:
            probability += 0.06
            signal_breakdown['confidence'] = 0.06
        elif confidence >= 0.75:
            probability += 0.03
            signal_breakdown['confidence'] = 0.03

        corroboration_count = _safe_int(features.get('corroboration_count', 0))
        if corroboration_count >= 4:
            probability += 0.18
            signal_breakdown['corroboration'] = 0.18
            factors.append(f"Strong corroboration across {corroboration_count} sources")
        elif corroboration_count >= 2:
            probability += 0.11
            signal_breakdown['corroboration'] = 0.11
            factors.append(f"Corroboration across {corroboration_count} sources")

        recent_events = _safe_int(features.get('recent_related_events_10m', 0))
        if recent_events >= 8:
            probability += 0.15
            signal_breakdown['burst_activity'] = 0.15
            factors.append(f"High burst activity in last 10m ({recent_events} events)")
        elif recent_events >= 4:
            probability += 0.09
            signal_breakdown['burst_activity'] = 0.09
            factors.append(f"Elevated burst activity in last 10m ({recent_events} events)")

        if features.get('corroboration_threshold_met'):
            probability += 0.06
            signal_breakdown['corroboration_threshold_met'] = 0.06

        if features.get('attack_chain_detected'):
            probability += 0.14
            signal_breakdown['attack_chain'] = 0.14
            factors.append("Attack chain correlation detected")
        
        # Analyze detection ratio
        detection_ratio = features.get('detection_ratio', '0/0')
        if '/' in str(detection_ratio):
            try:
                detected, total = map(int, detection_ratio.split('/'))
                if total > 0:
                    ratio = detected / total
                    if ratio > 0.3:
                        ratio_boost = min(0.22, ratio * 0.32)
                        probability += ratio_boost
                        signal_breakdown['detection_ratio'] = round(ratio_boost, 3)
                        factors.append(f"Detection ratio: {detected}/{total}")
            except:
                pass

        behavioral_sequence_length = _safe_int(features.get('behavioral_sequence_length', 0))
        if behavioral_sequence_length >= 6:
            probability += 0.07
            signal_breakdown['behavioral_chain'] = 0.07

        baseline_adjustment = features.get('baseline_adjustment', {})
        if isinstance(baseline_adjustment, dict):
            z_score = _safe_float(baseline_adjustment.get('z_score', 0.0))
            if z_score >= 3.0:
                probability += 0.12
                signal_breakdown['baseline_spike'] = 0.12
            elif z_score >= 1.8:
                probability += 0.07
                signal_breakdown['baseline_spike'] = 0.07

        if isinstance(features.get('api_results'), dict):
            api_consensus = 0
            for result in _iter_dict_values(features['api_results']):
                if isinstance(result, dict) and (result.get('malicious') is True or _safe_float(result.get('confidence', 0.0)) >= 0.85):
                    api_consensus += 1
            if api_consensus >= 3:
                probability += 0.14
                signal_breakdown['api_consensus'] = 0.14
            elif api_consensus >= 1:
                probability += 0.06
                signal_breakdown['api_consensus'] = 0.06
        
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
        
        # CRITICAL FIX: Ensure all components are valid floats with strict bounds
        base_conf = 0.58
        try:
            base_conf = float(base_conf or 0.58)
        except (TypeError, ValueError):
            base_conf = 0.58
        
        factors_boost = 0.0
        try:
            factors_boost = min(0.30, float(0.04 * len(factors) if factors else 0))
        except (TypeError, ValueError):
            factors_boost = 0.0
        
        prob_boost = 0.0
        try:
            prob_boost = float(0.08 if float(probability or 0.0) >= 0.92 else 0.0)
        except (TypeError, ValueError):
            prob_boost = 0.0
        
        # Calculate and strictly bound confidence to [0, 1]
        confidence = base_conf + factors_boost + prob_boost
        confidence = max(0.0, min(0.98, float(confidence or 0.0)))
            
        return {
            "is_threat": probability > self.threshold,
            "probability": round(probability, 3),
            "threat_level": threat_level,
            "confidence": confidence,
            "factors": factors,
            "signal_breakdown": signal_breakdown,
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
