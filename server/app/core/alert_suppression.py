"""
Alert Suppression and Deduplication System
Prevents alert fatigue by suppressing duplicate and low-value alerts
"""

import hashlib
import json
import logging
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class AlertSuppressionEngine:
    """Engine for suppressing duplicate and low-value alerts"""

    def __init__(self):
        # Alert deduplication cache
        self._alert_cache: Dict[str, Dict] = {}
        self._cache_ttl_seconds = 3600  # 1 hour

        # Suppression rules
        self._suppression_rules = {
            "duplicate_window_minutes": 15,
            "max_alerts_per_source_per_hour": 10,
            "max_similar_alerts_per_hour": 5,
            "low_value_suppression": {
                "enabled": True,
                "min_confidence_threshold": 0.3,
                "max_frequency_per_hour": 3
            }
        }

        # Alert frequency tracking
        self._source_alert_counts: Dict[str, List[float]] = defaultdict(list)
        self._alert_pattern_counts: Dict[str, List[float]] = defaultdict(list)

        # Cleanup task
        self._last_cleanup = time.time()

    def _generate_alert_signature(self, alert_data: Dict) -> str:
        """Generate a unique signature for alert deduplication"""
        # Create signature from key alert attributes
        signature_components = {
            "input": alert_data.get("input", ""),
            "input_type": alert_data.get("input_type", ""),
            "verdict": alert_data.get("verdict", ""),
            "primary_indicator": "",
            "source_ips": []
        }

        # Extract primary threat indicator
        threat_indicators = alert_data.get("threat_indicators", [])
        if threat_indicators:
            # Use the highest severity indicator as primary
            sorted_indicators = sorted(
                threat_indicators,
                key=lambda x: {"critical": 3, "high": 2, "medium": 1, "low": 0}.get(x.get("severity", "low"), 0),
                reverse=True
            )
            if sorted_indicators:
                signature_components["primary_indicator"] = sorted_indicators[0].get("indicator", "")

        # Extract source IPs for network alerts
        for indicator in threat_indicators:
            if indicator.get("type") in ["ip", "network_connection", "port_scan"]:
                source_ip = indicator.get("source_ip") or indicator.get("indicator", "")
                if source_ip and source_ip not in signature_components["source_ips"]:
                    signature_components["source_ips"].append(source_ip)

        # Sort IPs for consistent hashing
        signature_components["source_ips"].sort()

        # Create deterministic signature
        signature_str = json.dumps(signature_components, sort_keys=True)
        return hashlib.sha256(signature_str.encode()).hexdigest()[:16]

    def _is_duplicate_alert(self, alert_signature: str, current_time: float) -> Tuple[bool, Optional[Dict]]:
        """Check if alert is a duplicate within the suppression window"""
        if alert_signature in self._alert_cache:
            cached_alert = self._alert_cache[alert_signature]
            cached_time = cached_alert.get("timestamp", 0)

            # Check if within duplicate window
            if current_time - cached_time < (self._suppression_rules["duplicate_window_minutes"] * 60):
                return True, cached_alert

        return False, None

    def _check_source_frequency_limit(self, source: str, current_time: float) -> bool:
        """Check if source has exceeded alert frequency limit"""
        # Clean old entries
        cutoff_time = current_time - 3600  # 1 hour
        self._source_alert_counts[source] = [
            t for t in self._source_alert_counts[source] if t > cutoff_time
        ]

        # Check limit
        if len(self._source_alert_counts[source]) >= self._suppression_rules["max_alerts_per_source_per_hour"]:
            return True

        return False

    def _check_pattern_frequency_limit(self, alert_pattern: str, current_time: float) -> bool:
        """Check if similar alert pattern has exceeded frequency limit"""
        # Clean old entries
        cutoff_time = current_time - 3600  # 1 hour
        self._alert_pattern_counts[alert_pattern] = [
            t for t in self._alert_pattern_counts[alert_pattern] if t > cutoff_time
        ]

        # Check limit
        if len(self._alert_pattern_counts[alert_pattern]) >= self._suppression_rules["max_similar_alerts_per_hour"]:
            return True

        return False

    def _is_low_value_alert(self, alert_data: Dict, current_time: float) -> bool:
        """Determine if alert is low-value and should be suppressed"""
        if not self._suppression_rules["low_value_suppression"]["enabled"]:
            return False

        confidence = alert_data.get("confidence", 0.0)
        verdict = alert_data.get("verdict", "")

        # Only suppress low-confidence suspicious alerts
        if verdict != "SUSPICIOUS":
            return False

        if confidence >= self._suppression_rules["low_value_suppression"]["min_confidence_threshold"]:
            return False

        # Check frequency of low-value alerts
        pattern_key = f"low_value_{alert_data.get('input_type', 'unknown')}"
        cutoff_time = current_time - 3600  # 1 hour
        self._alert_pattern_counts[pattern_key] = [
            t for t in self._alert_pattern_counts[pattern_key] if t > cutoff_time
        ]

        if len(self._alert_pattern_counts[pattern_key]) >= self._suppression_rules["low_value_suppression"]["max_frequency_per_hour"]:
            return True

        return False

    def _cleanup_expired_cache(self, current_time: float):
        """Clean up expired alert cache entries"""
        if current_time - self._last_cleanup < 300:  # Clean every 5 minutes
            return

        expired_signatures = []
        ttl_seconds = self._cache_ttl_seconds

        for signature, alert_data in self._alert_cache.items():
            if current_time - alert_data.get("timestamp", 0) > ttl_seconds:
                expired_signatures.append(signature)

        for signature in expired_signatures:
            del self._alert_cache[signature]

        self._last_cleanup = current_time
        if expired_signatures:
            logger.debug(f"Cleaned up {len(expired_signatures)} expired alert cache entries")

    def should_suppress_alert(self, alert_data: Dict) -> Tuple[bool, str]:
        """
        Determine if an alert should be suppressed

        Returns:
            Tuple of (should_suppress, reason)
        """
        current_time = time.time()

        # Periodic cleanup
        self._cleanup_expired_cache(current_time)

        # Generate alert signature
        alert_signature = self._generate_alert_signature(alert_data)

        # Check for duplicates
        is_duplicate, original_alert = self._is_duplicate_alert(alert_signature, current_time)
        if is_duplicate:
            return True, f"Duplicate alert (similar to alert from {datetime.fromtimestamp(original_alert['timestamp']).isoformat()})"

        # Check source frequency limits
        source = alert_data.get("source", "unknown")
        if self._check_source_frequency_limit(source, current_time):
            return True, f"Source {source} exceeded alert frequency limit"

        # Check pattern frequency limits
        alert_pattern = f"{alert_data.get('input_type', 'unknown')}_{alert_data.get('verdict', 'unknown')}"
        if self._check_pattern_frequency_limit(alert_pattern, current_time):
            return True, f"Alert pattern {alert_pattern} exceeded frequency limit"

        # Check for low-value alerts
        if self._is_low_value_alert(alert_data, current_time):
            return True, "Low-value alert suppressed due to frequency"

        # Alert should not be suppressed
        return False, ""

    def record_alert(self, alert_data: Dict):
        """Record an alert for deduplication tracking"""
        current_time = time.time()
        alert_signature = self._generate_alert_signature(alert_data)

        # Store in cache
        self._alert_cache[alert_signature] = {
            "timestamp": current_time,
            "alert_data": alert_data.copy()
        }

        # Update frequency counters
        source = alert_data.get("source", "unknown")
        self._source_alert_counts[source].append(current_time)

        alert_pattern = f"{alert_data.get('input_type', 'unknown')}_{alert_data.get('verdict', 'unknown')}"
        self._alert_pattern_counts[alert_pattern].append(current_time)

        # Clean up old frequency data
        cutoff_time = current_time - 3600  # 1 hour
        self._source_alert_counts[source] = [t for t in self._source_alert_counts[source] if t > cutoff_time]
        self._alert_pattern_counts[alert_pattern] = [t for t in self._alert_pattern_counts[alert_pattern] if t > cutoff_time]

    def get_suppression_stats(self) -> Dict:
        """Get current suppression statistics"""
        current_time = time.time()
        cutoff_time = current_time - 3600  # Last hour

        return {
            "cache_size": len(self._alert_cache),
            "active_sources": len(self._source_alert_counts),
            "active_patterns": len(self._alert_pattern_counts),
            "recent_suppressions": {
                "by_source": {
                    source: len([t for t in times if t > cutoff_time])
                    for source, times in self._source_alert_counts.items()
                },
                "by_pattern": {
                    pattern: len([t for t in times if t > cutoff_time])
                    for pattern, times in self._alert_pattern_counts.items()
                }
            },
            "suppression_rules": self._suppression_rules.copy()
        }

    def update_suppression_rules(self, new_rules: Dict):
        """Update suppression rules dynamically"""
        self._suppression_rules.update(new_rules)
        logger.info(f"Updated alert suppression rules: {new_rules}")


# Global suppression engine instance
alert_suppression_engine = AlertSuppressionEngine()