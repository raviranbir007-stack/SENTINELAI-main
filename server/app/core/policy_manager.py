"""Policy management helpers for organization-aware Sentinel AI deployments."""

from __future__ import annotations

from typing import Any, Dict


DEFAULT_DETECTOR_PROFILES: Dict[str, Dict[str, Any]] = {
    "network": {
        "critical": 0.93,
        "high": 0.82,
        "medium": 0.60,
        "single_source_auto_high_min": 0.94,
    },
    "file": {
        "critical": 0.96,
        "high": 0.86,
        "medium": 0.64,
        "single_source_auto_high_min": 0.95,
    },
    "browser": {
        "critical": 0.94,
        "high": 0.84,
        "medium": 0.62,
        "single_source_auto_high_min": 0.94,
    },
    "ids": {
        "critical": 0.91,
        "high": 0.80,
        "medium": 0.58,
        "single_source_auto_high_min": 0.92,
    },
    "default": {
        "critical": 0.94,
        "high": 0.84,
        "medium": 0.62,
        "single_source_auto_high_min": 0.94,
    },
}

DEFAULT_DETECTOR_CALIBRATION: Dict[str, Dict[str, Any]] = {
    "network": {"scale": 1.03, "offset": 0.01},
    "file": {"scale": 1.05, "offset": 0.00},
    "browser": {"scale": 1.02, "offset": 0.01},
    "ids": {"scale": 1.04, "offset": 0.00},
    "default": {"scale": 1.00, "offset": 0.00},
}

DEFAULT_POLICY_RULES: Dict[str, Any] = {
    "detector_profiles": DEFAULT_DETECTOR_PROFILES,
    "detector_calibration": DEFAULT_DETECTOR_CALIBRATION,
    "quarantine_rules": {
        "auto_quarantine_on_critical": True,
        "require_multi_source_for_auto_block": True,
        "corroboration_threshold": 2,
    },
    "notification_rules": {
        "email": True,
        "slack": False,
        "teams": False,
        "webhook": False,
        "escalation_minutes": [5, 30, 60],
    },
    "alert_routing": {
        "critical": "security-on-call",
        "high": "soc",
        "medium": "analyst",
        "low": "dashboard",
    },
    "reporting": {
        "include_forensics": True,
        "default_time_ranges": ["24h", "7d", "30d"],
    },
    "retention": {
        "days": 90,
    },
}


def normalize_policy_rules(rules: Dict[str, Any] | None) -> Dict[str, Any]:
    normalized: Dict[str, Any] = dict(DEFAULT_POLICY_RULES)
    if isinstance(rules, dict):
        for key, value in rules.items():
            normalized[key] = value
    return normalized


def policy_detector_snapshot(rules: Dict[str, Any] | None) -> Dict[str, Dict[str, Any]]:
    rules = normalize_policy_rules(rules)
    profiles = rules.get("detector_profiles")
    calibration = rules.get("detector_calibration")
    return {
        "profiles": profiles if isinstance(profiles, dict) else dict(DEFAULT_DETECTOR_PROFILES),
        "calibration": calibration if isinstance(calibration, dict) else dict(DEFAULT_DETECTOR_CALIBRATION),
    }


def policy_runtime_snapshot(rules: Dict[str, Any] | None) -> Dict[str, Any]:
    rules = normalize_policy_rules(rules)
    return {
        "detector": policy_detector_snapshot(rules),
        "quarantine_rules": rules.get("quarantine_rules", {}),
        "notification_rules": rules.get("notification_rules", {}),
        "alert_routing": rules.get("alert_routing", {}),
        "reporting": rules.get("reporting", {}),
        "retention": rules.get("retention", {}),
    }
