"""
Unified Threat Analysis Orchestrator with AI-Enhanced Detection
Coordinates all threat detection APIs, ML models, and AI analysis
Enhanced with Multi-API Corroboration Engine
"""

import asyncio
import hashlib
import json
import logging
import os
import socket
import time
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List

from ..services.abuseipdb import AbuseIPDBService
from ..services.hybrid_analysis import HybridAnalysisService
from ..services.shodan import ShodanService
from ..services.urlscan import URLScanService
from ..services.virus_total import VirusTotalService
from ..config import settings
from .input_detector import InputDetector, InputType
from .corroboration_engine import corroboration_engine
from .security_telemetry import security_telemetry
from .alert_suppression import alert_suppression_engine

# Import ML models
try:
    from ..ml_models import get_anomaly_model, get_threat_model
    ML_MODELS_AVAILABLE = True
except ImportError:
    ML_MODELS_AVAILABLE = False
    logging.warning("ML models not available")

# Import AI analyzer
try:
    from ..ai_engine.analyzer import ThreatAnalyzer as AIAnalyzer
    AI_ANALYZER_AVAILABLE = True
except ImportError:
    AI_ANALYZER_AVAILABLE = False
    logging.warning("AI analyzer not available")

logger = logging.getLogger(__name__)


ALL_EXTERNAL_APIS = [
    {
        "key": "virustotal",
        "name": "VirusTotal",
        "config_attr": "VIRUSTOTAL_API_KEY",
        "supported_inputs": {"url", "domain", "file_hash", "hash"},
    },
    {
        "key": "abuseipdb",
        "name": "AbuseIPDB",
        "config_attr": "ABUSEIPDB_API_KEY",
        "supported_inputs": {"ip", "url", "domain"},
    },
    {
        "key": "shodan",
        "name": "Shodan",
        "config_attr": "SHODAN_API_KEY",
        "supported_inputs": {"ip", "url", "domain"},
    },
    {
        "key": "urlscan",
        "name": "URLScan.io",
        "config_attr": "URLSCAN_API_KEY",
        "supported_inputs": {"url", "domain"},
    },
    {
        "key": "hybrid_analysis",
        "name": "Hybrid Analysis",
        "config_attr": "HYBRIDANALYSIS_API_KEY",
        "supported_inputs": {"file_hash", "hash"},
    },
]


class ThreatLevel(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class ThreatAnalyzer:
    """
    Unified threat analyzer that:
    - Detects input type automatically
    - Calls appropriate APIs
    - Analyzes responses
    - Returns threat verdict
    """

    def __init__(self):
        self.detector = InputDetector()
        self.shodan = ShodanService()
        self.virustotal = VirusTotalService()
        self.abuseipdb = AbuseIPDBService()
        self.urlscan = URLScanService()
        self.hybrid_analysis = HybridAnalysisService()
        
        # Initialize ML models if available, else raise error (ML required)
        if ML_MODELS_AVAILABLE:
            try:
                self.anomaly_model = get_anomaly_model()
                self.threat_model = get_threat_model()
                logger.info("ML models initialized successfully and are required for all scans.")
            except Exception as e:
                logger.error(f"Failed to initialize ML models: {e}")
                raise RuntimeError("ML models are required but could not be initialized.")
        else:
            logger.error("ML models are required but not available. Aborting startup.")
            raise RuntimeError("ML models are required but not available.")
        
        # Initialize AI analyzer if available
        if AI_ANALYZER_AVAILABLE:
            try:
                self.ai_analyzer = AIAnalyzer()
                logger.debug("AI analyzer initialized successfully")
            except Exception as e:
                logger.warning(f"Failed to initialize AI analyzer: {e}")
                self.ai_analyzer = None
        else:
            self.ai_analyzer = None

        # API governance settings (performance + resilience)
        self._api_max_concurrent_calls = max(2, int(os.getenv("SENTINEL_API_MAX_CONCURRENT_CALLS", "12") or 12))
        self._api_queue_wait_timeout = float(os.getenv("SENTINEL_API_QUEUE_WAIT_TIMEOUT", "2.0") or 2.0)
        self._api_failure_threshold = max(2, int(os.getenv("SENTINEL_API_FAILURE_THRESHOLD", "4") or 4))
        self._api_circuit_cooldown = float(os.getenv("SENTINEL_API_CIRCUIT_COOLDOWN_SECONDS", "90") or 90)
        self._api_call_budget_daily = max(100, int(os.getenv("SENTINEL_API_BUDGET_DAILY", "5000") or 5000))
        self._api_semaphore = asyncio.Semaphore(self._api_max_concurrent_calls)

        # Source confidence weighting for verdict fusion
        self._source_confidence_weights = {
            "virustotal": 1.15,
            "abuseipdb": 1.0,
            "shodan": 0.95,
            "urlscan": 1.05,
            "hybrid analysis": 1.20,
            "hybrid_analysis": 1.20,
            "heuristic analysis": 0.85,
            "local analysis": 0.90,
        }

        # Detector-specific calibration and severity profiles.
        self._detector_threshold_profiles = {
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
        self._detector_calibration = {
            "network": {"scale": 1.03, "offset": 0.01},
            "file": {"scale": 1.05, "offset": 0.00},
            "browser": {"scale": 1.02, "offset": 0.01},
            "ids": {"scale": 1.04, "offset": 0.00},
            "default": {"scale": 1.00, "offset": 0.00},
        }
        # Optional runtime overrides for fine-tuning without code changes.
        try:
            overrides = os.getenv("SENTINEL_DETECTOR_THRESHOLD_PROFILES_JSON", "")
            if overrides:
                self._detector_threshold_profiles.update(json.loads(overrides))
        except Exception:
            logger.warning("Invalid SENTINEL_DETECTOR_THRESHOLD_PROFILES_JSON; using defaults")
        try:
            cal_overrides = os.getenv("SENTINEL_DETECTOR_CALIBRATION_JSON", "")
            if cal_overrides:
                self._detector_calibration.update(json.loads(cal_overrides))
        except Exception:
            logger.warning("Invalid SENTINEL_DETECTOR_CALIBRATION_JSON; using defaults")

        self._detector_profiles_path = Path.home() / ".sentinelai_detector_profiles.json"
        self._detector_calibration_path = Path.home() / ".sentinelai_detector_calibration.json"
        self._load_persisted_detector_configs()

    def _load_persisted_detector_configs(self) -> None:
        """Load persisted detector tuning generated by adaptive weekly jobs."""
        try:
            if self._detector_profiles_path.exists():
                loaded_profiles = json.loads(self._detector_profiles_path.read_text(encoding="utf-8"))
                if isinstance(loaded_profiles, dict):
                    self._detector_threshold_profiles.update(loaded_profiles)
        except Exception as exc:
            logger.warning("Failed to load persisted detector profiles: %s", exc)

        try:
            if self._detector_calibration_path.exists():
                loaded_calibration = json.loads(self._detector_calibration_path.read_text(encoding="utf-8"))
                if isinstance(loaded_calibration, dict):
                    self._detector_calibration.update(loaded_calibration)
        except Exception as exc:
            logger.warning("Failed to load persisted detector calibration: %s", exc)

    def get_detector_config(self) -> Dict[str, Dict[str, Any]]:
        return {
            "profiles": dict(self._detector_threshold_profiles),
            "calibration": dict(self._detector_calibration),
        }

    def apply_detector_config(
        self,
        profiles: Dict[str, Dict[str, Any]] | None = None,
        calibration: Dict[str, Dict[str, Any]] | None = None,
        persist: bool = True,
    ) -> Dict[str, Any]:
        if isinstance(profiles, dict):
            self._detector_threshold_profiles.update(profiles)
        if isinstance(calibration, dict):
            self._detector_calibration.update(calibration)

        if persist:
            try:
                self._detector_profiles_path.write_text(
                    json.dumps(self._detector_threshold_profiles, indent=2),
                    encoding="utf-8",
                )
            except Exception as exc:
                logger.warning("Failed to persist detector profiles: %s", exc)
            try:
                self._detector_calibration_path.write_text(
                    json.dumps(self._detector_calibration, indent=2),
                    encoding="utf-8",
                )
            except Exception as exc:
                logger.warning("Failed to persist detector calibration: %s", exc)

        return self.get_detector_config()

    async def _call_api_with_retry(self, name: str, call_factory, retries: int = 1, delay: float = 0.35):
        """Execute API coroutine with lightweight retry on transient failures."""
        transient_markers = (
            "timeout", "timed out", "temporar", "connection", "reset", "unavailable", "503", "502", "gateway"
        )
        non_retry_markers = ("rate limit", "quota", "not configured", "forbidden", "401", "403")

        last_error = None
        api_name_normalized = str(name or "unknown").strip().lower()

        # Circuit breaker: fail fast if provider is in cooldown window.
        circuit = security_telemetry.get_circuit_state(api_name_normalized)
        now_epoch = time.time()
        if float(circuit.get("opened_until_epoch", 0.0) or 0.0) > now_epoch:
            return {"error": f"{name} circuit open (cooldown in effect)"}

        if security_telemetry.api_usage_count(api_name_normalized, window_hours=24) >= self._api_call_budget_daily:
            return {"error": f"{name} budget cap reached ({self._api_call_budget_daily}/24h)"}

        for attempt in range(retries + 1):
            try:
                # Queue backpressure guard + concurrency limit
                queued_at = time.perf_counter()
                try:
                    await asyncio.wait_for(self._api_semaphore.acquire(), timeout=self._api_queue_wait_timeout)
                except asyncio.TimeoutError:
                    security_telemetry.record_api_metric(
                        api_name=api_name_normalized,
                        input_type="unknown",
                        status="queue_backpressure",
                        latency_ms=(time.perf_counter() - queued_at) * 1000.0,
                        is_timeout=True,
                    )
                    return {"error": f"{name} queue backpressure"}

                started = time.perf_counter()
                try:
                    result = await call_factory()
                finally:
                    self._api_semaphore.release()

                latency_ms = (time.perf_counter() - started) * 1000.0
                if not isinstance(result, dict) or not result.get("error"):
                    security_telemetry.record_api_metric(
                        api_name=api_name_normalized,
                        input_type="unknown",
                        status="checked",
                        latency_ms=latency_ms,
                    )
                    # successful call closes breaker quickly
                    security_telemetry.update_circuit_state(api_name_normalized, reset=True, opened_until_epoch=0.0)
                    return result

                err_text = str(result.get("error", "")).lower()
                is_timeout = any(tok in err_text for tok in ("timeout", "timed out"))
                security_telemetry.record_api_metric(
                    api_name=api_name_normalized,
                    input_type="unknown",
                    status="error",
                    latency_ms=latency_ms,
                    is_timeout=is_timeout,
                )
                if any(marker in err_text for marker in non_retry_markers):
                    security_telemetry.update_circuit_state(api_name_normalized, fail_delta=1, timeout_delta=(1 if is_timeout else 0))
                    return result
                if any(marker in err_text for marker in transient_markers) and attempt < retries:
                    await asyncio.sleep(delay * (attempt + 1))
                    continue

                # Open breaker after repeated failures
                updated = security_telemetry.get_circuit_state(api_name_normalized)
                fail_count = int(updated.get("fail_count", 0)) + 1
                timeout_count = int(updated.get("timeout_count", 0)) + (1 if is_timeout else 0)
                open_until = (time.time() + self._api_circuit_cooldown) if fail_count >= self._api_failure_threshold else float(updated.get("opened_until_epoch", 0.0) or 0.0)
                security_telemetry.update_circuit_state(
                    api_name_normalized,
                    fail_delta=1,
                    timeout_delta=(1 if is_timeout else 0),
                    opened_until_epoch=open_until,
                )
                return result
            except Exception as exc:
                last_error = exc
                err_text = str(exc).lower()
                is_timeout = any(tok in err_text for tok in ("timeout", "timed out"))
                security_telemetry.record_api_metric(
                    api_name=api_name_normalized,
                    input_type="unknown",
                    status="exception",
                    latency_ms=0.0,
                    is_timeout=is_timeout,
                )
                security_telemetry.update_circuit_state(
                    api_name_normalized,
                    fail_delta=1,
                    timeout_delta=(1 if is_timeout else 0),
                )
                if any(marker in err_text for marker in transient_markers) and attempt < retries:
                    await asyncio.sleep(delay * (attempt + 1))
                    continue
                break

        if last_error:
            return {"error": f"{name} transient failure: {last_error}"}
        return {"error": f"{name} transient failure"}

    def _build_mitre_attack_mapping(self, threats: List[Dict[str, Any]], input_type: str = "") -> List[Dict[str, Any]]:
        """Map observed behaviors to likely MITRE ATT&CK techniques (heuristic, non-attributional)."""
        mapping: List[Dict[str, Any]] = []
        seen = set()

        observed = []
        for t in threats:
            observed.append(str(t.get("indicator", "")))
            observed.append(str(t.get("details", "")))
            observed.append(str(t.get("source", "")))
        observed_text = " ".join(observed).lower()

        rules = [
            ("T1566", "Phishing", "Initial Access", ["phish", "credential", "login", "spoof", "bank", "mfa"]),
            ("T1557", "Adversary-in-the-Middle", "Credential Access", ["aitm", "adversary-in-the-middle", "session", "cookie", "mfa", "token"]),
            ("T1598", "Phishing for Information", "Reconnaissance", ["credential harvesting", "account verification", "password"]),
            ("T1046", "Network Service Discovery", "Discovery", ["port", "scan", "recon", "open services", "shodan"]),
            ("T1583.001", "Acquire Infrastructure: Domains", "Resource Development", ["newly registered", "domain age", "typosquat", "homograph", "idn"]),
            ("T1584.001", "Compromise Infrastructure: Domains", "Resource Development", ["malicious domain", "domain reputation"]),
            ("T1204.001", "User Execution: Malicious Link", "Execution", ["malicious url", "suspicious link", "redirect"]),
            ("T1204.002", "User Execution: Malicious File", "Execution", ["malicious file", "file hash", "dropper", "payload"]),
            ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control", ["http", "https", "c2", "beacon"]),
        ]

        for tech_id, name, tactic, keywords in rules:
            if any(k in observed_text for k in keywords):
                key = f"{tech_id}:{name}"
                if key in seen:
                    continue
                seen.add(key)
                mapping.append({
                    "technique_id": tech_id,
                    "technique": name,
                    "tactic": tactic,
                    "confidence": "medium",
                    "basis": "indicator keyword matching"
                })

        if input_type in {"ip", "domain", "url"} and not any(m["technique_id"] == "T1046" for m in mapping):
            mapping.append({
                "technique_id": "T1046",
                "technique": "Network Service Discovery",
                "tactic": "Discovery",
                "confidence": "low",
                "basis": "network-oriented scan context"
            })

        return mapping[:8]

    def _build_soar_guidance(self, verdict: str, corroboration_count: int) -> List[Dict[str, Any]]:
        """Generate practical SOAR playbook guidance for each scan."""
        verdict_l = str(verdict or "unknown").lower()

        if verdict_l in {"malicious", "critical"}:
            return [
                {"priority": "P1", "playbook": "Containment", "action": "Isolate affected host and block IOC in firewall/DNS/EDR."},
                {"priority": "P1", "playbook": "Credential Protection", "action": "Force credential reset and invalidate active sessions/tokens."},
                {"priority": "P2", "playbook": "Forensic Preservation", "action": "Capture timeline, logs, and volatile artifacts for chain-of-custody."},
            ]

        if verdict_l == "suspicious":
            return [
                {"priority": "P2", "playbook": "Validation", "action": "Trigger re-scan with expanded sources and sandbox detonation."},
                {"priority": "P2", "playbook": "Monitoring", "action": "Enable heightened telemetry and alert correlation for 24h."},
                {"priority": "P3", "playbook": "Analyst Review", "action": "Queue manual triage before irreversible blocking actions."},
            ]

        return [
            {"priority": "P3", "playbook": "Baseline", "action": "No containment required; maintain continuous monitoring."},
            {"priority": "P3", "playbook": "Quality Assurance", "action": f"Record evidence coverage ({corroboration_count} corroborating source(s))."},
        ]

    def _build_campaign_hypotheses(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Produce non-attributional campaign hypotheses such as AiTM/APT36-style patterns."""
        text = " ".join(
            f"{t.get('indicator', '')} {t.get('details', '')} {t.get('source', '')}" for t in threats
        ).lower()

        hypotheses: List[Dict[str, Any]] = []

        aitm_keys = ["aitm", "adversary-in-the-middle", "session", "token", "mfa", "cookie", "oauth"]
        if any(k in text for k in aitm_keys):
            hypotheses.append({
                "pattern": "AiTM-style credential/session interception",
                "confidence": "medium",
                "note": "Pattern match only; not actor attribution."
            })

        apt36_like_keys = ["phish", "credential", "webmail", "spoof", "homograph", "government", "defense"]
        if any(k in text for k in apt36_like_keys):
            hypotheses.append({
                "pattern": "APT36-style credential-phishing tradecraft",
                "confidence": "low",
                "note": "Tradecraft resemblance only; attribution requires external intelligence."
            })

        return hypotheses[:3]

    def _build_threat_intel_fusion(self, result: Dict[str, Any], threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize multi-provider intelligence into one common explainable schema."""
        api_results = result.get("api_results", {}) or {}
        api_status = api_results.get("api_status", {}) or {}

        provider_alias = {
            "virustotal": "virustotal",
            "abuseipdb": "abuseipdb",
            "shodan": "shodan",
            "urlscan": "urlscan",
            "urlscan.io": "urlscan",
            "hybrid analysis": "hybrid_analysis",
            "hybrid_analysis": "hybrid_analysis",
        }

        provider_hits = {k: 0 for k in ["virustotal", "abuseipdb", "shodan", "urlscan", "hybrid_analysis", "heuristic"]}
        malicious_count = 0
        suspicious_count = 0
        evidence = []
        for t in threats:
            if not isinstance(t, dict):
                continue
            source = str(t.get("source", "heuristic")).strip().lower()
            normalized = provider_alias.get(source, "heuristic")
            provider_hits[normalized] = provider_hits.get(normalized, 0) + 1
            sev = str(t.get("severity", "low")).lower()
            if sev in {"critical", "high"}:
                malicious_count += 1
            elif sev == "medium":
                suspicious_count += 1
            evidence.append(
                {
                    "source": t.get("source"),
                    "severity": sev,
                    "indicator": t.get("indicator"),
                }
            )

        vt_malicious = 0
        vt_suspicious = 0
        try:
            vt = api_results.get("virustotal") or {}
            attrs = (vt.get("data") or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
            vt_malicious = int(stats.get("malicious", 0) or 0)
            vt_suspicious = int(stats.get("suspicious", 0) or 0)
        except Exception:
            pass

        abuse_confidence = 0
        try:
            abuse_confidence = int(((api_results.get("abuseipdb") or {}).get("data") or {}).get("abuseConfidenceScore", 0) or 0)
        except Exception:
            abuse_confidence = 0

        exposure_level = "low"
        try:
            ports = (api_results.get("shodan") or {}).get("ports") or []
            if len(ports) >= 15:
                exposure_level = "high"
            elif len(ports) >= 6:
                exposure_level = "medium"
        except Exception:
            exposure_level = "low"

        sandbox_risk = 0
        try:
            ha_results = (api_results.get("hybrid_analysis") or {}).get("results") or []
            if isinstance(ha_results, list) and ha_results:
                sandbox_risk = max(int((item or {}).get("threat_score", 0) or 0) for item in ha_results if isinstance(item, dict))
        except Exception:
            sandbox_risk = 0

        redirect_suspicion = 0
        try:
            urlscan_data = ((api_results.get("urlscan") or {}).get("data") or {})
            if isinstance(urlscan_data, dict):
                if ((urlscan_data.get("classifications") or {}).get("phishing") or False):
                    redirect_suspicion = 90
                elif urlscan_data.get("page") or urlscan_data.get("task"):
                    redirect_suspicion = 35
        except Exception:
            redirect_suspicion = 0

        detection_source_count = sum(1 for v in provider_hits.values() if int(v) > 0)
        providers_checked = [
            str(meta.get("name", key))
            for key, meta in api_status.items()
            if isinstance(meta, dict) and meta.get("status") in {"checked", "clean", "no_threat"}
        ]

        confidence = float(result.get("confidence", 0.0) or 0.0)
        verdict = str(result.get("verdict", "unknown")).lower()
        if verdict in {"malicious", "critical"} and detection_source_count >= 2:
            action = "block_or_quarantine"
        elif verdict == "suspicious" and confidence >= 0.65 and detection_source_count >= 2:
            action = "contain_and_manual_review"
        elif verdict == "suspicious":
            action = "monitor_and_manual_review"
        else:
            action = "monitor"

        severity = "low"
        if verdict in {"critical", "malicious"}:
            severity = "critical" if confidence >= 0.9 else "high"
        elif verdict == "suspicious":
            severity = "medium"

        return {
            "reputation_score": round(max(0.0, min(100.0, confidence * 100.0)), 2),
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "abuse_confidence": abuse_confidence,
            "exposure_level": exposure_level,
            "sandbox_risk": sandbox_risk,
            "redirect_suspicion": redirect_suspicion,
            "detection_source_count": detection_source_count,
            "providers_checked": providers_checked,
            "provider_hits": provider_hits,
            "vt_summary": {"malicious": vt_malicious, "suspicious": vt_suspicious},
            "overall_severity": severity,
            "overall_confidence": round(confidence, 3),
            "recommended_action": action,
            "explanation_summary": result.get("summary", ""),
            "evidence_summary": evidence[:12],
            "last_seen_context": result.get("timestamp"),
        }

    def _build_advanced_forensic_analysis(
        self,
        result: Dict[str, Any],
        threats: List[Dict[str, Any]],
        corroboration_analysis: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """Construct enriched forensic analysis block for every scan."""
        api_results = result.get("api_results", {}) or {}
        forensic = result.get("forensic_metadata", {}) or {}
        apis_called = api_results.get("apis_called", []) or []
        apis_expected = api_results.get("apis_expected", []) or []
        apis_attempted = api_results.get("apis_attempted", []) or []
        api_status = api_results.get("api_status", {}) or {}

        heuristic_count = sum(1 for t in threats if str(t.get("source", "")).lower() == "heuristic analysis")
        signature_count = sum(
            1
            for t in threats
            if any(s in str(t.get("source", "")).lower() for s in ["virustotal", "hybrid"])
        )
        intel_count = sum(
            1
            for t in threats
            if any(s in str(t.get("source", "")).lower() for s in ["abuseipdb", "shodan", "urlscan"])
        )

        verdict = str(result.get("verdict", "unknown"))
        corroboration_count = int(forensic.get("corroboration_count", 0) or 0)
        mitre_map = self._build_mitre_attack_mapping(threats, str(result.get("input_type", "")))
        campaign_hypotheses = self._build_campaign_hypotheses(threats)

        return {
            "analysis_version": "3.0",
            "generated_at": datetime.utcnow().isoformat(),
            "orchestration": {
                "engine": "SENTINEL-AI Multi-Source Orchestrator",
                "apis_expected": len(apis_expected),
                "apis_attempted": len(apis_attempted),
                "apis_called": len(apis_called),
                "coverage_percent": round((len(apis_called) / max(len(apis_expected), 1)) * 100, 1) if apis_expected else 0.0,
                "api_status": api_status,
            },
            "detection_methods": {
                "heuristic_indicators": heuristic_count,
                "signature_based_indicators": signature_count,
                "threat_intel_indicators": intel_count,
                "multi_source_corroboration": corroboration_count,
            },
            "signature_based_detection": {
                "enabled": True,
                "sources": [s for s in ["VirusTotal", "Hybrid Analysis"] if s in (forensic.get("unique_sources") or apis_called)],
                "notes": "Signature detections are weighted with corroboration and confidence controls.",
            },
            "mitre_attack_mapping": mitre_map,
            "campaign_hypotheses": campaign_hypotheses,
            "soar_recommendations": self._build_soar_guidance(verdict, corroboration_count),
            "corroboration_summary": {
                "count": corroboration_count,
                "threshold_met": bool(forensic.get("corroboration_threshold_met", False)),
                "unique_sources": forensic.get("unique_sources", []),
                "reliability": (
                    "high" if forensic.get("corroboration_threshold_met", False)
                    else "baseline-clean" if len(threats) == 0
                    else "limited"
                ),
            },
            "corroboration_engine": corroboration_analysis or {},
        }

    def _normalize_input(self, value: str) -> str:
        """Normalize common obfuscations (hxxp, [.] ) for URL/domain inputs."""
        try:
            import re

            normalized = value.strip()

            # Replace hxxp/hxxps scheme obfuscation
            normalized = re.sub(r"^hxxps?://", lambda m: "https://" if "hxxps" in m.group(0) else "http://", normalized, flags=re.IGNORECASE)
            normalized = re.sub(r"^hxxps?:", lambda m: "https:" if "hxxps" in m.group(0) else "http:", normalized, flags=re.IGNORECASE)

            # Replace dot obfuscations
            normalized = normalized.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")

            # Replace hxxp in middle if present
            normalized = normalized.replace("hxxp://", "http://").replace("hxxps://", "https://")

            return normalized
        except Exception:
            return value

    def _get_expected_apis(self, input_type: str) -> List[Dict[str, str]]:
        """Return relevant external APIs for the given input type."""
        normalized = (input_type or "").lower()
        mapping = {
            "ip": [
                {"key": "abuseipdb", "name": "AbuseIPDB"},
                {"key": "shodan", "name": "Shodan"},
            ],
            "url": [
                {"key": "virustotal", "name": "VirusTotal"},
                {"key": "urlscan", "name": "URLScan.io"},
                {"key": "abuseipdb", "name": "AbuseIPDB"},
                {"key": "shodan", "name": "Shodan"},
            ],
            "domain": [
                {"key": "virustotal", "name": "VirusTotal"},
                {"key": "urlscan", "name": "URLScan.io"},
                {"key": "abuseipdb", "name": "AbuseIPDB"},
                {"key": "shodan", "name": "Shodan"},
            ],
            "file": [
                {"key": "virustotal", "name": "VirusTotal"},
                {"key": "hybrid_analysis", "name": "Hybrid Analysis"},
            ],
            "file_hash": [
                {"key": "virustotal", "name": "VirusTotal"},
                {"key": "hybrid_analysis", "name": "Hybrid Analysis"},
            ],
            "hash": [
                {"key": "virustotal", "name": "VirusTotal"},
                {"key": "hybrid_analysis", "name": "Hybrid Analysis"},
            ],
        }
        apis = mapping.get(normalized, [])
        # API health scoring + fallback order: healthiest provider first.
        ranked = sorted(
            apis,
            key=lambda x: security_telemetry.get_api_health_score(str(x.get("name", "")).lower()),
            reverse=True,
        )
        return ranked

    def _mark_expected_apis_not_applicable(self, result: Dict, reason: str) -> None:
        """Mark all expected API calls as not_applicable for non-actionable test inputs."""
        api_results = result.setdefault("api_results", {})
        api_status = api_results.setdefault("api_status", {})
        for _api_key, meta in api_status.items():
            if not isinstance(meta, dict):
                continue
            if meta.get("status") in {"pending", "unknown"}:
                meta["status"] = "not_applicable"
                meta["error"] = reason

    def _resolve_public_ip(self, value: str, input_type: str) -> str | None:
        """Resolve URL/domain to a public IPv4 address for IP-intel enrichment."""
        try:
            from urllib.parse import urlparse
            import ipaddress

            normalized = (input_type or "").lower()
            host = ""
            if normalized == "url":
                host = (urlparse(str(value)).hostname or "").strip().lower().rstrip('.')
            elif normalized == "domain":
                host = str(value).split(":", 1)[0].strip().lower().rstrip('.')
            elif normalized == "ip":
                host = str(value).strip()
            else:
                return None

            if not host:
                return None

            try:
                ip_obj = ipaddress.ip_address(host)
                return None if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local) else str(ip_obj)
            except Exception:
                pass

            reserved_tlds = (".test", ".example", ".invalid", ".localhost")
            if host.endswith(reserved_tlds):
                return None

            resolved = socket.gethostbyname(host)
            ip_obj = ipaddress.ip_address(resolved)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return None
            return str(ip_obj)
        except Exception:
            return None

    def _prepare_api_tracking(self, result: Dict, input_type: str) -> None:
        """Initialize API tracking metadata for a scan. Force all APIs to be tracked as expected and attempted. Always show all five APIs."""
        api_results = result.setdefault("api_results", {})
        api_status = api_results.setdefault("api_status", {})

        # All APIs are always expected and attempted
        api_results["apis_expected"] = [api["name"] for api in ALL_EXTERNAL_APIS]
        api_results["apis_attempted"] = [api["name"] for api in ALL_EXTERNAL_APIS]
        api_results["apis_called"] = []

        normalized_input = (input_type or "").lower()

        for api in ALL_EXTERNAL_APIS:
            configured = bool(getattr(settings, api["config_attr"], ""))
            applicable = normalized_input in api["supported_inputs"]
            # If not configured, status is not_configured; if not applicable, status is not_applicable; else pending
            if not configured:
                initial_status = "not_configured"
            elif not applicable:
                initial_status = "not_applicable"
            else:
                initial_status = "pending"

            api_status[api["key"]] = {
                "name": api["name"],
                "status": initial_status,
                "configured": configured,
                "applicable": applicable,
                "supported_inputs": sorted(api["supported_inputs"]),
                "error": None,
            }

    def _mark_external_apis_skipped(self, result: Dict, reason: str = "External APIs disabled for local-only analysis") -> None:
        """Mark expected external APIs as intentionally skipped.

        This keeps scan metadata explicit without burning provider quota.
        """
        api_results = result.setdefault("api_results", {})
        api_status = api_results.setdefault("api_status", {})
        warnings = result.setdefault("warnings", [])

        for api_key, meta in api_status.items():
            if not isinstance(meta, dict):
                continue
            if meta.get("applicable") and meta.get("status") in {"pending", "not_applicable", "unknown"}:
                meta["status"] = "skipped_local_mode"
                meta["error"] = reason

        api_results["apis_attempted"] = []
        api_results["apis_called"] = []

        if reason not in warnings:
            warnings.append(reason)

    def _track_api_result(
        self,
        result: Dict,
        api_key: str,
        display_name: str,
        response: Any,
        warnings: List[str] | None = None,
    ) -> None:
        """Track whether an external API was attempted, checked successfully, or unavailable."""
        api_results = result.setdefault("api_results", {})
        api_status = api_results.setdefault("api_status", {})

        attempted = api_results.setdefault("apis_attempted", [])
        called = api_results.setdefault("apis_called", [])

        if display_name not in attempted:
            attempted.append(display_name)

        # Ensure only dicts are stored; non-dict responses (e.g. raw JSON arrays
        # from Hybrid Analysis) are treated as errors so .get() never fails later.
        if not isinstance(response, dict):
            response = {"error": f"Unexpected response type: {type(response).__name__}"}

        api_results[api_key] = response

        error_message = ""
        if response.get("error"):
            error_message = str(response.get("error", ""))

        previous_status = api_status.get(api_key, {}) if isinstance(api_status.get(api_key, {}), dict) else {}

        # Patch: If API is not configured or not applicable, do not mark as error
        if error_message:
            error_lower = error_message.lower()
            if "not configured" in error_lower or "api key missing" in error_lower:
                status = "not_configured"
            elif "not applicable" in error_lower or "not supported" in error_lower:
                status = "not_applicable"
            elif "authorization failed" in error_lower or "unauthorized" in error_lower or "forbidden" in error_lower:
                status = "not_authorized"
            elif "rate limit" in error_lower:
                status = "rate_limited"
            elif "not yet complete" in error_lower or "scan not found" in error_lower:
                status = "pending"
            else:
                status = "error"
        else:
            status = "checked"
            if display_name not in called:
                called.append(display_name)

        api_status[api_key] = {
            "name": display_name,
            "status": status,
            "configured": previous_status.get("configured", status != "not_configured") and status != "not_configured",
            "applicable": previous_status.get("applicable"),
            "supported_inputs": previous_status.get("supported_inputs"),
            "error": error_message or None,
        }

        # Patch: Add more specific warning messages for not_configured and not_applicable
        if warnings is not None and status in {"not_configured", "rate_limited", "error", "not_applicable"}:
            warning_map = {
                "not_configured": f"{display_name} API key not configured",
                "rate_limited": f"{display_name} rate limit reached",
                "error": f"{display_name} request failed",
                "not_applicable": f"{display_name} not applicable for this input type",
            }
            warning_text = warning_map.get(status, f"{display_name} request failed: {error_message}")
            if warning_text not in warnings:
                warnings.append(warning_text)
        # Defensive: If API returned a dict with an 'error' key but error_message is empty, treat as error
        if isinstance(response, dict) and "error" in response and response["error"] and not error_message:
            status = "error"
            error_message = str(response["error"])

    async def analyze(self, value: str, use_external_apis: bool | None = None) -> Dict[str, Any]:
        """
        Main analysis method that orchestrates all threat detection.

        Args:
            value: Input to analyze (IP, URL, domain, file hash, etc.)
            use_external_apis: Override external intelligence API usage.
                None -> use settings.EXTERNAL_APIS_ENABLED

        Returns:
            Dict with threat analysis results
        """
        # Normalize common obfuscated indicators before detection
        normalized_value = self._normalize_input(value)

        local_token = str(normalized_value or "").strip().lower().rstrip('.')
        if local_token in {'localhost', 'localhost.localdomain', '127.0.0.1', '0.0.0.0', '::1'} or local_token.startswith('127.'):
            return {
                "input": value,
                "input_type": InputType.DOMAIN.value,
                "metadata": {"local_target": True},
                "timestamp": datetime.utcnow().isoformat(),
                "api_results": {},
                "threat_indicators": [],
                "verdict": ThreatLevel.CLEAN,
                "confidence": 0.9,
                "summary": "Local/private target recognized as trusted local infrastructure.",
                "use_external_apis": False,
                "forensic_metadata": {
                    "local_target": True,
                    "corroboration_count": 0,
                    "corroboration_threshold_met": False,
                    "evidence_sources": [],
                    "apis_checked": 0,
                    "scan_coverage": "0/0 relevant APIs",
                },
            }

        # Detect input type
        input_type, metadata = self.detector.detect(normalized_value)

        effective_external_api_mode = settings.EXTERNAL_APIS_ENABLED if use_external_apis is None else bool(use_external_apis)

        analysis_result = {
            "input": value,
            "input_type": input_type.value,
            "metadata": metadata,
            "timestamp": datetime.utcnow().isoformat(),
            "api_results": {},
            "threat_indicators": [],
            "verdict": ThreatLevel.CLEAN,
            "confidence": 0.0,
            "summary": "",
            "use_external_apis": effective_external_api_mode,
        }

        # Local/private infrastructure should not enter malicious blocking path.
        if self._is_local_or_private_target(input_type, normalized_value):
            analysis_result["verdict"] = ThreatLevel.CLEAN
            analysis_result["confidence"] = 0.9
            analysis_result["summary"] = "Local/private target recognized as trusted local infrastructure."
            analysis_result["forensic_metadata"] = {
                "local_target": True,
                "corroboration_count": 0,
                "corroboration_threshold_met": False,
                "evidence_sources": [],
                "apis_checked": 0,
                "scan_coverage": "0/0 relevant APIs",
            }
            return analysis_result

        try:
            # Route to appropriate analysis based on input type
            if input_type == InputType.IP:
                analysis_result = await self._analyze_ip(normalized_value, analysis_result)

            elif input_type == InputType.URL:
                analysis_result = await self._analyze_url(normalized_value, analysis_result)

            elif input_type == InputType.DOMAIN:
                analysis_result = await self._analyze_domain(normalized_value, analysis_result)

            elif input_type == InputType.FILE_HASH:
                hash_type = metadata.get("hash_type")
                analysis_result = await self._analyze_file_hash(
                    normalized_value, hash_type, analysis_result
                )

            elif input_type == InputType.FILE:
                analysis_result = await self._analyze_file(
                    normalized_value, metadata, analysis_result
                )

            else:
                analysis_result["verdict"] = ThreatLevel.SUSPICIOUS
                analysis_result["summary"] = (
                    "Input type could not be determined. Please provide a valid IP, URL, domain, file name, or file hash."
                )

            # Always apply AI/ML analysis after all API results are collected
            if analysis_result.get("verdict"):
                logger.debug("Applying AI/ML analysis to results and correlating with API results")
                analysis_result = await self._apply_ai_analysis(analysis_result)

            # Explicitly correlate ML/AI and API contributions in the result
            api_results = analysis_result.get("api_results", {})
            ai_analysis = analysis_result.get("ai_analysis", {})
            analysis_result["correlation"] = {
                "apis_called": api_results.get("apis_called", []),
                "apis_status": api_results.get("api_status", {}),
                "ml_ai": {
                    "anomaly_detection": ai_analysis.get("anomaly_detection", {}),
                    "threat_prediction": ai_analysis.get("threat_prediction", {}),
                    "advanced_ai": ai_analysis.get("advanced_ai", {}),
                },
                "final_verdict": analysis_result.get("verdict"),
                "confidence": analysis_result.get("confidence"),
            }

        except Exception as e:
            logger.error(f"Error analyzing {value}: {str(e)}")
            analysis_result["verdict"] = ThreatLevel.SUSPICIOUS
            analysis_result["summary"] = f"Error during analysis: {str(e)}"

        return analysis_result

    def _is_local_or_private_target(self, input_type: InputType, value: str) -> bool:
        """Return True if target resolves to localhost/private scope."""
        try:
            import ipaddress
            from urllib.parse import urlparse

            if input_type == InputType.IP:
                ip_obj = ipaddress.ip_address(str(value).strip())
                return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local

            if input_type == InputType.URL:
                host = (urlparse(str(value)).hostname or '').strip().lower().rstrip('.')
            elif input_type == InputType.DOMAIN:
                host = str(value).split(':', 1)[0].strip().lower().rstrip('.')
            else:
                return False

            if not host:
                return False
            if host in {'localhost', 'localhost.localdomain', '127.0.0.1', '0.0.0.0', '::1'} or host.startswith('127.'):
                return True

            try:
                ip_obj = ipaddress.ip_address(host)
                return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
            except Exception:
                return False
        except Exception:
            return False

    def _analyze_ip_heuristics(self, ip: str) -> List[Dict]:
        """
        Comprehensive IP address heuristic analysis for malicious patterns
        """
        threats = []
        
        try:
            import ipaddress
            
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if IPv6 - only do basic checks for IPv6
            is_ipv6 = isinstance(ip_obj, ipaddress.IPv6Address)
            
            # For IPv4, parse octets for detailed analysis
            octets = None
            if not is_ipv6 and '.' in ip:
                octets = [int(x) for x in ip.split('.')]
            
            # ============================================
            # 1. RESERVED & SPECIAL IP RANGES
            # ============================================
            if ip_obj.is_private:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "low",
                    "indicator": f"Private IP address ({ip}) - not routable on internet",
                    "type": "private_ip",
                    "confidence": 0.2
                })
            elif ip_obj.is_loopback:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "low",
                    "indicator": "Loopback address (localhost)",
                    "type": "loopback",
                    "confidence": 0.1
                })
            elif ip_obj.is_multicast:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": "Multicast address (unusual for web traffic)",
                    "type": "multicast",
                    "confidence": 0.4
                })
            elif ip_obj.is_reserved:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": "Reserved IP address",
                    "type": "reserved_ip",
                    "confidence": 0.5
                })
            
            # ============================================
            # 2. KNOWN MALICIOUS IP RANGES
            # ============================================
            # Check against commonly abused ranges (IPv4 only)
            if not is_ipv6:
                suspicious_ranges = [
                    ('185.0.0.0/8', 'Frequently used for malware hosting'),
                    ('45.0.0.0/8', 'Common in C2 infrastructure'),
                    ('103.0.0.0/8', 'Frequently abused for phishing'),
                    ('91.0.0.0/8', 'Eastern Europe - high abuse rate'),
                    ('92.0.0.0/8', 'Eastern Europe - high abuse rate'),
                    ('93.0.0.0/8', 'Eastern Europe - high abuse rate'),
                    ('194.0.0.0/8', 'Bullet-proof hosting region'),
                ]
                
                for range_str, description in suspicious_ranges:
                    if ip_obj in ipaddress.ip_network(range_str):
                        threats.append({
                            "source": "Heuristic Analysis",
                            "severity": "medium",
                            "indicator": f"IP in frequently abused range: {description}",
                            "type": "suspicious_range",
                            "confidence": 0.6
                        })
                        break
            
            # ============================================
            # 3. UNUSUAL IP PATTERNS (IPv4 only)
            # ============================================
            if octets:
                # Sequential pattern detection (common in scanning/botnet)
                if octets[1] == octets[2] == octets[3]:
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "low",
                        "indicator": f"Sequential IP pattern (x.{octets[1]}.{octets[2]}.{octets[3]})",
                        "type": "pattern_ip",
                        "confidence": 0.3
                    })
                
                # Network/broadcast addresses
                if octets[3] in [0, 1, 255]:
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "low",
                        "indicator": f"IP ends in {octets[3]} (network scanning pattern)",
                        "type": "scanning_pattern",
                        "confidence": 0.3
                    })
                    
        except Exception as e:
            logger.warning(f"IP heuristic analysis failed: {str(e)}")
        
        return threats

    async def _analyze_ip(self, ip: str, result: Dict) -> Dict:
        """Analyze IP address using all available APIs and heuristic analysis. All APIs are attempted and logged."""
        logger.debug(f"Analyzing IP: {ip}")

        threats = list(result.get("threat_indicators", []))
        warnings = result.setdefault("warnings", [])
        self._prepare_api_tracking(result, result.get("input_type", "ip"))

        # Run heuristic analysis first
        heuristic_threats = self._analyze_ip_heuristics(ip)
        if heuristic_threats:
            threats.extend(heuristic_threats)
            logger.debug(f"IP heuristic analysis found {len(heuristic_threats)} indicator(s)")

        if not result.get("use_external_apis", settings.EXTERNAL_APIS_ENABLED):
            self._mark_external_apis_skipped(result)
            result["threat_indicators"] = threats
            return self._calculate_verdict(result)

        # Attempt all APIs, not just relevant ones
        for api in ALL_EXTERNAL_APIS:
            api_key = api["key"]
            api_name = api["name"]
            try:
                if api_key == "abuseipdb":
                    abuseipdb_result = await self.abuseipdb.check_ip(ip)
                    self._track_api_result(result, api_key, api_name, abuseipdb_result, warnings)
                    if abuseipdb_result and abuseipdb_result.get("data"):
                        data = abuseipdb_result.get("data", {})
                        abuse_score = data.get("abuseConfidenceScore", 0)
                        if abuse_score > 75:
                            threats.append({"source": api_name, "severity": "critical", "indicator": f"High abuse confidence score: {abuse_score}%", "score": abuse_score})
                        elif abuse_score > 25:
                            threats.append({"source": api_name, "severity": "medium", "indicator": f"Moderate abuse confidence score: {abuse_score}%", "score": abuse_score})
                elif api_key == "shodan":
                    shodan_result = await self.shodan.search_ip(ip)
                    self._track_api_result(result, api_key, api_name, shodan_result, warnings)
                    if shodan_result and not shodan_result.get("error"):
                        ports = shodan_result.get("ports", [])
                        vulns = shodan_result.get("vulns", [])
                        if vulns:
                            critical_vulns = [v for v in vulns if "critical" in v.lower()]
                            if critical_vulns:
                                threats.append({"source": api_name, "severity": "critical", "indicator": f"Critical vulnerabilities found: {len(critical_vulns)}", "details": critical_vulns[:5]})
                            else:
                                threats.append({"source": api_name, "severity": "medium", "indicator": f"Vulnerabilities found: {len(vulns)}", "details": vulns[:5]})
                        if len(ports) > 10:
                            threats.append({"source": api_name, "severity": "low", "indicator": f"Many open ports detected: {len(ports)}"})
                elif api_key == "virustotal":
                    # Not applicable for IP, but log as not_applicable
                    self._track_api_result(result, api_key, api_name, {"error": "Not applicable for IP"}, warnings)
                elif api_key == "urlscan":
                    self._track_api_result(result, api_key, api_name, {"error": "Not applicable for IP"}, warnings)
                elif api_key == "hybrid_analysis":
                    self._track_api_result(result, api_key, api_name, {"error": "Not applicable for IP"}, warnings)
            except Exception as e:
                logger.warning(f"{api_name} check failed for {ip}: {str(e)}")
                self._track_api_result(result, api_key, api_name, {"error": str(e)}, warnings)

        result["threat_indicators"] = threats
        result = self._calculate_verdict(result)
        return result

    def _analyze_url_heuristics(self, url: str) -> List[Dict]:
        """
        Comprehensive URL analysis for suspicious patterns using advanced heuristics
        This catches threats that might not be in external API databases yet
        """
        threats = []
        
        try:
            from urllib.parse import urlparse, unquote
            import re
            
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
            full_url = url.lower()
            
            # Decode URL-encoded strings to catch obfuscation
            decoded_url = unquote(full_url)
            decoded_path = unquote(path)
            decoded_query = unquote(query)
            
            # ============================================
            # 1. IP-BASED URL DETECTION (HIGH RISK)
            # ============================================
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            if re.match(ip_pattern, domain.split(':')[0]):
                port = parsed.port
                # Suspicious ports commonly used by malware
                high_risk_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 4321, 12345, 54321]
                medium_risk_ports = [8080, 8443, 3389, 5900, 1433, 3306, 5432, 27017]
                
                if port in high_risk_ports:
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "critical",
                        "indicator": f"Direct IP with high-risk port {port} (common in malware C2 and backdoors)",
                        "type": "suspicious_port",
                        "confidence": 0.9
                    })
                elif port in medium_risk_ports:
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "medium",
                        "indicator": f"Direct IP with exposed service port {port}",
                        "type": "exposed_port",
                        "confidence": 0.6
                    })
                else:
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "medium",
                        "indicator": "Direct IP address instead of domain (suspicious for web content)",
                        "type": "ip_address",
                        "confidence": 0.5
                    })
            
            # ============================================
            # 2. MALICIOUS FILE EXTENSIONS
            # ============================================
            dangerous_extensions = [
                '.exe', '.dll', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', 
                '.ps1', '.scr', '.com', '.pif', '.reg', '.msi', '.jar', '.app',
                '.deb', '.rpm', '.dmg', '.pkg', '.sh', '.bash', '.zsh', '.run'
            ]
            
            for ext in dangerous_extensions:
                if path.endswith(ext) or decoded_path.endswith(ext):
                    # Check for highly suspicious paths
                    critical_paths = [
                        '/cmd/', '/shell/', '/payload/', '/backdoor/', '/exploit/', 
                        '/hack/', '/malware/', '/virus/', '/trojan/', '/c2/', '/c&c/',
                        '/reverse/', '/meterpreter/', '/beacon/', '/implant/', '/rat/',
                        '/keylog/', '/stealer/', '/ransomware/', '/crypter/', '/loader/'
                    ]
                    
                    suspicious_paths = [
                        '/download/', '/get/', '/file/', '/upload/', '/tmp/', '/temp/',
                        '/pub/', '/public/', '/share/', '/data/', '/bin/', '/exe/'
                    ]
                    
                    if any(crit in path for crit in critical_paths):
                        threats.append({
                            "source": "Heuristic Analysis",
                            "severity": "critical",
                            "indicator": f"Executable file ({ext}) in malware-related path: {path[:50]}",
                            "type": "malicious_file",
                            "confidence": 0.95
                        })
                    elif any(susp in path for susp in suspicious_paths):
                        threats.append({
                            "source": "Heuristic Analysis",
                            "severity": "critical",
                            "indicator": f"Executable file ({ext}) in suspicious download path",
                            "type": "suspicious_executable",
                            "confidence": 0.75
                        })
                    else:
                        threats.append({
                            "source": "Heuristic Analysis",
                            "severity": "medium",
                            "indicator": f"Executable file detected: {ext}",
                            "type": "executable",
                            "confidence": 0.5
                        })
            
            # ============================================
            # 3. PHISHING & CREDENTIAL THEFT DETECTION
            # ============================================
            phishing_keywords = [
                'steal', 'phish', 'fake', 'scam', 'fraud', 'spoof',
                'verify-account', 'verify_account', 'account-verify', 'account_verify',
                'login-secure', 'secure-login', 'securelogin', 
                'update-password', 'update_password', 'reset-password',
                'confirm-identity', 'confirm_identity', 'validate-account',
                'suspended-account', 'locked-account', 'security-alert',
                'unusual-activity', 'suspicious-activity',
                'billing-problem', 'payment-failed', 'expire',
                'urgent', 'immediate', 'action-required'
            ]
            
            brand_impersonation = [
                'paypal', 'amazon', 'ebay', 'facebook', 'instagram', 'twitter',
                'microsoft', 'apple', 'google', 'netflix', 'spotify', 'linkedin',
                'bank', 'banking', 'wells-fargo', 'chase', 'citibank', 'usbank',
                'outlook', 'office365', 'o365', 'dropbox', 'icloud', 'gmail'
            ]
            
            for keyword in phishing_keywords:
                if keyword in domain or keyword in decoded_path or keyword in decoded_query:
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "critical",
                        "indicator": f"Phishing pattern detected: '{keyword}' in URL",
                        "type": "phishing",
                        "confidence": 0.85
                    })
                    break
            
            # Check for brand impersonation
            for brand in brand_impersonation:
                if brand in domain:
                    # Check if it's NOT the legitimate domain
                    legitimate_domains = {
                        'paypal': ['paypal.com', 'paypal.co'],
                        'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de'],
                        'microsoft': ['microsoft.com', 'live.com', 'outlook.com'],
                        'google': ['google.com', 'gmail.com', 'youtube.com'],
                        'apple': ['apple.com', 'icloud.com'],
                        'facebook': ['facebook.com', 'fb.com'],
                        'netflix': ['netflix.com'],
                    }
                    
                    is_legitimate = False
                    if brand in legitimate_domains:
                        for legit_domain in legitimate_domains[brand]:
                            if domain.endswith(legit_domain):
                                is_legitimate = True
                                break
                    
                    if not is_legitimate:
                        threats.append({
                            "source": "Heuristic Analysis",
                            "severity": "critical",
                            "indicator": f"Possible brand impersonation: '{brand}' in suspicious domain",
                            "type": "brand_impersonation",
                            "confidence": 0.8
                        })
            
            # ============================================
            # 4. CREDENTIAL HARVESTING DETECTION
            # ============================================
            credential_params = [
                'user=', 'pass=', 'password=', 'passwd=', 'pwd=',
                'username=', 'login=', 'email=', 'credential=',
                'uname=', 'pword=', 'auth=', 'token=', 'session='
            ]
            
            credential_paths = [
                '/steal', '/phish', '/capture', '/harvest', '/grab',
                '/get', '/collect', '/logger', '/log', '/auth'
            ]
            
            has_cred_params = any(param in query for param in credential_params)
            has_cred_path = any(cpath in path for cpath in credential_paths)
            
            if has_cred_params and has_cred_path:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "critical",
                    "indicator": "Credential parameters with malicious path (credential theft)",
                    "type": "credential_theft",
                    "confidence": 0.9
                })
            elif has_cred_params and any(keyword in domain for keyword in phishing_keywords):
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "critical",
                    "indicator": "Credential parameters in suspicious domain",
                    "type": "credential_theft",
                    "confidence": 0.8
                })
            
            # ============================================
            # 5. SUSPICIOUS TLD DETECTION
            # ============================================
            high_risk_tlds = ['.xyz', '.top', '.cc', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.click']
            medium_risk_tlds = ['.info', '.biz', '.su', '.ru', '.cn', '.ws', '.vg', '.buzz']
            
            domain_has_high_risk_tld = any(domain.endswith(tld) for tld in high_risk_tlds)
            domain_has_medium_risk_tld = any(domain.endswith(tld) for tld in medium_risk_tlds)
            
            if domain_has_high_risk_tld:
                # Check if combined with other suspicious indicators
                if any(keyword in domain for keyword in phishing_keywords + brand_impersonation):
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "critical",
                        "indicator": f"High-risk TLD combined with suspicious keywords",
                        "type": "suspicious_tld",
                        "confidence": 0.85
                    })
                else:
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "medium",
                        "indicator": f"Domain uses high-risk TLD (frequently used in malware/phishing)",
                        "type": "suspicious_tld",
                        "confidence": 0.5
                    })
            elif domain_has_medium_risk_tld and any(keyword in domain for keyword in brand_impersonation):
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": f"Medium-risk TLD with brand keywords",
                    "type": "suspicious_tld",
                    "confidence": 0.6
                })

            # ============================================
            # 5.5 PUNYCODE / HOMOGRAPH RISK
            # ============================================
            host_for_shape = (domain or "").split(":", 1)[0].strip().lower().rstrip('.')
            if "xn--" in host_for_shape:
                severity = "critical" if any(brand in host_for_shape for brand in brand_impersonation) else "high"
                confidence = 0.88 if severity == "critical" else 0.72
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": severity,
                    "indicator": "Punycode hostname detected (possible homograph impersonation)",
                    "type": "punycode_homograph",
                    "confidence": confidence
                })

            # Excessive symbols/hyphens in host are common in disposable phishing infrastructure.
            hyphen_count = host_for_shape.count('-')
            digit_count = sum(1 for c in host_for_shape if c.isdigit())
            if hyphen_count >= 4 or digit_count >= 6:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": "Host format resembles generated/disposable phishing infrastructure",
                    "type": "suspicious_host_format",
                    "confidence": 0.58
                })
            
            # ============================================
            # 6. TYPOSQUATTING & HOMOGRAPH DETECTION
            # ============================================
            # Detect look-alikes, but avoid flagging legitimate brand domains.
            host_no_port = (domain or "").split(":", 1)[0].strip().lower().rstrip('.')
            legitimate_brand_domains = {
                "paypal": ["paypal.com", "paypal.co.uk"],
                "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com"],
                "google": ["google.com", "gmail.com", "youtube.com", "gstatic.com"],
                "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr"],
                "facebook": ["facebook.com", "fb.com", "fbcdn.net"],
                "apple": ["apple.com", "icloud.com", "me.com"],
            }

            # Use only actual look-alike forms (avoid exact brand literal regexes).
            typosquat_patterns = [
                (r'paypa1|paypa\-secure', 'paypal'),
                (r'micr0soft|micros0ft', 'microsoft'),
                (r'g00gle|go0gle', 'google'),
                (r'amaz0n|amason', 'amazon'),
                (r'facebo0k|f4cebook|faceb00k', 'facebook'),
                (r'app1e|appl3', 'apple'),
            ]

            for pattern, original in typosquat_patterns:
                is_legit = any(host_no_port.endswith(ld) for ld in legitimate_brand_domains.get(original, []))
                if is_legit:
                    continue
                if re.search(pattern, host_no_port):
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "critical",
                        "indicator": f"Typosquatting detected: impersonating '{original}'",
                        "type": "typosquatting",
                        "confidence": 0.9
                    })
            
            # ============================================
            # 7. DOUBLE EXTENSION DETECTION
            # ============================================
            double_ext_patterns = [
                r'\.pdf\.exe$', r'\.doc\.exe$', r'\.jpg\.exe$',
                r'\.png\.exe$', r'\.txt\.exe$', r'\.zip\.exe$',
                r'\.[a-z]{3,4}\.(exe|dll|bat|cmd|scr)$'
            ]
            
            for pattern in double_ext_patterns:
                if re.search(pattern, path):
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "critical",
                        "indicator": "Double file extension detected (common malware obfuscation)",
                        "type": "double_extension",
                        "confidence": 0.95
                    })
                    break
            
            # ============================================
            # 8. SUSPICIOUS ENCODING & OBFUSCATION
            # ============================================
            # Check for excessive URL encoding (obfuscation)
            encoding_count = full_url.count('%')
            if encoding_count > 5:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": f"Excessive URL encoding detected ({encoding_count} encoded chars - possible obfuscation)",
                    "type": "obfuscation",
                    "confidence": 0.6
                })
            
            # Check for suspicious encoded strings
            suspicious_encoded = ['%2e%2e', '..%2f', '%00', 'javascript:', 'data:', 'vbscript:']
            for encoded in suspicious_encoded:
                if encoded in full_url:
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "critical",
                        "indicator": f"Malicious encoded pattern detected: {encoded}",
                        "type": "malicious_encoding",
                        "confidence": 0.85
                    })
            
            # ============================================
            # 9. DATA EXFILTRATION PATTERNS
            # ============================================
            if len(query) > 200:
                exfil_indicators = ['data=', 'info=', 'content=', 'output=', 'result=', 'dump=']
                if any(indicator in query for indicator in exfil_indicators):
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "medium",
                        "indicator": "Unusually long query string with data parameters (possible exfiltration)",
                        "type": "data_exfiltration",
                        "confidence": 0.65
                    })
            
            # ============================================
            # 10. SUSPICIOUS SUBDOMAINS
            # ============================================
            subdomain_count = domain.count('.')
            if subdomain_count > 3:  # e.g., a.b.c.example.com
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "low",
                    "indicator": f"Excessive subdomains ({subdomain_count} levels - possible DGA or evasion)",
                    "type": "suspicious_subdomain",
                    "confidence": 0.4
                })
            
            # ============================================
            # 11. SHORTENED URL DETECTION
            # ============================================
            url_shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
            if any(shortener in domain for shortener in url_shorteners):
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "low",
                    "indicator": "URL shortener detected (could hide malicious destination)",
                    "type": "url_shortener",
                    "confidence": 0.3
                })
            
            # ============================================
            # 12. SUSPICIOUS PATH PATTERNS
            # ============================================
            malicious_path_keywords = [
                'admin', 'administrator', 'root', 'system', 'config',
                'backup', 'database', 'db', 'sql', 'dump', 'export',
                'shell', 'webshell', 'c99', 'r57', 'b374k'
            ]
            
            for keyword in malicious_path_keywords:
                if f'/{keyword}' in path or f'{keyword}.php' in path:
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "medium",
                        "indicator": f"Suspicious path keyword: '{keyword}' (potential unauthorized access)",
                        "type": "suspicious_path",
                        "confidence": 0.55
                    })
                    break

            # ============================================
            # 13. OAUTH / TOKEN THEFT FLOWS
            # ============================================
            oauth_abuse_markers = [
                'response_type=token', 'access_token=', 'id_token=',
                'redirect_uri=', 'client_id=', 'code_challenge=', 'oauth', 'openid'
            ]
            oauth_hits = sum(1 for marker in oauth_abuse_markers if marker in decoded_query)
            if oauth_hits >= 3 and any(k in decoded_path for k in ('login', 'auth', 'callback', 'verify')):
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "high",
                    "indicator": "OAuth/token workflow with suspicious URL structure (possible token theft flow)",
                    "type": "oauth_token_abuse",
                    "confidence": 0.72
                })

            # ============================================
            # 14. CLIENT-SIDE CREDENTIAL CAPTURE HINTS
            # ============================================
            js_capture_markers = ['document.cookie', 'localstorage', 'sessionstorage', 'navigator.clipboard']
            capture_hits = sum(1 for marker in js_capture_markers if marker in decoded_url)
            if capture_hits >= 2 and any(k in decoded_query for k in ('password', 'token', 'session', 'auth')):
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "high",
                    "indicator": "Client-side storage/cookie access combined with auth parameter leakage",
                    "type": "credential_capture_flow",
                    "confidence": 0.74
                })
                    
        except Exception as e:
            logger.warning(f"Heuristic analysis failed: {str(e)}")
        
        return threats

    async def _analyze_url(self, url: str, result: Dict) -> Dict:
        """Analyze URL using all available APIs and heuristic analysis. All APIs are attempted and logged."""
        logger.debug(f"Analyzing URL: {url}")

        threats = list(result.get("threat_indicators", []))
        warnings = result.setdefault("warnings", [])
        self._prepare_api_tracking(result, result.get("input_type", "url"))

        # Handle chrome-extension wrappers by using embedded URL if present
        if url.lower().startswith("chrome-extension://"):
            embedded = InputDetector.extract_embedded_url(url)
            if embedded:
                logger.debug(f"Extracted embedded URL from chrome-extension wrapper: {embedded}")
                result.setdefault("metadata", {})["original_wrapper"] = url
                url = embedded

        # Run heuristic analysis first
        logger.debug(f"Running heuristic analysis on URL: {url}")
        heuristic_threats = self._analyze_url_heuristics(url)
        if heuristic_threats:
            threats.extend(heuristic_threats)
            logger.debug(f"Heuristic analysis found {len(heuristic_threats)} threat indicator(s)")

        if not result.get("use_external_apis", settings.EXTERNAL_APIS_ENABLED):
            self._mark_external_apis_skipped(result)
            result["threat_indicators"] = threats
            return self._calculate_verdict(result)

        # Attempt all APIs, not just relevant ones
        for api in ALL_EXTERNAL_APIS:
            api_key = api["key"]
            api_name = api["name"]
            try:
                if api_key == "virustotal":
                    vt_result = await self.virustotal.scan_url(url)
                    self._track_api_result(result, api_key, api_name, vt_result, warnings)
                    if vt_result and not vt_result.get("error"):
                        if "data" in vt_result:
                            attributes = vt_result.get("data", {}).get("attributes", {})
                            analysis = attributes.get("stats") or attributes.get("last_analysis_stats", {})
                            malicious = analysis.get("malicious", 0)
                            suspicious = analysis.get("suspicious", 0)
                            harmless = analysis.get("harmless", 0)
                            undetected = analysis.get("undetected", 0)
                            total_engines = sum([malicious, suspicious, harmless, undetected])
                            if malicious >= 5:
                                threats.append({"source": api_name, "severity": "critical", "indicator": f"Malicious detection: {malicious}/{total_engines} vendor(s)", "count": malicious})
                            elif malicious >= 2:
                                threats.append({"source": api_name, "severity": "medium", "indicator": f"Possible threat: {malicious}/{total_engines} vendor(s)", "count": malicious})
                            elif suspicious >= 3:
                                threats.append({"source": api_name, "severity": "medium", "indicator": f"Suspicious detection: {suspicious}/{total_engines} vendor(s)", "count": suspicious})
                elif api_key == "urlscan":
                    urlscan_result = await self.urlscan.scan_url(url)
                    self._track_api_result(result, api_key, api_name, urlscan_result, warnings)
                    if urlscan_result and not urlscan_result.get("error"):
                        if "uuid" in urlscan_result:
                            logger.debug(f"URLScan.io scan submitted successfully: {urlscan_result.get('uuid')}")
                        if isinstance(urlscan_result, dict) and "data" in urlscan_result:
                            result_data = urlscan_result.get("data", {})
                            classifications = result_data.get("classifications", {})
                            if isinstance(classifications, dict):
                                if classifications.get("phishing"):
                                    threats.append({"source": api_name, "severity": "critical", "indicator": "Phishing site detected"})
                                if classifications.get("malware"):
                                    threats.append({"source": api_name, "severity": "critical", "indicator": "Malware detected"})
                elif api_key == "abuseipdb":
                    enrichment_ip = self._resolve_public_ip(url, "url")
                    if enrichment_ip:
                        abuseipdb_result = await self.abuseipdb.check_ip(enrichment_ip)
                        self._track_api_result(result, api_key, api_name, abuseipdb_result, warnings)
                    else:
                        self._track_api_result(result, api_key, api_name, {"error": "Target host did not resolve to a public IP"}, warnings)
                elif api_key == "shodan":
                    enrichment_ip = self._resolve_public_ip(url, "url")
                    if enrichment_ip:
                        shodan_result = await self.shodan.search_ip(enrichment_ip)
                        self._track_api_result(result, api_key, api_name, shodan_result, warnings)
                    else:
                        self._track_api_result(result, api_key, api_name, {"error": "Target host did not resolve to a public IP"}, warnings)
                elif api_key == "hybrid_analysis":
                    self._track_api_result(result, api_key, api_name, {"error": "Not applicable for URL"}, warnings)
            except Exception as e:
                logger.warning(f"{api_name} check failed for {url}: {str(e)}")
                self._track_api_result(result, api_key, api_name, {"error": str(e)}, warnings)

        result["threat_indicators"] = threats
        result = self._calculate_verdict(result)
        return result

    def _analyze_domain_heuristics(self, domain: str) -> List[Dict]:
        """
        Comprehensive domain heuristic analysis for suspicious patterns
        """
        threats = []
        
        try:
            import re
            from datetime import datetime
            
            domain = domain.lower().strip()
            
            # ============================================
            # 1. SUSPICIOUS TLD DETECTION
            # ============================================
            high_risk_tlds = [
                '.xyz', '.top', '.cc', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', 
                '.click', '.stream', '.download', '.work', '.date', '.racing',
                '.win', '.bid', '.faith', '.cricket', '.science', '.party', '.review'
            ]
            
            medium_risk_tlds = [
                '.info', '.biz', '.su', '.ru', '.cn', '.ws', '.vg', '.buzz',
                '.link', '.club', '.site', '.online', '.live', '.space'
            ]
            
            for tld in high_risk_tlds:
                if domain.endswith(tld):
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "medium",
                        "indicator": f"High-risk TLD ({tld}) frequently used in phishing/malware",
                        "type": "suspicious_tld",
                        "confidence": 0.6
                    })
                    break
            
            for tld in medium_risk_tlds:
                if domain.endswith(tld):
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "low",
                        "indicator": f"Medium-risk TLD ({tld}) - monitor for abuse",
                        "type": "suspicious_tld",
                        "confidence": 0.4
                    })
                    break
            
            # ============================================
            # 2. DOMAIN LENGTH & COMPLEXITY
            # ============================================
            # Extremely long domains (common in DGA)
            domain_name = domain.split('.')[0]  # Get domain without TLD
            if len(domain_name) > 30:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": f"Unusually long domain name ({len(domain_name)} chars - possible DGA)",
                    "type": "suspicious_length",
                    "confidence": 0.5
                })
            
            # Check for excessive hyphens or numbers (common in malicious domains)
            hyphen_count = domain_name.count('-')
            if hyphen_count > 3:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "low",
                    "indicator": f"Excessive hyphens in domain ({hyphen_count}) - suspicious pattern",
                    "type": "suspicious_pattern",
                    "confidence": 0.4
                })
            
            # Check for excessive numbers
            number_count = sum(c.isdigit() for c in domain_name)
            if number_count > len(domain_name) * 0.5:  # More than 50% numbers
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": f"High number density in domain ({number_count} digits) - possible DGA",
                    "type": "suspicious_pattern",
                    "confidence": 0.55
                })
            
            # ============================================
            # 3. BRAND IMPERSONATION & TYPOSQUATTING
            # ============================================
            brand_keywords = [
                'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook',
                'instagram', 'twitter', 'netflix', 'spotify', 'linkedin', 'ebay',
                'bank', 'banking', 'chase', 'wellsfargo', 'citibank', 'usbank',
                'outlook', 'office365', 'gmail', 'yahoo', 'icloud', 'dropbox'
            ]
            
            legitimate_domains = {
                'paypal': ['paypal.com', 'paypal.co.uk'],
                'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr'],
                'google': ['google.com', 'gmail.com', 'youtube.com', 'gstatic.com'],
                'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com'],
                'apple': ['apple.com', 'icloud.com', 'me.com'],
                'facebook': ['facebook.com', 'fb.com', 'fbcdn.net'],
                'netflix': ['netflix.com', 'nflxvideo.net'],
            }
            
            for brand in brand_keywords:
                if brand in domain:
                    # Check if it's a legitimate domain
                    is_legitimate = False
                    if brand in legitimate_domains:
                        for legit in legitimate_domains[brand]:
                            if domain.endswith(legit):
                                is_legitimate = True
                                break
                    
                    if not is_legitimate:
                        threats.append({
                            "source": "Heuristic Analysis",
                            "severity": "critical",
                            "indicator": f"Possible brand impersonation: '{brand}' in non-legitimate domain",
                            "type": "brand_impersonation",
                            "confidence": 0.75
                        })
                        break

            # Brand + lure tokens in the same domain are strongly suspicious,
            # even if exact typosquatting regex doesn't match.
            lure_tokens = ['secure', 'verify', 'account', 'auth', 'update', 'signin', 'support', 'billing']
            has_brand = any(b in domain for b in brand_keywords)
            lure_hits = sum(1 for token in lure_tokens if token in domain)
            if has_brand and lure_hits >= 2:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "high",
                    "indicator": "Brand keyword mixed with multiple lure/auth tokens in domain",
                    "type": "brand_lure_domain",
                    "confidence": 0.73
                })
            
            # ============================================
            # 4. PHISHING KEYWORDS
            # ============================================
            phishing_terms = [
                'verify', 'secure', 'account', 'update', 'confirm', 'login',
                'signin', 'webscr', 'banking', 'suspended', 'locked', 'alert',
                'urgent', 'expire', 'validate', 'restore', 'recover'
            ]
            
            phishing_count = sum(1 for term in phishing_terms if term in domain)
            if phishing_count >= 2:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "critical",
                    "indicator": f"Multiple phishing keywords detected ({phishing_count}) in domain",
                    "type": "phishing_domain",
                    "confidence": 0.8
                })
            elif phishing_count == 1:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": "Phishing-related keyword in domain",
                    "type": "phishing_domain",
                    "confidence": 0.5
                })
            
            # ============================================
            # 5. HOMOGRAPH/IDN ATTACKS
            # ============================================
            # Check for mixed character sets (Cyrillic, Greek lookalikes)
            suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'у', 'х']  # Cyrillic
            if any(char in domain for char in suspicious_chars):
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "critical",
                    "indicator": "Homograph attack detected (lookalike characters)",
                    "type": "homograph",
                    "confidence": 0.9
                })
            
            # Check for IDN domains (punycode)
            if 'xn--' in domain:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": "IDN (internationalized) domain - potential homograph attack",
                    "type": "idn_domain",
                    "confidence": 0.6
                })
            
            # ============================================
            # 6. NEWLY REGISTERED PATTERNS
            # ============================================
            # Look for patterns common in newly registered malicious domains
            new_domain_patterns = [
                r'\d{4,}',  # Long numeric sequences
                r'[a-z]{20,}',  # Very long letter sequences (no spaces)
                r'([a-z]{2})\1{2,}',  # Repeated character pairs (aabbcc)
            ]
            
            for pattern in new_domain_patterns:
                if re.search(pattern, domain_name):
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "low",
                        "indicator": "Domain matches DGA (domain generation algorithm) pattern",
                        "type": "dga_pattern",
                        "confidence": 0.45
                    })
                    break
            
            # ============================================
            # 7. EXCESSIVE SUBDOMAINS
            # ============================================
            subdomain_count = domain.count('.')
            if subdomain_count > 4:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": f"Excessive subdomain levels ({subdomain_count}) - evasion technique",
                    "type": "excessive_subdomains",
                    "confidence": 0.55
                })
            
        except Exception as e:
            logger.warning(f"Domain heuristic analysis failed: {str(e)}")
        
        return threats

    async def _analyze_domain(self, domain: str, result: Dict) -> Dict:
        """Analyze domain using all available APIs and heuristic analysis. All APIs are attempted and logged."""
        logger.debug(f"Analyzing domain: {domain}")

        threats = list(result.get("threat_indicators", []))
        warnings = result.setdefault("warnings", [])
        self._prepare_api_tracking(result, result.get("input_type", "domain"))

        # Run heuristic analysis first
        heuristic_threats = self._analyze_domain_heuristics(domain)
        if heuristic_threats:
            threats.extend(heuristic_threats)
            logger.debug(f"Domain heuristic analysis found {len(heuristic_threats)} indicator(s)")

        # If domain is reserved/non-routable, mark all APIs as not applicable for test/demo purposes
        if str(domain).lower().endswith((".test", ".example", ".invalid", ".localhost")):
            self._mark_expected_apis_not_applicable(result, "Reserved test/non-routable domain input: APIs not called for test/demo domains.")
            # Add explicit API coverage explanation for the report
            result["api_coverage_explanation"] = (
                "API coverage: All 5 APIs are marked as 'not applicable' because the domain is reserved/non-routable (e.g., .test, .example). "
                "External threat intelligence APIs cannot provide meaningful results for such domains. This is intentional to avoid false positives and wasted quota. "
                "For real-world scans, API coverage will show checked/not_applicable/exceed_quota as appropriate."
            )
            result["threat_indicators"] = threats
            return self._calculate_verdict(result)

        if not result.get("use_external_apis", settings.EXTERNAL_APIS_ENABLED):
            self._mark_external_apis_skipped(result)
            result["threat_indicators"] = threats
            return self._calculate_verdict(result)

        # Attempt all APIs, not just relevant ones
        for api in ALL_EXTERNAL_APIS:
            api_key = api["key"]
            api_name = api["name"]
            try:
                if api_key == "virustotal":
                    vt_result = await self.virustotal.scan_domain(domain)
                    self._track_api_result(result, api_key, api_name, vt_result, warnings)
                    if vt_result and not vt_result.get("error"):
                        attrs = (vt_result.get("data") or {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
                        malicious = int(stats.get("malicious", 0) or 0)
                        suspicious = int(stats.get("suspicious", 0) or 0)
                        harmless = int(stats.get("harmless", 0) or 0)
                        undetected = int(stats.get("undetected", 0) or 0)
                        total_engines = max(0, malicious + suspicious + harmless + undetected)
                        if malicious >= 3:
                            threats.append({"source": api_name, "severity": "critical", "indicator": f"Malicious domain detection: {malicious}/{total_engines} vendor(s)", "count": malicious})
                        elif malicious >= 1 or suspicious >= 2:
                            threats.append({"source": api_name, "severity": "medium", "indicator": f"Suspicious domain reputation ({malicious} malicious, {suspicious} suspicious)", "count": malicious + suspicious})
                elif api_key == "urlscan":
                    urlscan_result = await self.urlscan.search_domain(domain)
                    self._track_api_result(result, api_key, api_name, urlscan_result, warnings)
                    if urlscan_result and not urlscan_result.get("error"):
                        results = urlscan_result.get("results", []) if isinstance(urlscan_result, dict) else []
                        malicious_hits = 0
                        suspicious_hits = 0
                        for item in results[:10]:
                            verdicts = (item or {}).get("verdicts", {})
                            overall = verdicts.get("overall", {}) if isinstance(verdicts, dict) else {}
                            score = overall.get("score", 0) if isinstance(overall, dict) else 0
                            is_mal = bool(overall.get("malicious", False)) if isinstance(overall, dict) else False
                            tags = (item or {}).get("tags", [])
                            if is_mal:
                                malicious_hits += 1
                            elif int(score or 0) > 0 or any(str(t).lower() in {"phishing", "malware", "suspicious"} for t in (tags or [])):
                                suspicious_hits += 1
                        if malicious_hits > 0:
                            threats.append({"source": api_name, "severity": "critical", "indicator": f"Historical malicious URLScan verdict(s): {malicious_hits}", "count": malicious_hits})
                        elif suspicious_hits > 0:
                            threats.append({"source": api_name, "severity": "medium", "indicator": f"Historical suspicious URLScan signal(s): {suspicious_hits}", "count": suspicious_hits})
                elif api_key == "abuseipdb":
                    enrichment_ip = self._resolve_public_ip(domain, "domain")
                    if enrichment_ip:
                        abuseipdb_result = await self.abuseipdb.check_ip(enrichment_ip)
                        self._track_api_result(result, api_key, api_name, abuseipdb_result, warnings)
                    else:
                        self._track_api_result(result, api_key, api_name, {"error": "Target host did not resolve to a public IP"}, warnings)
                elif api_key == "shodan":
                    enrichment_ip = self._resolve_public_ip(domain, "domain")
                    if enrichment_ip:
                        shodan_result = await self.shodan.search_ip(enrichment_ip)
                        self._track_api_result(result, api_key, api_name, shodan_result, warnings)
                    else:
                        self._track_api_result(result, api_key, api_name, {"error": "Target host did not resolve to a public IP"}, warnings)
                elif api_key == "hybrid_analysis":
                    self._track_api_result(result, api_key, api_name, {"error": "Not applicable for domain"}, warnings)
            except Exception as e:
                logger.warning(f"{api_name} check failed for {domain}: {str(e)}")
                self._track_api_result(result, api_key, api_name, {"error": str(e)}, warnings)

        result["threat_indicators"] = threats
        result = self._calculate_verdict(result)
        return result

    def _analyze_filehash_heuristics(self, file_hash: str, hash_type: str) -> List[Dict]:
        """
        Heuristic analysis for file hashes
        """
        threats = []
        
        try:
            import re
            
            file_hash = file_hash.lower().strip()
            
            # ============================================
            # 1. KNOWN MALICIOUS HASH PATTERNS
            # ============================================
            # Check for null/empty file hash (0000...0000)
            if re.match(r'^0+$', file_hash):
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": "Null hash detected (empty or corrupted file)",
                    "type": "null_hash",
                    "confidence": 0.7
                })
            
            # Check for all same characters (suspicious pattern)
            if len(set(file_hash)) == 1:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": "Suspicious hash pattern (all identical characters)",
                    "type": "suspicious_hash",
                    "confidence": 0.6
                })
            
            # ============================================
            # 2. HASH FORMAT VALIDATION
            # ============================================
            expected_lengths = {
                'md5': 32,
                'sha1': 40,
                'sha256': 64
            }
            
            if hash_type in expected_lengths:
                if len(file_hash) != expected_lengths[hash_type]:
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "medium",
                        "indicator": f"Invalid {hash_type.upper()} hash length (expected {expected_lengths[hash_type]}, got {len(file_hash)})",
                        "type": "invalid_hash",
                        "confidence": 0.8
                    })
            
            # Check for non-hexadecimal characters
            if not re.match(r'^[0-9a-f]+$', file_hash):
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": "Invalid hash format (contains non-hexadecimal characters)",
                    "type": "invalid_hash",
                    "confidence": 0.9
                })
            
        except Exception as e:
            logger.warning(f"File hash heuristic analysis failed: {str(e)}")
        
        return threats

    async def _analyze_file_hash(self, file_hash: str, hash_type: str, result: Dict) -> Dict:
        """Analyze file hash using all available APIs and heuristic analysis. All APIs are attempted and logged."""
        logger.debug(f"Analyzing file hash ({hash_type}): {file_hash}")

        threats = list(result.get("threat_indicators", []))
        warnings = result.setdefault("warnings", [])
        self._prepare_api_tracking(result, result.get("input_type", "file_hash"))

        # Run heuristic analysis first
        heuristic_threats = self._analyze_filehash_heuristics(file_hash, hash_type)
        if heuristic_threats:
            threats.extend(heuristic_threats)
            logger.debug(f"File hash heuristic analysis found {len(heuristic_threats)} indicator(s)")

        if not result.get("use_external_apis", settings.EXTERNAL_APIS_ENABLED):
            self._mark_external_apis_skipped(result)
            result["threat_indicators"] = threats
            return self._calculate_verdict(result)

        # Attempt all APIs, not just relevant ones
        for api in ALL_EXTERNAL_APIS:
            api_key = api["key"]
            api_name = api["name"]
            try:
                if api_key == "virustotal":
                    vt_result = await self.virustotal.scan_file(file_hash)
                    self._track_api_result(result, api_key, api_name, vt_result, warnings)
                    if vt_result and not vt_result.get("error"):
                        if "data" in vt_result:
                            analysis = (
                                vt_result.get("data", {})
                                .get("attributes", {})
                                .get("last_analysis_stats", {})
                            )
                            malicious = analysis.get("malicious", 0)
                            suspicious = analysis.get("suspicious", 0)
                            if malicious > 0:
                                threats.append({"source": api_name, "severity": "critical", "indicator": f"Malware detected by {malicious} vendor(s)", "count": malicious})
                            elif suspicious > 0:
                                threats.append({"source": api_name, "severity": "medium", "indicator": f"Suspicious file by {suspicious} vendor(s)", "count": suspicious})
                elif api_key == "hybrid_analysis":
                    ha_result = await self.hybrid_analysis.search_hash(file_hash)
                    self._track_api_result(result, api_key, api_name, ha_result, warnings)
                    if ha_result and not ha_result.get("error"):
                        results = ha_result.get("results", [])
                        if results:
                            for item in results:
                                verdict = item.get("verdict")
                                threat_score = item.get("threat_score", 0)
                                if verdict == "malicious" or threat_score > 75:
                                    threats.append({"source": api_name, "severity": "critical", "indicator": f"Malware verdict with score {threat_score}", "verdict": verdict})
                                elif verdict == "suspicious" or threat_score > 25:
                                    threats.append({"source": api_name, "severity": "medium", "indicator": f"Suspicious verdict with score {threat_score}", "verdict": verdict})
                elif api_key == "abuseipdb":
                    self._track_api_result(result, api_key, api_name, {"error": "Not applicable for file hash"}, warnings)
                elif api_key == "shodan":
                    self._track_api_result(result, api_key, api_name, {"error": "Not applicable for file hash"}, warnings)
                elif api_key == "urlscan":
                    self._track_api_result(result, api_key, api_name, {"error": "Not applicable for file hash"}, warnings)
            except Exception as e:
                logger.warning(f"{api_name} check failed for {file_hash}: {str(e)}")
                self._track_api_result(result, api_key, api_name, {"error": str(e)}, warnings)

        result["threat_indicators"] = threats
        result = self._calculate_verdict(result)

        # concise summary to avoid huge dumps
        try:
            verdict = result.get('verdict', 'unknown')
            confidence = result.get('confidence', 0)
            logger.info(
                f"File hash analysis complete: {file_hash} verdict={verdict} confidence={confidence:.2f} "
                f"apis={','.join(result.get('api_results', {}).get('apis_called', []))}"
            )
        except Exception:
            pass

        return result
    
    async def _analyze_file(self, file_value: str, metadata: Dict, result: Dict) -> Dict:
        """Analyze filename/path inputs for suspicious extensions and provide heuristic and API-assisted analysis."""
        logger.debug(f"Analyzing file input: {file_value}")

        # Start with heuristic file extension checks
        threats = list(result.get("threat_indicators", []))
        self._prepare_api_tracking(result, result.get("input_type", "file"))

        file_extension = metadata.get("file_extension") if isinstance(metadata, dict) else None
        if not file_extension and "." in str(file_value):
            file_extension = "." + str(file_value).strip().split('.')[-1].lower()

        suspicious_exts = {
            ".exe", ".dll", ".bat", ".cmd", ".com", ".js", ".vbs", ".ps1", ".scr", ".jar", ".msi", ".docm", ".xlsm", ".pptm"
        }

        if file_extension and file_extension.lower() in suspicious_exts:
            threats.append({
                "source": "Heuristic Analysis",
                "severity": "suspicious",
                "indicator": f"Suspicious file extension detected: {file_extension}",
                "type": "suspicious_file_extension",
                "confidence": 0.55,
            })

        # If external APIs are enabled, attempt file-hash intelligence via derived hash path
        if result.get("use_external_apis", settings.EXTERNAL_APIS_ENABLED):
            derived_hash = hashlib.sha256(str(file_value).encode("utf-8")).hexdigest()
            result.setdefault("metadata", {})["derived_file_hash"] = derived_hash
            result.setdefault("metadata", {})["file_extension"] = file_extension

            # Keep existing heuristics + API results merged from file hash path
            hash_analysis = await self._analyze_file_hash(derived_hash, "sha256", result)
            result = hash_analysis
            # Post-process to preserve the heuristic markers
            result_threats = result.get("threat_indicators", [])
            result["threat_indicators"] = threats + [t for t in result_threats if t not in threats]
            result["summary"] = (
                "File detected by extension. Derived hash-based API checks completed; use actual file hash for strongest results."
            )
            return result

        # Otherwise evaluate locally and skip external APIs
        self._mark_external_apis_skipped(result, reason="File path/name input does not support direct external API lookup; provide hash for full coverage")

        result["threat_indicators"] = threats
        result = self._calculate_verdict(result)
        if not result.get("summary"):
            result["summary"] = (
                "File input acknowledged. For hash-based analysis, provide a MD5/SHA1/SHA256 hash."
            )

        return result

    async def _apply_ai_analysis(self, result: Dict) -> Dict:
        """
        Apply AI and ML models to enhance threat analysis with predictions
        """
        try:
            if not self.anomaly_model or not self.threat_model:
                logger.error("ML/AI models are required for all scans but are missing.")
                raise RuntimeError("ML/AI models are required for all scans.")

            # Prepare features for ML models
            features = {
                'threat_indicators': result.get('threat_indicators', []),
                'verdict': result.get('verdict'),
                'confidence': result.get('confidence', 0),
                'scan_type': result.get('input_type', 'unknown'),
                'api_results': result.get('api_results', {}),
                'malicious_score': result.get('confidence', 0) if result.get('verdict') == ThreatLevel.MALICIOUS else 0
            }

            ai_analysis = {}

            # Anomaly Detection
            try:
                anomaly_result = self.anomaly_model.predict(features)
                ai_analysis['anomaly_detection'] = {
                    'is_anomaly': anomaly_result.get('is_anomaly', False),
                    'score': anomaly_result.get('score', 0),
                    'confidence': anomaly_result.get('confidence', 0),
                    'factors': anomaly_result.get('factors', [])
                }
                logger.info(f"[ML] Anomaly detection used: is_anomaly={anomaly_result.get('is_anomaly')}, score={anomaly_result.get('score')}, factors={anomaly_result.get('factors')}")
            except Exception as e:
                logger.error(f"Anomaly detection failed: {e}")

            # Threat Prediction
            try:
                threat_prediction = self.threat_model.predict(features)
                ai_analysis['threat_prediction'] = {
                    'is_threat': threat_prediction.get('is_threat', False),
                    'probability': threat_prediction.get('probability', 0),
                    'threat_level': threat_prediction.get('threat_level', 'unknown'),
                    'confidence': threat_prediction.get('confidence', 0),
                    'factors': threat_prediction.get('factors', [])
                }
                logger.info(f"[ML] Threat prediction used: threat_level={threat_prediction.get('threat_level')}, probability={threat_prediction.get('probability')}, factors={threat_prediction.get('factors')}")
                # Enhance verdict if AI predicts high threat
                if threat_prediction.get('probability', 0) > 0.8 and result.get('verdict') != ThreatLevel.MALICIOUS:
                    logger.info("[ML] AI prediction suggests escalating to MALICIOUS")
                    result['ai_escalation'] = True
                    result['ai_escalation_reason'] = f"AI model predicted {threat_prediction.get('probability'):.0%} threat probability"
            except Exception as e:
                logger.error(f"Threat prediction failed: {e}")

            # Advanced AI Analysis (Gemini if available)
            if self.ai_analyzer:
                try:
                    threat_data = {
                        'id': result.get('input', 'unknown'),
                        'type': result.get('input_type', 'unknown'),
                        'indicators': result.get('threat_indicators', []),
                        'api_results': result.get('api_results', {}),
                        'verdict': result.get('verdict'),
                        'confidence': result.get('confidence', 0)
                    }
                    ai_result = await self.ai_analyzer.analyze_threat(threat_data)
                    ai_analysis['advanced_ai'] = {
                        'risk_level': ai_result.get('risk_level', 'unknown'),
                        'confidence': ai_result.get('confidence', 0),
                        'threat_types': ai_result.get('threat_types', []),
                        'recommendations': ai_result.get('recommendations', [])
                    }
                    logger.info(f"[AI] Advanced AI analysis used: risk_level={ai_result.get('risk_level')}, confidence={ai_result.get('confidence')}")
                except Exception as e:
                    logger.error(f"Advanced AI analysis failed: {e}")

            # Add behavioral analysis
            behavioral_analysis = self._generate_behavioral_analysis(result)
            ai_analysis['behavioral_analysis'] = behavioral_analysis

            # Calculate reputation score
            reputation_score = self._calculate_reputation_score(result, ai_analysis)
            ai_analysis['reputation_score'] = reputation_score

            # Store AI analysis results
            result['ai_analysis'] = ai_analysis

            # Refine verdict based on AI insights
            result = self._refine_verdict_with_ai(result, ai_analysis)

        except Exception as e:
            logger.error(f"AI analysis failed: {e}", exc_info=True)

        return result
    
    def _generate_behavioral_analysis(self, result: Dict) -> Dict:
        """
        Generate behavioral analysis based on patterns and characteristics
        """
        behavioral_score = 0
        behaviors = []
        
        try:
            input_type = result.get('input_type', '')
            threat_indicators = result.get('threat_indicators', [])
            
            # Analyze behavior patterns
            if input_type == 'url':
                # URL behavioral patterns
                indicator = result.get('input', '')
                
                if any(port in indicator for port in [':4444', ':5555', ':6666', ':1337']):
                    behavioral_score += 0.3
                    behaviors.append('Uses non-standard port associated with malware')
                
                if any(keyword in indicator.lower() for keyword in ['cmd', 'shell', 'exploit', 'payload']):
                    behavioral_score += 0.25
                    behaviors.append('Contains keywords associated with exploitation')
                
                if len([t for t in threat_indicators if t.get('severity') == 'critical']) >= 2:
                    behavioral_score += 0.2
                    behaviors.append('Multiple critical indicators suggest coordinated attack')
            
            elif input_type == 'ip':
                # IP behavioral patterns
                ip_ranges = result.get('metadata', {}).get('geo_info', {})
                
                if len(threat_indicators) > 3:
                    behavioral_score += 0.25
                    behaviors.append('Multiple threat indicators suggest active malicious activity')
            
            # Check for evasion techniques
            if any('obfuscation' in str(t).lower() for t in threat_indicators):
                behavioral_score += 0.2
                behaviors.append('Uses obfuscation/evasion techniques')
            
            # Check for multi-stage attack patterns
            if len(threat_indicators) >= 3 and len(set(t.get('type', '') for t in threat_indicators)) >= 2:
                behavioral_score += 0.15
                behaviors.append('Exhibits multi-stage attack pattern')
            
            behavioral_score = min(behavioral_score, 1.0)
            
        except Exception as e:
            logger.warning(f"Behavioral analysis failed: {e}")
        
        return {
            'score': round(behavioral_score, 2),
            'behaviors_detected': behaviors,
            'risk_level': 'high' if behavioral_score > 0.7 else 'medium' if behavioral_score > 0.4 else 'low'
        }
    
    def _calculate_reputation_score(self, result: Dict, ai_analysis: Dict) -> Dict:
        """
        Calculate reputation score based on multiple factors
        """
        reputation = 100  # Start with perfect score
        factors = []
        
        try:
            # Deduct points for threats
            threat_indicators = result.get('threat_indicators', [])
            critical_count = sum(1 for t in threat_indicators if t.get('severity') == 'critical')
            medium_count = sum(1 for t in threat_indicators if t.get('severity') == 'medium')
            low_count = sum(1 for t in threat_indicators if t.get('severity') == 'low')
            
            reputation -= critical_count * 25
            reputation -= medium_count * 10
            reputation -= low_count * 5
            
            if critical_count > 0:
                factors.append(f"{critical_count} critical threats (-{critical_count * 25} points)")
            if medium_count > 0:
                factors.append(f"{medium_count} medium threats (-{medium_count * 10} points)")
            
            # AI model influence
            if ai_analysis.get('threat_prediction', {}).get('probability', 0) > 0.8:
                reputation -= 20
                factors.append("AI model high threat probability (-20 points)")
            
            if ai_analysis.get('anomaly_detection', {}).get('is_anomaly', False):
                reputation -= 15
                factors.append("Anomaly detected (-15 points)")
            
            # Behavioral score influence
            behavioral_score = ai_analysis.get('behavioral_analysis', {}).get('score', 0)
            if behavioral_score > 0.7:
                reputation -= 20
                factors.append("High-risk behavior patterns (-20 points)")
            elif behavioral_score > 0.4:
                reputation -= 10
                factors.append("Medium-risk behavior patterns (-10 points)")
            
            # Ensure score stays in valid range
            reputation = max(0, min(100, reputation))
            
        except Exception as e:
            logger.warning(f"Reputation calculation failed: {e}")
        
        return {
            'score': reputation,
            'rating': 'trusted' if reputation >= 80 else 'neutral' if reputation >= 50 else 'suspicious' if reputation >= 30 else 'malicious',
            'factors': factors
        }
    
    def _refine_verdict_with_ai(self, result: Dict, ai_analysis: Dict) -> Dict:
        """
        Refine the threat verdict using AI insights
        """
        try:
            original_verdict = result.get('verdict')
            original_confidence = result.get('confidence', 0)
            
            # Get AI predictions
            threat_prediction = ai_analysis.get('threat_prediction', {})
            anomaly_detection = ai_analysis.get('anomaly_detection', {})
            behavioral_analysis = ai_analysis.get('behavioral_analysis', {})
            reputation = ai_analysis.get('reputation_score', {})
            
            # Escalation logic
            should_escalate = False
            escalation_reasons = []
            
            # Check if AI strongly suggests malicious
            if threat_prediction.get('probability', 0) > 0.85:
                should_escalate = True
                escalation_reasons.append(f"AI threat prediction: {threat_prediction.get('probability'):.0%}")
            
            if anomaly_detection.get('is_anomaly', False) and anomaly_detection.get('score', 0) > 0.8:
                should_escalate = True
                escalation_reasons.append(f"Strong anomaly detected (score: {anomaly_detection.get('score')})")
            
            if behavioral_analysis.get('score', 0) > 0.7:
                should_escalate = True
                escalation_reasons.append(f"High-risk behavior (score: {behavioral_analysis.get('score')})")
            
            if reputation.get('score', 100) < 30:
                should_escalate = True
                escalation_reasons.append(f"Poor reputation score: {reputation.get('score')}")
            
            # Apply escalation if needed
            if should_escalate and original_verdict != ThreatLevel.MALICIOUS:
                if original_verdict == ThreatLevel.CLEAN:
                    result['verdict'] = ThreatLevel.SUSPICIOUS
                    result['confidence'] = 0.65
                else:  # SUSPICIOUS -> MALICIOUS
                    result['verdict'] = ThreatLevel.MALICIOUS
                    result['confidence'] = min(0.90, original_confidence + 0.15)
                
                result['ai_verdict_adjustment'] = {
                    'original_verdict': original_verdict,
                    'adjusted_verdict': result['verdict'],
                    'reasons': escalation_reasons,
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                logger.debug(f"Verdict escalated from {original_verdict} to {result['verdict']} based on AI analysis")
            
            # Boost confidence if AI corroborates
            elif original_verdict == ThreatLevel.MALICIOUS:
                if threat_prediction.get('probability', 0) > 0.7:
                    confidence_boost = 0.05
                    result['confidence'] = min(0.98, original_confidence + confidence_boost)
                    result['ai_confidence_boost'] = confidence_boost
        
        except Exception as e:
            logger.warning(f"Verdict refinement failed: {e}")
        
        return result

    def _clamp01(self, value: float) -> float:
        try:
            return max(0.0, min(1.0, float(value)))
        except Exception:
            return 0.0

    def _resolve_detector_profile(self, result: Dict, threats: List[Dict[str, Any]]) -> str:
        input_type = str(result.get("input_type", "")).lower()
        if input_type == "ip":
            return "network"
        if input_type in {"url", "domain"}:
            return "browser"
        if input_type in {"file", "file_hash", "hash"}:
            return "file"

        sources = " ".join(str((t or {}).get("source", "")).lower() for t in threats if isinstance(t, dict))
        if any(tok in sources for tok in ["ids", "nids", "hids", "snort", "suricata", "attackevent"]):
            return "ids"
        return "default"

    def _calibrate_confidence(self, confidence: float, detector_profile: str) -> float:
        raw = self._clamp01(confidence)
        calib = self._detector_calibration.get(detector_profile, self._detector_calibration.get("default", {}))
        scale = float(calib.get("scale", 1.0) or 1.0)
        offset = float(calib.get("offset", 0.0) or 0.0)
        return self._clamp01((raw * scale) + offset)

    def _map_severity_from_calibrated_confidence(
        self,
        calibrated_confidence: float,
        detector_profile: str,
        source_count: int,
    ) -> str:
        profile = self._detector_threshold_profiles.get(
            detector_profile,
            self._detector_threshold_profiles.get("default", {}),
        )
        crit_th = float(profile.get("critical", 0.94) or 0.94)
        high_th = float(profile.get("high", 0.84) or 0.84)
        med_th = float(profile.get("medium", 0.62) or 0.62)
        single_source_high = float(profile.get("single_source_auto_high_min", 0.94) or 0.94)

        conf = self._clamp01(calibrated_confidence)
        if conf >= crit_th:
            severity = "critical"
        elif conf >= high_th:
            severity = "high"
        elif conf >= med_th:
            severity = "medium"
        else:
            severity = "low"

        # Multi-source correlation rule:
        # Auto high/critical requires >=2 independent sources,
        # unless confidence is exceptionally high.
        if source_count < 2 and severity in {"high", "critical"} and conf < single_source_high:
            return "medium"
        return severity

    def _build_explainability_block(self, result: Dict, threats: List[Dict[str, Any]], detector_profile: str) -> Dict[str, Any]:
        forensic = result.get("forensic_metadata", {}) or {}
        source_count = int(forensic.get("corroboration_count", 0) or 0)
        calibrated = float((forensic.get("calibration") or {}).get("confidence_calibrated", result.get("confidence", 0.0)) or 0.0)

        top_signals = []
        for item in threats[:8]:
            if not isinstance(item, dict):
                continue
            top_signals.append(
                {
                    "source": item.get("source", "unknown"),
                    "severity": item.get("severity", "unknown"),
                    "indicator": item.get("indicator", ""),
                    "confidence": round(float(item.get("confidence", 0.0) or 0.0), 3),
                }
            )

        matched_rules = []
        if source_count >= 2:
            matched_rules.append("multi_source_corroboration")
        if source_count < 2 and calibrated < 0.94:
            matched_rules.append("single_source_review_gate")
        if (forensic.get("heuristic_indicators") or {}).get("critical", 0) >= 1:
            matched_rules.append("critical_heuristic_indicator")
        if float(forensic.get("source_weighted_confidence", 0.0) or 0.0) >= 0.75:
            matched_rules.append("source_weighted_confidence_high")

        source_reliability = {}
        for item in threats:
            if not isinstance(item, dict):
                continue
            src = str(item.get("source", "unknown")).strip().lower()
            source_reliability[src] = round(float(self._source_confidence_weights.get(src, 0.9)), 3)

        return {
            "detector_profile": detector_profile,
            "top_signals": top_signals,
            "matched_rules": matched_rules,
            "source_reliability": source_reliability,
            "model_confidence": round(float(result.get("confidence", 0.0) or 0.0), 3),
        }

    def _build_report_quality_checks(self, result: Dict) -> Dict[str, Any]:
        warnings: List[str] = []
        issues: List[str] = []
        forensic = result.get("forensic_metadata", {}) or {}
        severity = str((forensic.get("calibration") or {}).get("severity_gated", "low")).lower()
        confidence = float(result.get("confidence", 0.0) or 0.0)

        # Check missing IOC fields for non-clean findings.
        if severity in {"medium", "high", "critical"}:
            input_value = str(result.get("input", "") or "").strip()
            if not input_value:
                issues.append("missing_primary_ioc")
                warnings.append("Primary IOC value is missing in this analysis result.")

        # Check contradictory severity-confidence combinations.
        if severity in {"high", "critical"} and confidence < 0.70:
            issues.append("severity_confidence_mismatch")
            warnings.append("High/Critical severity has lower-than-expected confidence.")
        if severity == "low" and confidence > 0.90:
            issues.append("severity_confidence_mismatch")
            warnings.append("Low severity has unusually high confidence.")

        # Check stale data timestamp.
        ts = str(result.get("timestamp", "") or "").strip()
        if ts:
            try:
                ts_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                age_hours = (datetime.utcnow() - ts_dt.replace(tzinfo=None)).total_seconds() / 3600.0
                if age_hours > 24:
                    issues.append("stale_data")
                    warnings.append(f"Analysis data age is {age_hours:.1f}h; consider refreshing before reporting.")
            except Exception:
                pass

        return {
            "ok": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
        }

    def _calculate_verdict(self, result: Dict) -> Dict:
        """
        Calculate final threat verdict based on indicators with forensic corroboration

        Implements multi-source corroboration:
        - Malicious if ≥2 sources confirm threat
        - Tracks evidence sources with links/IDs
        - Confidence increases with more corroboration

        Returns ThreatLevel and confidence score
        """
        threats = result.get("threat_indicators", [])

        if not threats:
            # EVEN FOR CLEAN SCANS: Show which APIs were called and checked
            apis_called = result.get("api_results", {}).get("apis_called", [])
            apis_expected = result.get("api_results", {}).get("apis_expected", [])
            api_results = result.get("api_results", {})
            
            # Build forensic record showing all APIs checked (even if no threats)
            checked_sources = []
            for api_name in apis_called:
                api_key = api_name.lower().replace(".", "_").replace(" ", "_")
                api_data = api_results.get(api_key, {})
                
                source_info = {
                    "source": api_name,
                    "severity": "info",
                    "indicator": "No threats detected",
                    "timestamp": datetime.utcnow().isoformat(),
                    "status": "checked",
                    "threats_found": 0
                }
                
                # Add specific scan details if available
                if "virustotal" in api_key and "data" in api_data:
                    attrs = api_data.get("data", {}).get("attributes", {})
                    stats = attrs.get("stats") or attrs.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) if stats else 0
                    source_info["details"] = f"Scanned by {total} engines, {malicious} detections"
                    source_info["threats_found"] = malicious
                elif "urlscan" in api_key and "data" in api_data:
                    source_info["details"] = "URL scanned successfully"
                elif "abuseipdb" in api_key and "data" in api_data:
                    score = api_data.get("data", {}).get("abuseConfidenceScore", 0)
                    source_info["details"] = f"Abuse score: {score}%"
                    source_info["threats_found"] = score
                elif "shodan" in api_key and not api_data.get("error"):
                    ports = len(api_data.get("ports", []))
                    source_info["details"] = f"{ports} ports scanned"
                elif "hybridanalysis" in api_key or "hybrid_analysis" in api_key:
                    source_info["details"] = "File hash lookup completed"
                
                checked_sources.append(source_info)
            
            coverage_ratio = (len(apis_called) / len(apis_expected)) if apis_expected else 1.0
            if apis_expected:
                # Keep confidence realistic when external corroboration is partial or absent.
                base_confidence = 0.68 if result.get("use_external_apis", True) else 0.62
                result["confidence"] = min(0.95, round(base_confidence + (0.27 * coverage_ratio), 3))
            else:
                # Heuristic-only clean result without relevant external APIs.
                result["confidence"] = 0.8

            result["verdict"] = ThreatLevel.CLEAN
            if apis_expected:
                if apis_called:
                    result["summary"] = f"No threats detected. Verified by {len(apis_called)}/{len(apis_expected)} relevant API(s)."
                else:
                    result["summary"] = f"No confirmed threats detected, but no relevant external API completed for this scan (0/{len(apis_expected)})."
            else:
                result["summary"] = "No threats detected."
            result["forensic_metadata"] = {
                "evidence_sources": apis_called,  # List of API names that were called
                "corroboration_count": 0,  # No threats corroborated
                "corroboration_threshold_met": False,
                "source_details": checked_sources,  # Detailed info about what each API checked
                "apis_checked": len(apis_called),
                "total_apis_available": len(apis_expected),
                "scan_coverage": f"{len(apis_called)}/{len(apis_expected) or 0} relevant APIs",
                "api_status": api_results.get("api_status", {}),
            }

            advanced_forensic = self._build_advanced_forensic_analysis(
                result=result,
                threats=threats,
                corroboration_analysis=None,
            )
            result["forensic_metadata"]["advanced_analysis"] = advanced_forensic
            result["forensic_analysis"] = advanced_forensic
            return result

        # Extract unique sources that detected threats
        unique_sources = set()
        evidence_sources = []
        source_details = []
        
        # Separate heuristic and API threats for proper handling
        heuristic_threats = [t for t in threats if t.get("source") == "Heuristic Analysis"]
        api_threats = [t for t in threats if t.get("source") != "Heuristic Analysis"]
        
        for threat in threats:
            source = threat.get("source") or "Heuristic Analysis"
            if source:
                unique_sources.add(source)
                
                # Build evidence record with source details
                evidence_record = {
                    "source": source,
                    "severity": threat.get("severity"),
                    "indicator": threat.get("indicator"),
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                # Add source-specific IDs/links for forensic traceability
                if "count" in threat:
                    evidence_record["detection_count"] = threat["count"]
                if "score" in threat:
                    evidence_record["score"] = threat["score"]
                if "details" in threat:
                    evidence_record["details"] = threat["details"]
                
                # Add API result reference for full traceability
                api_results = result.get("api_results", {})
                source_key = source.lower().replace(" ", "_").replace(".", "_")
                if source_key in api_results:
                    evidence_record["api_result_ref"] = source_key
                
                evidence_sources.append(source)
                source_details.append(evidence_record)

        # Count sources confirming threats
        corroboration_count = len(unique_sources)
        corroboration_threshold_met = corroboration_count >= 2
        
        # Analyze threat severity with corroboration
        critical_count = sum(1 for t in threats if t.get("severity") == "critical")
        high_count = sum(1 for t in threats if t.get("severity") == "high")
        medium_count = sum(1 for t in threats if t.get("severity") == "medium")
        low_count = sum(1 for t in threats if t.get("severity") == "low")
        
        # Count heuristic threats separately
        heuristic_critical = sum(1 for t in heuristic_threats if t.get("severity") == "critical")
        heuristic_high = sum(1 for t in heuristic_threats if t.get("severity") == "high")
        heuristic_medium = sum(1 for t in heuristic_threats if t.get("severity") == "medium")
        heuristic_low = sum(1 for t in heuristic_threats if t.get("severity") == "low")

        # Weighted severity scoring to better fuse multiple weak/medium findings.
        weighted_score = (
            (critical_count * 5)
            + (high_count * 3)
            + (medium_count * 2)
            + low_count
        )
        heuristic_weighted_score = (
            (heuristic_critical * 5)
            + (heuristic_high * 3)
            + (heuristic_medium * 2)
            + heuristic_low
        )

        # Per-source confidence weighting (local + APIs + corroboration inputs)
        source_weighted_score = 0.0
        source_weight_total = 0.0
        sev_weight = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}
        for t in threats:
            if not isinstance(t, dict):
                continue
            src = str(t.get("source", "heuristic analysis")).strip().lower()
            src_weight = float(self._source_confidence_weights.get(src, 0.9))
            sev = str(t.get("severity", "low")).lower()
            ind_conf = float(t.get("confidence", 0.6) or 0.6)
            weighted = src_weight * sev_weight.get(sev, 0.25) * ind_conf
            source_weighted_score += weighted
            source_weight_total += src_weight

        weighted_fusion_confidence = 0.0
        if source_weight_total > 0:
            weighted_fusion_confidence = max(0.0, min(1.0, source_weighted_score / source_weight_total))
        
        # Calculate average confidence from heuristic threats
        heuristic_confidences = [t.get("confidence", 0.5) for t in heuristic_threats if "confidence" in t]
        avg_heuristic_confidence = sum(heuristic_confidences) / len(heuristic_confidences) if heuristic_confidences else 0.5
        
        # Calculate highest confidence for critical heuristics
        critical_heuristic_confidences = [t.get("confidence", 0.5) for t in heuristic_threats if t.get("severity") == "critical" and "confidence" in t]
        max_critical_confidence = max(critical_heuristic_confidences) if critical_heuristic_confidences else 0.5

        # Enhanced multi-source corroboration logic with conservative defaults
        # to reduce false positives when external APIs fail or are unavailable.
        api_status_map = (result.get("api_results") or {}).get("api_status") or {}
        api_checked = len((result.get("api_results") or {}).get("apis_called") or [])
        api_error_count = 0
        for api_meta in api_status_map.values():
            status = str((api_meta or {}).get("status", "")).lower()
            if status == "error":
                api_error_count += 1
        has_api_corroboration = len(api_threats) > 0

        if heuristic_critical >= 3:
            result["verdict"] = ThreatLevel.MALICIOUS
            result["confidence"] = min(0.95, max_critical_confidence + 0.10)
            result["summary"] = (
                f"MALICIOUS - {heuristic_critical} critical threat indicators detected. "
                f"Multiple malicious patterns confirmed through heuristic analysis."
            )
        elif heuristic_critical >= 2:
            result["verdict"] = ThreatLevel.MALICIOUS
            result["confidence"] = min(0.90, max_critical_confidence + 0.05)
            result["summary"] = (
                f"MALICIOUS - {heuristic_critical} critical threat indicators detected. "
                f"Pattern-based analysis identified malicious characteristics."
            )
        elif heuristic_critical >= 1 and has_api_corroboration:
            # Heuristic + API threat = corroborated malicious
            result["verdict"] = ThreatLevel.MALICIOUS
            result["confidence"] = min(0.95, max_critical_confidence + (len(api_threats) * 0.05))
            result["summary"] = (
                "MALICIOUS (CORROBORATED) - Critical threat patterns confirmed by external analysis."
            )
        elif heuristic_high >= 2 and has_api_corroboration:
            # Multiple high-severity heuristic indicators corroborated by APIs is strong malicious evidence.
            result["verdict"] = ThreatLevel.MALICIOUS
            result["confidence"] = min(0.90, 0.75 + (heuristic_high * 0.05) + (len(api_threats) * 0.03))
            result["summary"] = (
                f"MALICIOUS (CORROBORATED) - {heuristic_high} high-severity patterns confirmed by external analysis."
            )
        elif heuristic_weighted_score >= 8 and has_api_corroboration:
            result["verdict"] = ThreatLevel.SUSPICIOUS
            result["confidence"] = min(0.82, 0.62 + (heuristic_weighted_score * 0.02))
            result["summary"] = (
                "SUSPICIOUS (CORROBORATED) - Multiple layered risk indicators detected across heuristic and API analysis."
            )
        elif heuristic_critical >= 1 and max_critical_confidence >= 0.85:
            # Single high-confidence heuristic without corroboration should remain suspicious,
            # especially when APIs were not checked or returned errors.
            result["verdict"] = ThreatLevel.SUSPICIOUS
            result["confidence"] = min(0.80, max_critical_confidence)
            api_hint = "limited corroboration"
            if api_checked == 0 or api_error_count > 0:
                api_hint = "API corroboration unavailable"
            result["summary"] = (
                f"SUSPICIOUS - High-confidence threat pattern detected: {heuristic_threats[0].get('indicator', 'Unknown')} "
                f"({api_hint})."
            )
        elif heuristic_critical >= 1:
            result["verdict"] = ThreatLevel.SUSPICIOUS
            result["confidence"] = min(0.75, max_critical_confidence + 0.05)
            result["summary"] = (
                f"SUSPICIOUS - Critical threat pattern detected: {heuristic_threats[0].get('indicator', 'Unknown')}"
            )
        elif heuristic_high >= 2:
            result["verdict"] = ThreatLevel.SUSPICIOUS
            result["confidence"] = min(0.78, 0.62 + (heuristic_high * 0.06))
            result["summary"] = (
                f"SUSPICIOUS - {heuristic_high} high-severity suspicious patterns detected."
            )
        elif heuristic_medium >= 3:
            # 3+ medium heuristics = likely malicious
            result["verdict"] = ThreatLevel.SUSPICIOUS
            result["confidence"] = min(0.75, avg_heuristic_confidence + 0.10)
            result["summary"] = (
                f"SUSPICIOUS - {heuristic_medium} suspicious patterns detected (strong evidence)."
            )
        elif heuristic_medium >= 2 and avg_heuristic_confidence >= 0.6:
            # 2 medium heuristics with good confidence
            result["verdict"] = ThreatLevel.SUSPICIOUS
            result["confidence"] = min(0.70, avg_heuristic_confidence + 0.05)
            result["summary"] = (
                f"SUSPICIOUS - {heuristic_medium} suspicious patterns detected in analysis."
            )
        elif corroboration_threshold_met:
            # At least 2 sources confirm - higher confidence
            if critical_count > 0:
                result["verdict"] = ThreatLevel.MALICIOUS
                result["confidence"] = min(1.0, 0.85 + (corroboration_count * 0.05))
                result["summary"] = (
                    f"MALICIOUS (CORROBORATED) - {critical_count} critical threat(s) "
                    f"confirmed by {corroboration_count} independent sources."
                )
            elif high_count >= 2:
                result["verdict"] = ThreatLevel.MALICIOUS
                result["confidence"] = min(1.0, 0.80 + (corroboration_count * 0.05))
                result["summary"] = (
                    f"MALICIOUS (CORROBORATED) - {high_count} high-severity threat(s) "
                    f"confirmed by {corroboration_count} independent sources."
                )
            elif medium_count >= 2:
                result["verdict"] = ThreatLevel.MALICIOUS
                result["confidence"] = min(1.0, 0.75 + (corroboration_count * 0.05))
                result["summary"] = (
                    f"MALICIOUS (CORROBORATED) - Multiple medium threats "
                    f"confirmed by {corroboration_count} independent sources."
                )
            elif medium_count > 0:
                result["verdict"] = ThreatLevel.SUSPICIOUS
                result["confidence"] = min(1.0, 0.65 + (corroboration_count * 0.05))
                result["summary"] = (
                    f"SUSPICIOUS (CORROBORATED) - Threats detected by "
                    f"{corroboration_count} independent sources."
                )
            else:
                result["verdict"] = ThreatLevel.SUSPICIOUS
                result["confidence"] = 0.60
                result["summary"] = (
                    f"SUSPICIOUS - Low-level threats confirmed by "
                    f"{corroboration_count} sources."
                )
        else:
            # Limited corroboration - lower confidence, more conservative verdict
            if critical_count > 0:
                result["verdict"] = ThreatLevel.MALICIOUS
                result["confidence"] = 0.70  # Lower confidence without corroboration
                result["summary"] = (
                    f"MALICIOUS - {critical_count} critical threat(s) detected "
                    f"(limited corroboration - additional validation recommended)."
                )
            elif high_count >= 2:
                result["verdict"] = ThreatLevel.SUSPICIOUS
                result["confidence"] = 0.62
                result["summary"] = (
                    f"SUSPICIOUS - {high_count} high-severity threat(s) detected "
                    f"(limited corroboration - manual review recommended)."
                )
            elif medium_count >= 2:
                result["verdict"] = ThreatLevel.SUSPICIOUS
                result["confidence"] = 0.55
                result["summary"] = (
                    f"SUSPICIOUS - {medium_count} medium threat(s) detected "
                    f"(limited corroboration - manual review recommended)."
                )
            elif medium_count > 0:
                result["verdict"] = ThreatLevel.SUSPICIOUS
                result["confidence"] = 0.50
                result["summary"] = "SUSPICIOUS - Potential threats detected (limited corroboration)."
            elif low_count > 0:
                result["verdict"] = ThreatLevel.SUSPICIOUS
                result["confidence"] = 0.35
                result["summary"] = "SUSPICIOUS - Minor threat indicators (limited corroboration)."
            else:
                result["verdict"] = ThreatLevel.CLEAN
                result["confidence"] = 0.9
                result["summary"] = "No significant threats detected."

        # Add forensic metadata for reliability tracking
        apis_called = result.get("api_results", {}).get("apis_called", [])
        apis_expected = result.get("api_results", {}).get("apis_expected", [])
        api_status_map = result.get("api_results", {}).get("api_status", {}) or {}
        api_status_counts: Dict[str, int] = {}
        for meta in api_status_map.values():
            status = str((meta or {}).get("status", "unknown") or "unknown").lower()
            api_status_counts[status] = api_status_counts.get(status, 0) + 1

        unavailable_statuses = {"not_configured", "not_authorized", "rate_limited", "error", "skipped_local_mode"}
        available_statuses = {"checked", "clean", "no_threat"}

        result["forensic_metadata"] = {
            "evidence_sources": evidence_sources,
            "corroboration_count": corroboration_count,
            "corroboration_threshold_met": corroboration_threshold_met,
            "source_details": source_details,
            "unique_sources": list(unique_sources),
            "total_indicators": len(threats),
            "critical_indicators": critical_count,
            "high_indicators": high_count,
            "medium_indicators": medium_count,
            "low_indicators": low_count,
            "weighted_score": weighted_score,
            "heuristic_indicators": {
                "critical": heuristic_critical,
                "high": heuristic_high,
                "medium": heuristic_medium,
                "low": heuristic_low,
                "weighted_score": heuristic_weighted_score,
                "avg_confidence": round(avg_heuristic_confidence, 2),
                "max_critical_confidence": round(max_critical_confidence, 2)
            },
            "source_weighted_confidence": round(weighted_fusion_confidence, 3),
            "source_confidence_weights": self._source_confidence_weights,
            "apis_checked": len(apis_called),
            "apis_called_list": apis_called,
            "total_apis_available": len(apis_expected),
            "scan_coverage": f"{len(apis_called)}/{len(apis_expected) or 0} relevant APIs",
            "api_status": api_status_map,
            "api_status_counts": api_status_counts,
            "external_corroboration_available": (len(apis_expected) == 0) or bool(api_status_counts.get("checked", 0)),
            "external_corroboration_unavailable_reasons": [
                status for status in unavailable_statuses if api_status_counts.get(status, 0)
            ],
            "external_clean_checks": sum(api_status_counts.get(s, 0) for s in available_statuses),
        }
        
        # Enhanced: Apply Multi-API Corroboration Analysis
        try:
            api_results_dict = result.get("api_results", {})
            corroboration_analysis = corroboration_engine.analyze_corroboration(
                api_results=api_results_dict,
                threat_indicators=threats,
                input_type=result.get("input_type")
            )
            
            # Add corroboration analysis to result
            result["corroboration_analysis"] = corroboration_analysis
            
            # Override verdict if corroboration engine has higher confidence
            if corroboration_analysis['verdict']['confidence'] > result['confidence']:
                logger.debug(
                    f"Corroboration engine override: {result['verdict']} -> "
                    f"{corroboration_analysis['verdict']['classification']} "
                    f"(confidence: {result['confidence']:.2f} -> "
                    f"{corroboration_analysis['verdict']['confidence']:.2f})"
                )
                result['verdict'] = corroboration_analysis['verdict']['classification']
                result['confidence'] = corroboration_analysis['verdict']['confidence']
                result['summary'] = corroboration_analysis['verdict']['explanation']
            
            # Add actionable recommendations
            result['recommendations'] = corroboration_analysis['recommendations']
            
            # Add corroboration flags
            result['flags'] = corroboration_analysis['flags']

            # Confidence-weighted verdict fusion (local + APIs + corroboration)
            corroboration_conf = float(corroboration_analysis.get('verdict', {}).get('confidence', 0.0) or 0.0)
            fused_conf = (
                (result.get('confidence', 0.0) * 0.40)
                + (weighted_fusion_confidence * 0.30)
                + (corroboration_conf * 0.30)
            )
            result['confidence'] = max(0.0, min(1.0, round(fused_conf, 3)))
            
            logger.debug(
                f"Corroboration: {corroboration_analysis['corroboration']['level'].upper()} "
                f"({corroboration_analysis['corroboration']['source_count']} sources, "
                f"weighted score: {corroboration_analysis['corroboration']['weighted_score']:.2f})"
            )
            
        except Exception as e:
            logger.error(f"Error in corroboration analysis: {e}")
            # Continue with original verdict if corroboration fails

        # False-positive suppression feedback loop with decay-weighted trust scoring.
        try:
            fingerprint = f"{result.get('input_type','unknown')}|{result.get('summary','')[:220]}"
            suppression = security_telemetry.should_suppress_fingerprint(
                fingerprint=fingerprint,
                min_trust=0.68,
                min_margin=0.75,
                min_samples=3,
            )
            fp_score = float(suppression.get("trust_score", 0.0) or 0.0)
            if bool(suppression.get("suppress")) and str(result.get('verdict','')).lower() == 'suspicious' and float(result.get('confidence', 0.0) or 0.0) <= 0.66:
                result['verdict'] = ThreatLevel.CLEAN
                result['confidence'] = min(0.55, float(result.get('confidence', 0.0) or 0.0))
                result['summary'] = "Downgraded by feedback loop: repeated false-positive pattern detected."
                result.setdefault('flags', {})['feedback_suppressed'] = True
            result.setdefault('forensic_metadata', {})['false_positive_score'] = round(fp_score, 3)
            result.setdefault('forensic_metadata', {})['feedback_suppression'] = suppression
        except Exception:
            pass

        # Correlation engine across URL/IP/domain/hash events.
        try:
            input_type = str(result.get("input_type", "unknown"))
            input_value = str(result.get("input", ""))
            security_telemetry.record_correlation_event(
                event_type=input_type,
                event_value=input_value,
                verdict=str(result.get("verdict", "unknown")).lower(),
                confidence=float(result.get("confidence", 0.0) or 0.0),
                metadata={
                    "threats_detected": len(threats),
                    "apis_called": (result.get("api_results") or {}).get("apis_called", []),
                },
            )
            recent = security_telemetry.get_recent_events(minutes=45)
            has_phish = any(e.get("type") in {"url", "domain"} and e.get("verdict") in {"suspicious", "malicious", "critical"} for e in recent)
            has_download_hash = any(e.get("type") == "file_hash" for e in recent)
            has_c2_ip = any(e.get("type") == "ip" and e.get("verdict") in {"suspicious", "malicious", "critical"} for e in recent)
            chain = []
            if has_phish:
                chain.append("phishing")
            if has_download_hash:
                chain.append("download")
            if has_c2_ip:
                chain.append("c2")
            result.setdefault("forensic_metadata", {})["correlation_chain"] = chain
            if chain == ["phishing", "download", "c2"]:
                result.setdefault("flags", {})["attack_chain_detected"] = "phishing_download_c2"
        except Exception:
            pass

        # Unified threat-intelligence fusion summary for downstream APIs/UI/reporting.
        try:
            fusion = self._build_threat_intel_fusion(result, threats)
            result["threat_intel_fusion"] = fusion
            result.setdefault("forensic_metadata", {})["threat_intel_fusion"] = fusion
        except Exception:
            pass

        # Confidence calibration + detector-specific severity gating.
        try:
            detector_profile = self._resolve_detector_profile(result, threats)
            forensic = result.setdefault("forensic_metadata", {})
            corroboration_count = int(forensic.get("corroboration_count", 0) or 0)

            raw_conf = self._clamp01(float(result.get("confidence", 0.0) or 0.0))
            calibrated_conf = self._calibrate_confidence(raw_conf, detector_profile)
            severity_gated = self._map_severity_from_calibrated_confidence(
                calibrated_conf,
                detector_profile,
                corroboration_count,
            )

            # Apply verdict gating from calibrated severity.
            prior_verdict = str(result.get("verdict", "unknown")).lower()
            if severity_gated in {"critical", "high"}:
                result["verdict"] = ThreatLevel.MALICIOUS
            elif severity_gated == "medium":
                result["verdict"] = ThreatLevel.SUSPICIOUS
            else:
                if prior_verdict == "clean":
                    result["verdict"] = ThreatLevel.CLEAN
                else:
                    result["verdict"] = ThreatLevel.SUSPICIOUS

            result["confidence"] = round(calibrated_conf, 3)
            forensic["calibration"] = {
                "detector_profile": detector_profile,
                "confidence_raw": round(raw_conf, 3),
                "confidence_calibrated": round(calibrated_conf, 3),
                "severity_gated": severity_gated,
                "source_count": corroboration_count,
                "profiles": self._detector_threshold_profiles,
            }

            if corroboration_count < 2 and severity_gated in {"high", "critical"} and calibrated_conf < 0.94:
                result.setdefault("flags", {})["manual_review_required"] = True
                result["summary"] = (
                    "SUSPICIOUS - Single-source high-risk signal detected. "
                    "Manual review required before high-severity escalation."
                )

            explainability = self._build_explainability_block(result, threats, detector_profile)
            forensic["explainability"] = explainability
            result["explainability"] = explainability

            report_quality = self._build_report_quality_checks(result)
            result["report_quality_checks"] = report_quality
            forensic["report_quality_checks"] = report_quality
        except Exception as calibration_exc:
            logger.warning(f"Calibration/gating stage failed: {calibration_exc}")

        advanced_forensic = self._build_advanced_forensic_analysis(
            result=result,
            threats=threats,
            corroboration_analysis=result.get("corroboration_analysis"),
        )
        result["forensic_metadata"]["advanced_analysis"] = advanced_forensic
        result["forensic_analysis"] = advanced_forensic

        # Apply alert suppression for non-clean results
        if result.get("verdict") != ThreatLevel.CLEAN:
            should_suppress, suppression_reason = alert_suppression_engine.should_suppress_alert(result)
            if should_suppress:
                logger.info(f"Alert suppressed for {value}: {suppression_reason}")
                result["suppressed"] = True
                result["suppression_reason"] = suppression_reason
                result["verdict"] = ThreatLevel.CLEAN
                result["confidence"] = max(0.1, result.get("confidence", 0.0) * 0.3)  # Reduce confidence
                result["summary"] = f"Alert suppressed: {suppression_reason}"
                # Add suppression metadata
                result.setdefault("forensic_metadata", {})["alert_suppression"] = {
                    "suppressed": True,
                    "reason": suppression_reason,
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                # Record the alert for future deduplication
                alert_suppression_engine.record_alert(result)

        return result


# Global instance
threat_analyzer = ThreatAnalyzer()
