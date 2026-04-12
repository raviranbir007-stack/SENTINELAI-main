"""
PDF Report Generator using Gemini API
Generates AI-analyzed threat reports in PDF format
"""

import asyncio
import importlib.util
import ipaddress
import json
import logging
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from collections import OrderedDict, Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Optional
import time
from zoneinfo import ZoneInfo

try:
    from ..config import settings
except Exception:
    settings = None

try:
    import google.genai as genai
    from google.genai.types import GenerateContentConfig

    GEMINI_AVAILABLE = True
except ImportError:
    try:
        import google.generativeai as genai

        GEMINI_AVAILABLE = True
    except ImportError:
        GEMINI_AVAILABLE = False

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


logger = logging.getLogger(__name__)

if GEMINI_AVAILABLE is False:
    logger.warning(
        "google.genai or google-generativeai not installed. Install with: pip install google-genai or pip install google-generativeai"
    )
if REPORTLAB_AVAILABLE is False:
    logger.warning("reportlab not installed. Install with: pip install reportlab")


class ReportGenerator:
    """Generate AI-analyzed threat reports in PDF format"""

    def __init__(self):
        csv_key_candidates = []
        for csv_env_name in ("GEMINI_API_KEYS", "GOOGLE_API_KEYS"):
            csv_raw = os.getenv(csv_env_name, "")
            if csv_raw:
                csv_key_candidates.extend([item.strip() for item in csv_raw.split(",") if item.strip()])

        key_candidates = [
            (getattr(settings, "GEMINI_API_KEY", "") if settings else ""),
            os.getenv("GEMINI_API_KEY", ""),
            os.getenv("GOOGLE_API_KEY", ""),
            *csv_key_candidates,
        ]
        for idx in range(1, 21):
            key_candidates.append(os.getenv(f"GEMINI_API_KEY_{idx}", ""))
            key_candidates.append(os.getenv(f"GOOGLE_API_KEY_{idx}", ""))

        self.gemini_keys = []
        seen_keys = set()
        for raw in key_candidates:
            value = str(raw or "").strip()
            if not value:
                continue
            if value in seen_keys:
                continue
            seen_keys.add(value)
            self.gemini_keys.append(value)

        self.gemini_key = self.gemini_keys[0] if self.gemini_keys else ""
        self.initialized = False
        # Circuit-breaker & retry configuration (env-configurable)
        # Keep retries conservative but non-zero for transient provider failures.
        try:
            self.gemini_max_attempts = int(os.getenv("GEMINI_MAX_ATTEMPTS", "3"))
        except Exception:
            self.gemini_max_attempts = 3
        self.gemini_max_attempts = max(1, min(self.gemini_max_attempts, 5))
        try:
            self.circuit_threshold = int(os.getenv("GEMINI_CIRCUIT_THRESHOLD", "5"))
        except Exception:
            self.circuit_threshold = 5
        try:
            self.circuit_open_seconds = int(os.getenv("GEMINI_CIRCUIT_OPEN_SECONDS", "60"))
        except Exception:
            self.circuit_open_seconds = 60

        self._failure_count = 0
        self._circuit_open_until = 0
        self._last_circuit_notice_at = 0.0
        self._last_gemini_failure_reason = ""
        self._quota_cooldown_until = 0.0
        self._last_quota_warning_at = 0.0
        self._analysis_cache: OrderedDict[str, tuple[float, str]] = OrderedDict()
        try:
            self._analysis_cache_ttl = int(os.getenv("GEMINI_ANALYSIS_CACHE_TTL_SECONDS", "1800"))
        except Exception:
            self._analysis_cache_ttl = 1800
        self._analysis_cache_ttl = max(60, self._analysis_cache_ttl)
        try:
            self._analysis_cache_size = int(os.getenv("GEMINI_ANALYSIS_CACHE_SIZE", "64"))
        except Exception:
            self._analysis_cache_size = 64
        self._analysis_cache_size = max(8, self._analysis_cache_size)
        try:
            self.gemini_daily_report_limit = int(os.getenv("GEMINI_DAILY_REPORT_LIMIT", "50"))
        except Exception:
            self.gemini_daily_report_limit = 50
        self.gemini_daily_report_limit = max(1, self.gemini_daily_report_limit)
        try:
            self.gemini_hourly_report_limit = int(os.getenv("GEMINI_HOURLY_REPORT_LIMIT", "12"))
        except Exception:
            self.gemini_hourly_report_limit = 12
        self.gemini_hourly_report_limit = max(1, self.gemini_hourly_report_limit)
        self.gemini_exec_only = str(os.getenv("GEMINI_EXECUTIVE_ONLY", "false")).strip().lower() in {"1", "true", "yes", "on"}
        try:
            self.gemini_quota_cooldown_seconds = int(os.getenv("GEMINI_QUOTA_COOLDOWN_SECONDS", "900"))
        except Exception:
            self.gemini_quota_cooldown_seconds = 900
        self.gemini_quota_cooldown_seconds = max(60, self.gemini_quota_cooldown_seconds)
        try:
            self.gemini_request_timeout_seconds = float(os.getenv("GEMINI_REQUEST_TIMEOUT_SECONDS", "45"))
        except Exception:
            self.gemini_request_timeout_seconds = 45.0
        self.gemini_request_timeout_seconds = max(10.0, min(self.gemini_request_timeout_seconds, 120.0))
        
        # Rate limiter: configurable request spacing to reduce provider throttling.
        self._last_request_time = 0
        try:
            self._min_request_interval = float(os.getenv("GEMINI_MIN_REQUEST_INTERVAL", "2.0"))
        except Exception:
            self._min_request_interval = 2.0
        self._min_request_interval = max(0.2, self._min_request_interval)

        model_candidates = os.getenv(
            "GEMINI_MODEL_CANDIDATES",
            "gemini-2.5-flash,gemini-2.5-pro,gemini-2.0-flash"
        )
        self.gemini_model_candidates = [m.strip() for m in model_candidates.split(",") if m.strip()]
        if not self.gemini_model_candidates:
            self.gemini_model_candidates = ["gemini-2.5-flash"]

        if GEMINI_AVAILABLE and self.gemini_keys:
            try:
                # Prefer older `configure` call when available (legacy package)
                if hasattr(genai, "configure"):
                    genai.configure(api_key=self.gemini_keys[0])
                    self.initialized = True
                    logger.info("Gemini API initialized successfully (legacy client)")
                # Newer `google.genai` provides a `client.Client` class
                elif hasattr(genai, "Client") or (hasattr(genai, "client") and hasattr(genai.client, "Client")):
                    # We don't need to call configure; client will accept api_key at call time
                    self.initialized = True
                    logger.info("Gemini API available via google.genai client")
                else:
                    logger.warning("Gemini client present but no supported initializer found")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini: {str(e)}")

    async def generate_analysis_report(
        self, threat_analysis: Dict[str, Any], output_filename: Optional[str] = None
    ) -> Optional[bytes]:
        """
        Generate a comprehensive, security-hardened AI-analyzed threat report with full scan results, forensic reliability, and digital integrity.
        """
        import hashlib
        if not REPORTLAB_AVAILABLE:
            logger.warning("reportlab not installed. Returning text fallback instead of PDF.")
            ai_analysis = await self._generate_ai_analysis(threat_analysis)
            scan_results = self._format_scan_results_section(threat_analysis)
            forensic_summary = self._format_forensic_summary(threat_analysis)
            text_report = f"{ai_analysis}\n\n---\n\nSCAN RESULTS\n\n{scan_results}\n\nFORENSIC SUMMARY\n\n{forensic_summary}"
            digest = hashlib.sha256(text_report.encode("utf-8")).hexdigest()
            text_report += f"\n\n[Report Integrity Hash: {digest}]"
            return text_report.encode("utf-8")

        try:
            ai_analysis = await self._generate_ai_analysis(threat_analysis)
            pdf_bytes = self._create_pdf_report(threat_analysis, ai_analysis)
            if pdf_bytes:
                digest = hashlib.sha256(pdf_bytes).hexdigest()
                logger.info(f"Generated report hash: {digest}")
            return pdf_bytes
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            try:
                fallback_text = self._get_fallback_analysis(threat_analysis)
                if REPORTLAB_AVAILABLE:
                    fallback_pdf = self._create_pdf_report(threat_analysis, fallback_text)
                    if fallback_pdf:
                        return fallback_pdf

                scan_results = self._format_scan_results_section(threat_analysis)
                forensic_summary = self._format_forensic_summary(threat_analysis)
                text_report = f"{fallback_text}\n\n---\n\nSCAN RESULTS\n\n{scan_results}\n\nFORENSIC SUMMARY\n\n{forensic_summary}"
                return text_report.encode("utf-8", "replace")
            except Exception as fallback_error:
                logger.error(f"Fallback report generation also failed: {fallback_error}")
                return None

    async def generate_comprehensive_interval_report(
        self, threat_analysis: Dict[str, Any]
    ) -> Optional[bytes]:
        """
        Generate a comprehensive multi-interval report with distinct 24h, 7d, 30d analysis sections.
        Perfect for comparing immediate vs. trending vs. strategic threat postures.
        """
        import hashlib
        if not REPORTLAB_AVAILABLE:
            logger.warning("reportlab not installed. Using standard report instead.")
            return await self.generate_analysis_report(threat_analysis)

        try:
            # Generate AI analysis once for all intervals (reusable context)
            ai_analysis = await self._generate_ai_analysis(threat_analysis)
            
            # Create the comprehensive interval report
            pdf_bytes = self._create_comprehensive_interval_report(threat_analysis, ai_analysis)
            
            if pdf_bytes:
                digest = hashlib.sha256(pdf_bytes).hexdigest()
                logger.info(f"Generated comprehensive interval report hash: {digest}")
                return pdf_bytes
            else:
                logger.warning("Comprehensive interval report returned None, falling back to standard report")
                return await self.generate_analysis_report(threat_analysis)
                
        except Exception as e:
            logger.error(f"Error generating comprehensive interval report: {str(e)}")
            # Fall back to standard report
            try:
                return await self.generate_analysis_report(threat_analysis)
            except Exception as fallback_error:
                logger.error(f"Fallback to standard report also failed: {fallback_error}")
                return None

    def _format_scan_results_section(self, threat_analysis: Dict[str, Any]) -> str:
        """Format a clear, detailed scan results section for the report."""
        from .threat_analyzer import ALL_EXTERNAL_APIS
        api_results = threat_analysis.get("api_results", {})
        api_status = api_results.get("api_status", {})
        apis_called = api_results.get("apis_called", [])
        apis_expected = api_results.get("apis_expected", [api["name"] for api in ALL_EXTERNAL_APIS])
        coverage = self._build_detection_coverage_overview(threat_analysis)
        lines = [f"APIs Expected: {', '.join(apis_expected)}"]
        lines.append(f"APIs Called: {', '.join(apis_called)}")
        lines.append(f"Detection Mode: {coverage.get('mode', 'unknown').replace('_', ' ').title()}")
        if coverage.get("method_names"):
            lines.append(f"Local Methods: {', '.join(coverage.get('method_names', [])[:12])}")
        if coverage.get("api_summary"):
            lines.append(f"Coverage Summary: {coverage.get('api_summary')}")
        if coverage.get("fallback_reason"):
            lines.append(f"Fallback Reason: {coverage.get('fallback_reason')}")
        lines.append("")
        # Add explicit API coverage explanation if present (for test/demo domains)
        explanation = threat_analysis.get("api_coverage_explanation")
        if explanation:
            lines.append(f"API Coverage Note: {explanation}")
        # Always show all 5 APIs, with suitability/applicability and status
        for api in ALL_EXTERNAL_APIS:
            key = api["key"]
            name = api["name"]
            meta = api_status.get(key, {})
            status = str(meta.get("status", "unknown") or "unknown").strip().lower()
            configured = meta.get("configured", False)
            applicable = meta.get("applicable", False)
            error = meta.get("error")
            if status in {"success", "completed", "ok", "checked", "online", "available", "clean", "no_threat"}:
                status_str = "provider data collected"
            elif status in {"rate_limited", "quota_exceeded"}:
                status_str = "collection throttled; fallback intelligence applied"
            elif status in {"failed", "error", "timeout"}:
                status_str = "collection failed; fallback intelligence applied"
            elif status in {"pending", "in_progress", "queued"}:
                status_str = "provider analysis did not complete in this scan window"
            elif status == "skipped_local_mode":
                status_str = "external APIs disabled for local-only analysis"
            else:
                reasons = []
                if not configured:
                    reasons.append("provider key missing")
                if not applicable:
                    reasons.append("indicator outside provider scope")
                if explanation and status == "not_applicable":
                    reasons.append("test/demo domain handling")
                status_str = f"fallback intelligence applied ({'; '.join(reasons) if reasons else 'provider unavailable'})"
            lines.append(f"- {name}: {status_str}{' | error: ' + error if error else ''}")
        lines.append("")
        threats = threat_analysis.get("threat_indicators", [])
        if threats:
            lines.append(f"Threat Indicators Detected: {len(threats)}")
            for t in threats:
                src = t.get("source", "?")
                sev = t.get("severity", "?")
                ind = t.get("indicator", "?")
                lines.append(f"  - [{sev}] {src}: {ind}")
        else:
            lines.append("No threat indicators detected.")
        return "\n".join(lines)

    def _format_forensic_summary(self, threat_analysis: Dict[str, Any]) -> str:
        """Format a forensic reliability and evidence summary for the report."""
        forensic = threat_analysis.get("forensic_metadata", {})
        coverage = self._build_detection_coverage_overview(threat_analysis)
        lines = []
        lines.append(f"Corroboration Count: {forensic.get('corroboration_count', 0)}")
        lines.append(f"Corroboration Threshold Met: {forensic.get('corroboration_threshold_met', False)}")
        lines.append(f"APIs Checked: {forensic.get('apis_checked', 0)} / {forensic.get('total_apis_available', 0)}")
        lines.append(f"Scan Coverage: {forensic.get('scan_coverage', '')}")
        lines.append(f"Detection Mode: {coverage.get('mode', 'unknown').replace('_', ' ').title()}")
        if coverage.get("method_names"):
            lines.append(f"Local Methods: {', '.join(coverage.get('method_names', [])[:12])}")
        if coverage.get("fallback_reason"):
            lines.append(f"Fallback Reason: {coverage.get('fallback_reason')}")
        quality = threat_analysis.get("report_quality_checks") or forensic.get("report_quality_checks") or {}
        if quality:
            lines.append(f"Report QA Passed: {bool(quality.get('ok', False))}")
            warnings = quality.get("warnings") or []
            if warnings:
                lines.append("Report QA Warnings:")
                for warning in warnings:
                    lines.append(f"- {warning}")
        details = forensic.get("source_details", [])
        if details:
            lines.append("\nEvidence Table:")
            for d in details:
                src = d.get("source", "?")
                sev = d.get("severity", "?")
                ind = d.get("indicator", "?")
                ts = d.get("timestamp", "?")
                lines.append(f"- {src} | {sev} | {ind} | {ts}")
        return "\n".join(lines)

    def _build_behavioral_sequence(self, threat_analysis: Dict[str, Any]) -> list[Dict[str, Any]]:
        """Return a normalized chronological sequence for behavioral and network evidence."""
        forensic = threat_analysis.get("forensic_metadata", {}) or {}
        sequence = threat_analysis.get("behavioral_sequence") or forensic.get("behavioral_sequence") or []
        normalized: list[Dict[str, Any]] = []
        seen = set()

        def add_event(timestamp: str, stage: str, source: str, details: str, confidence: float = 0.0) -> None:
            normalized_timestamp = str(timestamp or "").strip() or "unknown"
            key = (normalized_timestamp, stage, source, details)
            if key in seen:
                return
            seen.add(key)
            normalized.append(
                {
                    "timestamp": normalized_timestamp,
                    "stage": stage,
                    "source": source,
                    "details": details,
                    "confidence": round(float(confidence or 0.0), 3),
                }
            )

        if isinstance(sequence, list) and sequence:
            for item in sequence:
                if not isinstance(item, dict):
                    continue
                add_event(
                    item.get("timestamp"),
                    str(item.get("stage", "telemetry")),
                    str(item.get("source", "unknown")),
                    str(item.get("details", "")),
                    float(item.get("confidence", 0.0) or 0.0),
                )
        else:
            for detail in forensic.get("source_details", []) or []:
                if not isinstance(detail, dict):
                    continue
                add_event(
                    detail.get("timestamp"),
                    "corroboration",
                    str(detail.get("source", "unknown")),
                    str(detail.get("indicator", detail.get("details", ""))),
                    float(detail.get("score", detail.get("confidence", 0.0)) or 0.0),
                )

            behavioral = threat_analysis.get("behavioral_analysis", {}) or {}
            for index, behavior in enumerate(behavioral.get("behaviors_detected", []) or [], start=1):
                add_event(
                    threat_analysis.get("timestamp"),
                    f"behavioral_signal_{index}",
                    "behavioral_analysis",
                    str(behavior),
                    float(behavioral.get("score", 0.0) or 0.0),
                )

            network = threat_analysis.get("network_analysis", {}) or {}
            for item in network.get("suspicious_connections", []) or []:
                if not isinstance(item, dict):
                    continue
                add_event(
                    item.get("timestamp") or threat_analysis.get("timestamp"),
                    "network_activity",
                    str(item.get("process", item.get("source", "network"))),
                    f"{item.get('remote_ip', 'unknown')}:{item.get('remote_port', 'n/a')} | {item.get('reason', item.get('risk', 'unknown'))}",
                    float(item.get("confidence", 0.0) or 0.0),
                )

            for index, stage in enumerate(forensic.get("correlation_chain", []) or [], start=1):
                add_event(
                    threat_analysis.get("timestamp"),
                    f"attack_chain_step_{index}",
                    "correlation_chain",
                    str(stage),
                    float(threat_analysis.get("confidence", 0.0) or 0.0),
                )

        normalized.sort(key=lambda item: (str(item.get("timestamp", "unknown")), str(item.get("stage", ""))))
        return normalized[:20]

    def _format_behavioral_sequence(self, threat_analysis: Dict[str, Any]) -> str:
        sequence = self._build_behavioral_sequence(threat_analysis)
        if not sequence:
            return "No behavioral sequence data available."

        report_timezone = self._resolve_timezone_name(threat_analysis)
        lines = []
        for index, event in enumerate(sequence, start=1):
            lines.append(
                f"{index}. {self._format_timestamp_for_report(event.get('timestamp', 'unknown'), report_timezone)} | {event.get('stage', 'telemetry')} | {event.get('source', 'unknown')} | {event.get('details', '')}"
            )
        return "\n".join(lines)

    def _normalize_interval(self, interval: str) -> tuple[str, int]:
        value = str(interval or "24h").strip().lower()
        hours_map = {"24h": 24, "7d": 168, "30d": 720}
        return value, hours_map.get(value, 24)

    def _build_interval_summaries(self, threat_analysis: Dict[str, Any]) -> list[Dict[str, Any]]:
        intervals = threat_analysis.get("intervals") or ["24h"]
        summaries: list[Dict[str, Any]] = []

        for interval in intervals:
            label, hours = self._normalize_interval(interval)
            activity = {}
            vulns = {}

            try:
                from .activity_database import activity_db

                activity = activity_db.get_activity_summary(hours=hours) or {}
            except Exception as exc:
                logger.debug(f"Could not load activity summary for {label}: {exc}")

            try:
                vuln_summary = self._get_endpoint_vuln_summary(hours=hours)
                vulns = vuln_summary or {}
            except Exception as exc:
                logger.debug(f"Could not load vuln summary for {label}: {exc}")

            summaries.append(
                {
                    "interval": label,
                    "hours": hours,
                    "activity": activity,
                    "vulns": vulns,
                }
            )

        return summaries

    def _format_interval_summary_text(self, threat_analysis: Dict[str, Any]) -> str:
        summaries = threat_analysis.get("interval_summaries") or self._build_interval_summaries(threat_analysis)
        if not summaries:
            return "No interval summaries available."

        lines = []
        for summary in summaries:
            activity = summary.get("activity") or {}
            vulns = summary.get("vulns") or {}
            interval = str(summary.get("interval", "24h")).upper()
            lines.append(
                f"{interval}: threat scans {activity.get('threat_scans', 0)}, threats detected {activity.get('threats_detected', 0)}, "
                f"websites {activity.get('websites_visited', 0)}, applications {activity.get('applications_launched', 0)}, "
                f"network connections {activity.get('network_connections', 0)}, endpoint vulnerabilities {vulns.get('total', 0) if isinstance(vulns, dict) else 0}."
            )

        return "\n".join(lines)

    def _normalize_report_type(self, report_type: str) -> str:
        value = str(report_type or "executive_summary").strip().lower().replace("-", "_").replace(" ", "_")
        if value in {"technical", "technical_report", "technical_analysis", "soc_technical", "engineering"}:
            return "technical_analysis"
        if value in {"forensic", "forensic_analysis", "digital_forensics", "forensic_investigation", "investigation", "digital_investigation"}:
            return "forensic_investigation"
        if value in {"executive", "executive_report", "executive_summary", "leadership"}:
            return "executive_summary"
        return "executive_summary"

    def _infer_indicator_type(self, indicator_value: Any, source: str = "") -> str:
        value = str(indicator_value or "").strip()
        source_text = str(source or "").lower()
        if not value:
            return "Unknown"

        try:
            ipaddress.ip_address(value)
            return "IP"
        except Exception:
            pass

        lower = value.lower()
        if lower.startswith(("http://", "https://", "hxxp://", "hxxps://")):
            return "URL"

        if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value):
            return "File"

        if re.fullmatch(r"(?=.{1,253}$)(?:[a-zA-Z0-9-]{1,63}\.)+[A-Za-z]{2,63}", value):
            return "Domain"

        if any(token in source_text for token in ("ip", "network", "abuseipdb", "shodan")):
            return "IP"
        if any(token in source_text for token in ("url", "web", "domain", "urlscan")):
            return "URL"
        if any(token in source_text for token in ("hash", "file", "artifact", "virustotal")):
            return "File"
        return "Unknown"

    def _normalize_confidence(self, value: Any) -> float:
        try:
            conf = float(value or 0.0)
        except (TypeError, ValueError):
            return 0.0
        if conf > 1.0:
            conf = conf / 100.0
        return max(0.0, min(conf, 1.0))

    def _status_from_severity(self, severity: str) -> str:
        sev = str(severity or "unknown").lower()
        if sev in {"critical", "high", "malicious"}:
            return "malicious"
        if sev in {"medium", "suspicious"}:
            return "suspicious"
        if sev in {"safe", "clean", "low", "benign"}:
            return "safe"
        return "suspicious"

    def _infer_attack_type(self, indicator_type: str, indicator_value: str, severity: str, source: str) -> str:
        text = f"{indicator_value} {source}".lower()
        if any(token in text for token in ("phish", "credential", "login", "bank", "invoice", "spoof")):
            return "phishing"
        if any(token in text for token in ("c2", "cnc", "beacon", "callback", "botnet", "command-and-control")):
            return "c2"
        if any(token in text for token in ("dropper", "payload", "malware", "trojan", "ransom")):
            return "malware_delivery"
        if indicator_type == "File":
            return "malware_delivery"
        if indicator_type == "IP" and str(severity or "").lower() in {"critical", "malicious", "high"}:
            return "c2"
        if indicator_type in {"URL", "Domain"}:
            return "phishing"
        return "unknown"

    def _api_status_text(self, api_results: Dict[str, Any], api_key: str) -> str:
        api_status = api_results.get("api_status", {}) if isinstance(api_results, dict) else {}
        meta = api_status.get(api_key, {}) if isinstance(api_status, dict) else {}
        if not isinstance(meta, dict) or not meta:
            return "intelligence fallback active (reason: telemetry-only analysis, provider metadata missing)"
        status = str(meta.get("status", "not_executed") or "not_executed").strip().lower()
        configured = bool(meta.get("configured", False))
        applicable = bool(meta.get("applicable", False))
        if status in {"success", "completed", "ok", "checked", "online", "available", "clean", "no_threat"}:
            return "provider data collected successfully"
        if status == "skipped_local_mode":
            return "intelligence fallback active (reason: external APIs disabled for local-only analysis)"

        reasons = []
        if not configured:
            reasons.append("provider key not configured in environment")
        if not applicable:
            reasons.append("indicator type is outside provider coverage")
        if status in {"rate_limited", "quota_exceeded"}:
            reasons.append("provider quota or rate limit reached")
        if status in {"pending", "in_progress", "queued"}:
            reasons.append("provider analysis did not complete in this scan window")
        if status in {"timeout", "error", "failed"}:
            reasons.append("provider request failed during collection")
        if not reasons:
            reasons.append(f"provider returned unrecognized status: {status}")

        return f"intelligence fallback active (reason: {'; '.join(reasons)})"

    def _generate_fallback_intelligence(self, indicator_value: str, indicator_type: str, threat_set: list[Dict]) -> Dict[str, str]:
        """Generate fallback intelligence when APIs are unavailable."""
        intelligence = {}
        
        # GeoIP and ASN inference for IPs
        if indicator_type == "IP":
            try:
                ip_obj = ipaddress.ip_address(indicator_value)
                if ip_obj.is_private:
                    intelligence["geoip_status"] = "Private IP range (RFC 1918)"
                    intelligence["asn_inference"] = "Internal network or VPN"
                elif ip_obj.is_loopback:
                    intelligence["geoip_status"] = "Loopback address"
                else:
                    intelligence["geoip_status"] = f"Public IP - requires external GeoIP lookup"
                    intelligence["asn_inference"] = "ASN inference pending API availability"
            except:
                pass
        
        # Domain pattern analysis
        if indicator_type in {"Domain", "URL"}:
            lower_val = indicator_value.lower()
            suspicious_tlds = {".xyz", ".tk", ".ml", ".ga", ".ru", ".cn", ".ir"}
            suspicious_keywords = ["secure", "verify", "login", "update", "confirm", "authenticate", "signin", "bank", "paypal"]
            
            for tld in suspicious_tlds:
                if lower_val.endswith(tld):
                    intelligence["domain_tld_risk"] = f"Suspicious TLD detected: {tld}"
                    break
            
            for keyword in suspicious_keywords:
                if keyword in lower_val:
                    intelligence["phishing_indicator"] = f"Phishing keyword detected: {keyword}"
                    break
            
            if "xn--" in lower_val:
                intelligence["domain_homograph_risk"] = "Possible homograph/IDN abuse detected"
        
        # Behavioral classification based on scan set
        repetition_count = sum(1 for scan in threat_set if str(scan.get("indicator_value", "")) == indicator_value)
        if repetition_count > 3:
            intelligence["behavioral_pattern"] = f"Repeated indicator ({repetition_count} times) suggests automated scanning or C2 beaconing"
        elif repetition_count > 1:
            intelligence["behavioral_pattern"] = f"Repeated indicator ({repetition_count} times) suggests possible persistence attempt"
        
        return intelligence

    def _detect_repetition_pattern(self, indicator_value: str, scans: list[Dict], scan_timestamps: list) -> Dict[str, Any]:
        """Detect repetition patterns in threat indicators."""
        pattern = {
            "count": 0,
            "first_seen": None,
            "last_seen": None,
            "is_repeated": False,
            "frequency_classification": "single_occurrence",
            "timeline_gaps": [],
        }
        
        matching_scans = [(i, scan) for i, scan in enumerate(scans) if str(scan.get("indicator_value", "")) == indicator_value]
        if not matching_scans:
            return pattern
        
        pattern["count"] = len(matching_scans)
        pattern["is_repeated"] = len(matching_scans) > 1
        
        if matching_scans:
            pattern["first_seen"] = matching_scans[0][1].get("timestamp")
            pattern["last_seen"] = matching_scans[-1][1].get("timestamp")
        
        if pattern["is_repeated"]:
            if pattern["count"] >= 5:
                pattern["frequency_classification"] = "high_frequency_persistence"
            elif pattern["count"] >= 3:
                pattern["frequency_classification"] = "medium_frequency_scanning"
            else:
                pattern["frequency_classification"] = "low_frequency_recurrence"
        
        return pattern

    def _analyze_domain_pattern(self, indicator_value: str) -> Dict[str, str]:
        """Analyze domain structure for impersonation and phishing patterns."""
        analysis = {}
        
        if not indicator_value or "." not in indicator_value:
            return analysis
        
        lower_val = indicator_value.lower()
        parts = lower_val.split(".")
        
        # Check for homograph/similar domain attacks
        homograph_risk_chars = ["0", "l", "1", "o", "i"]  # Similar looking characters
        for part in parts[:-1]:
            for char in homograph_risk_chars:
                if char in part:
                    if analysis.get("homograph_risk") is None:
                        analysis["homograph_risk"] = f"Possible homograph attack - similar characters present"
        
        # Check subdomain depth (deeper could indicate CDN abuse or subdomain takeover)
        if len(parts) > 3:
            analysis["subdomain_depth"] = f"Deep subdomain structure ({len(parts)} levels) - possible subdomain takeover or advanced evasion"
        
        # Check for brand impersonation patterns
        impersonation_brands = ["microsoft", "apple", "google", "amazon", "paypal", "bank", "admin", "support"]
        for brand in impersonation_brands:
            if brand in lower_val and lower_val != f"{brand}.com":
                analysis["brand_impersonation_risk"] = f"Possible impersonation of {brand.title()}"
                break
        
        return analysis

    def _generate_detection_reason(self, indicator_value: str, indicator_type: str, status: str, severity: str, 
                                    repetition: Dict[str, Any], api_data: Dict[str, Any]) -> str:
        """Generate structured, meaningful detection reason."""
        reason_parts = []
        
        # Base classification
        reason_parts.append(f"Indicator classified as {status.upper()}")
        
        # Severity context
        if severity:
            reason_parts.append(f"due to {severity.upper()} severity assessment")
        
        # API-driven intelligence
        api_evidence = []
        if isinstance(api_data.get("virustotal"), dict) and api_data["virustotal"].get("malicious", 0) > 0:
            api_evidence.append(f"VirusTotal: {api_data['virustotal'].get('malicious')} malicious detections")
        if isinstance(api_data.get("abuseipdb"), dict) and api_data["abuseipdb"].get("abuse_confidence", 0) > 50:
            api_evidence.append(f"AbuseIPDB: {api_data['abuseipdb'].get('abuse_confidence')}% abuse confidence")
        if isinstance(api_data.get("shodan"), dict) and api_data["shodan"].get("vulnerabilities", 0) > 0:
            api_evidence.append(f"Shodan: {api_data['shodan'].get('vulnerabilities')} known vulnerabilities")
        if isinstance(api_data.get("urlscan"), dict) and api_data["urlscan"].get("malicious", False):
            api_evidence.append("URLScan: Classified as malicious")
        if isinstance(api_data.get("hybrid_analysis"), dict) and api_data["hybrid_analysis"].get("threat_score", 0) > 70:
            api_evidence.append(f"Hybrid Analysis: Threat score {api_data['hybrid_analysis'].get('threat_score')}/100")
        
        if api_evidence:
            reason_parts.append(f"Corroborated by: {'; '.join(api_evidence)}")
        else:
            reason_parts.append("Local telemetry and heuristic analysis applied")
        
        # Repetition intelligence
        if repetition.get("is_repeated"):
            reason_parts.append(f"Observed {repetition['count']} times in scan window ({repetition['frequency_classification']})")
        
        return ". ".join(reason_parts) + "."

    def _generate_behavior_pattern(self, indicator_value: str, indicator_type: str, attack_type: str,
                                   repetition: Dict[str, Any], scans: list[Dict]) -> str:
        """Generate real inferred behavior description."""
        patterns = []
        
        if attack_type and attack_type != "unknown":
            patterns.append(f"Classified attack pattern: {attack_type.replace('_', ' ').title()}")
        
        if indicator_type == "IP":
            if repetition.get("frequency_classification") == "high_frequency_persistence":
                patterns.append(f"High-frequency repeated access to {indicator_value} indicates possible command-and-control (C2) beaconing or automated scanning activity")
            elif repetition.get("frequency_classification") == "medium_frequency_scanning":
                patterns.append(f"Medium-frequency repeated access suggests reconnaissance or brute-force attempt")
            elif repetition.get("is_repeated"):
                patterns.append(f"Multiple connections to {indicator_value} within observation window suggest persistent external interaction")
            else:
                patterns.append(f"Single detected connection to external IP {indicator_value} warrants monitoring for potential lateral movement")
        
        elif indicator_type == "Domain":
            if repetition.get("is_repeated"):
                patterns.append(f"Repeated DNS resolution or HTTP requests to {indicator_value} - possible malware C2 or credential harvesting campaign")
                if repetition["count"] >= 5:
                    patterns.append("High frequency suggests automated malware callback behavior")
            else:
                patterns.append(f"Single access to suspicious domain {indicator_value} - possible user compromise or drive-by download")
        
        elif indicator_type == "URL":
            patterns.append(f"Detected access to suspicious URL path - potential credential harvesting or exploit delivery vector")
            if "/login" in indicator_value.lower() or "/auth" in indicator_value.lower():
                patterns.append("URL path structure suggests credential harvesting attack")
            elif ".exe" in indicator_value.lower() or ".zip" in indicator_value.lower():
                patterns.append("Executable or archive delivery detected - possible malware distribution")
        
        elif indicator_type == "File":
            patterns.append(f"File hash detected in execution or download context")
            if "ransom" in attack_type.lower():
                patterns.append("Behavioral signature consistent with ransomware family")
            elif "trojan" in attack_type.lower():
                patterns.append("Behavioral signature consistent with trojan family")
        
        if not patterns:
            patterns.append(f"Detected {indicator_type.lower()} indicator with suspicious characteristics")
        
        return " | ".join(patterns)

    def _generate_payload_characteristics(self, indicator_value: str, indicator_type: str,
                                         api_data: Dict[str, Any], has_api_coverage: bool) -> str:
        """Analyze delivery method and attack intent from available data."""
        characteristics = []
        
        if indicator_type == "URL":
            if "/admin" in indicator_value.lower() or "/config" in indicator_value.lower():
                characteristics.append("Admin interface access attempt - possible privilege escalation")
            if "/steal" in indicator_value.lower() or "/exfil" in indicator_value.lower():
                characteristics.append("Data exfiltration endpoint detected")
            if re.search(r"\.(exe|zip|iso|bat|cmd|ps1|vbs)$", indicator_value.lower()):
                characteristics.append("Direct executable delivery vector")
            if "callback" in indicator_value.lower() or "beacon" in indicator_value.lower():
                characteristics.append("C2 callback or beacon endpoint signature")
        
        elif indicator_type == "File":
            vt_data = api_data.get("virustotal", {})
            if isinstance(vt_data, dict):
                malicious_count = vt_data.get("malicious", 0)
                if malicious_count > 30:
                    characteristics.append(f"File detected as malicious by {malicious_count} security vendors - strong indicator")
                elif malicious_count > 10:
                    characteristics.append(f"File flagged by {malicious_count} vendors - concerning pattern")
            
            if "ransom" in indicator_value.lower():
                characteristics.append("Filename suggests ransomware variant")
            if "crack" in indicator_value.lower() or "keygen" in indicator_value.lower():
                characteristics.append("Software piracy/tool delivery detected")
        
        elif indicator_type == "IP":
            shodan_data = api_data.get("shodan", {})
            if isinstance(shodan_data, dict):
                if shodan_data.get("open_ports", 0) > 0:
                    characteristics.append(f"IP has {shodan_data.get('open_ports')} open ports - possible exposed service")
                if shodan_data.get("vulnerabilities", 0) > 0:
                    characteristics.append(f"{shodan_data.get('vulnerabilities')} known CVEs associated - active exploitation risk")
            
            abuse_data = api_data.get("abuseipdb", {})
            if isinstance(abuse_data, dict) and abuse_data.get("total_reports", 0) > 10:
                characteristics.append(f"IP reported {abuse_data.get('total_reports')} times - widespread abuse history")
        
        if not characteristics:
            if has_api_coverage:
                characteristics.append("Malware analysis: File/Domain characteristics inferred from telemetry correlation")
            else:
                characteristics.append("Fallback analysis applied - API data availability limited, using heuristic and local telemetry context")
        
        return " | ".join(characteristics)

    def _calculate_dynamic_confidence(self, indicator_value: str, api_data: Dict[str, Any],
                                     repetition: Dict[str, Any], api_coverage: int) -> float:
        """Calculate confidence dynamically based on data richness and corroboration."""
        base_confidence = 0.5
        
        # Repetition boost
        if repetition.get("frequency_classification") == "high_frequency_persistence":
            base_confidence += 0.25
        elif repetition.get("frequency_classification") == "medium_frequency_scanning":
            base_confidence += 0.15
        elif repetition.get("is_repeated"):
            base_confidence += 0.10
        
        # API corroboration boost
        corroborating_apis = 0
        if isinstance(api_data.get("virustotal"), dict) and api_data["virustotal"].get("malicious", 0) > 0:
            corroborating_apis += 1
        if isinstance(api_data.get("abuseipdb"), dict) and api_data["abuseipdb"].get("abuse_confidence", 0) > 50:
            corroborating_apis += 1
        if isinstance(api_data.get("shodan"), dict) and api_data["shodan"].get("vulnerabilities", 0) > 0:
            corroborating_apis += 1
        if isinstance(api_data.get("urlscan"), dict) and api_data["urlscan"].get("malicious", False):
            corroborating_apis += 1
        if isinstance(api_data.get("hybrid_analysis"), dict) and api_data["hybrid_analysis"].get("threat_score", 0) > 70:
            corroborating_apis += 1
        
        base_confidence += (corroborating_apis * 0.10)
        
        return min(max(base_confidence, 0.0), 1.0)

    def _map_mitre_attack(self, indicator_type: str, attack_type: str, behavior_pattern: str) -> Dict[str, list]:
        """Map detected threat to MITRE ATT&CK framework."""
        tactics = []
        techniques = []
        
        # Map attack types to MITRE tactics
        if "c2" in attack_type.lower() or "beacon" in behavior_pattern.lower():
            tactics.append("Command and Control")
            techniques.append("T1071: Application Layer Protocol")
            techniques.append("T1065: Uncommonly Used Port")
        elif "phishing" in attack_type.lower():
            tactics.append("Initial Access")
            tactics.append("Credential Access")
            techniques.append("T1598: Phishing")
            techniques.append("T1056: Input Capture")
        elif "malware" in attack_type.lower() or "dropper" in attack_type.lower():
            tactics.append("Execution")
            tactics.append("Persistence")
            techniques.append("T1203: Exploitation for Client Execution")
            techniques.append("T1112: Modify Registry/Config")
        elif "scanning" in behavior_pattern.lower() or "reconnaissance" in behavior_pattern.lower():
            tactics.append("Reconnaissance")
            techniques.append("T1592: Gather Victim Host Information")
            techniques.append("T1595: Active Scanning")
        
        return {"tactics": list(set(tactics)), "techniques": list(set(techniques))}

    def _generate_kill_chain(self, indicator_type: str, attack_type: str, indicator_value: str) -> list[str]:
        """Generate applicable Lockheed Martin kill chain stages."""
        chain = []
        
        if indicator_type == "IP" or indicator_type == "Domain":
            chain.append("1. Reconnaissance: IP/Domain identified through network monitoring")
            if "scanning" in attack_type.lower():
                chain.append("2. Weaponization: Potential scanning tool or exploit framework enumeration")
                chain.append("3. Delivery: Active reconnaissance against network")
            else:
                chain.append("2. Weaponization: Malicious infrastructure prepared")
                chain.append("3. Delivery: Malware or payload delivered via network connection")
        elif indicator_type == "URL":
            chain.append("1. Reconnaissance: Target identified")
            chain.append("2. Weaponization: Exploit kit or phishing lure prepared")
            chain.append("3. Delivery: URL crafted for phishing or drive-by download")
            chain.append("4. Exploitation: Client-side vulnerability or social engineering")
        elif indicator_type == "File":
            chain.append("1. Reconnaissance: System information gathering")
            chain.append("2. Weaponization: Malware binary created/obfuscated")
            chain.append("3. Delivery: File transferred to system")
            chain.append("4. Exploitation: File executed with elevated privileges")
        
        chain.append("5. Installation: Malware/tool establishes persistence")
        chain.append("6. Command & Control: Beacon or C2 callback initiated")
        chain.append("7. Actions on Objective: Data exfiltration or lateral movement")
        
        return chain

    def _detect_contradictions(self, indicator_value: str, scans: list[Dict]) -> list[str]:
        """Detect contradictions in detection results across same indicator."""
        contradictions = []
        matching_scans = [s for s in scans if str(s.get("indicator_value", "")) == indicator_value]
        
        if not matching_scans or len(matching_scans) < 2:
            return contradictions
        
        statuses = set(str((s.get("classification", {}) or {}).get("status", "")).lower() for s in matching_scans)
        if len(statuses) > 1 and "safe" in statuses and ("suspicious" in statuses or "malicious" in statuses):
            contradictions.append(f"Contradictory detections: Same indicator ({indicator_value}) classified as both SAFE and SUSPICIOUS/MALICIOUS")
            contradictions.append("→ Possible explanation: Time-based payload mutation, sandbox evasion, or API inconsistency")
        
        return contradictions

    def _analyze_attribution(self, indicator_value: str, indicator_type: str, api_data: Dict[str, Any]) -> list[str]:
        """Basic threat attribution analysis."""
        attribution = []
        
        if indicator_type == "IP":
            # Port-based attribution
            shodan_data = api_data.get("shodan", {})
            if isinstance(shodan_data, dict):
                # Common exploit framework ports
                if 4444 in (shodan_data.get("open_ports") or []):
                    attribution.append("Port 4444 detected - common Metasploit handler port (possible exploitation framework)")
                if 5555 in (shodan_data.get("open_ports") or []):
                    attribution.append("Port 5555 detected - Android ADB access (possible mobile compromise)")
                if 8888 in (shodan_data.get("open_ports") or []):
                    attribution.append("Port 8888 detected - possible proxy/tunnel server")
                
                # Org inference
                org = shodan_data.get("org", "")
                if org and "hosting" in org.lower():
                    attribution.append(f"IP hosted by {org} - likely bulletproof hosting provider")
                if org and "vpn" in org.lower():
                    attribution.append(f"IP hosted by VPN provider ({org}) - possible anonymization attempt")
        
        elif indicator_type == "Domain":
            # Domain-based attribution
            domain_lower = indicator_value.lower()
            if ".ru" in indicator_value or ".cn" in indicator_value or ".ir" in indicator_value:
                attribution.append(f"TLD suggests possible state-sponsored or regional threat actor involvement")
            
            if "crypto" in domain_lower or "mine" in domain_lower:
                attribution.append("Domain pattern suggests possible cryptocurrency mining or theft campaign")
            if "ddos" in domain_lower or "botnet" in domain_lower:
                attribution.append("Domain pattern suggests botnet or DDoS infrastructure")
        
        return attribution if attribution else ["Attribution: Insufficient data for targeted attribution"]

    def _derive_scan_detection_results(self, api_results: Dict[str, Any], item: Dict[str, Any], indicator_type: str) -> Dict[str, Any]:
        source = str(item.get("source") or item.get("type") or "activity_monitor")
        heuristic = item.get("heuristic") or f"local correlation from source={source}"

        virustotal_value: Any = self._api_status_text(api_results, "virustotal")
        vt_data = api_results.get("virustotal") if isinstance(api_results, dict) else None
        if isinstance(vt_data, dict):
            attrs = ((vt_data.get("data") or {}).get("attributes") or {})
            stats = attrs.get("last_analysis_stats") or {}
            if isinstance(stats, dict) and stats:
                virustotal_value = {
                    "malicious": int(stats.get("malicious", 0) or 0),
                    "suspicious": int(stats.get("suspicious", 0) or 0),
                    "undetected": int(stats.get("undetected", 0) or 0),
                    "harmless": int(stats.get("harmless", 0) or 0),
                    "reputation": int(attrs.get("reputation", 0) or 0),
                }

        abuseipdb_value: Any = self._api_status_text(api_results, "abuseipdb")
        abuse_data = ((api_results.get("abuseipdb") or {}).get("data") or {}) if isinstance(api_results, dict) else {}
        if isinstance(abuse_data, dict) and abuse_data:
            abuseipdb_value = {
                "abuse_confidence": int(abuse_data.get("abuseConfidenceScore", 0) or 0),
                "total_reports": int(abuse_data.get("totalReports", 0) or 0),
                "country": str(abuse_data.get("countryCode", "Unknown")),
            }

        shodan_value: Any = self._api_status_text(api_results, "shodan")
        shodan_data = api_results.get("shodan") if isinstance(api_results, dict) else None
        if isinstance(shodan_data, dict) and not shodan_data.get("error"):
            ports = shodan_data.get("ports") or []
            shodan_value = {
                "open_ports": ports,
                "open_port_count": len(ports),
                "vulnerabilities": len(shodan_data.get("vulns") or []),
                "org": str(shodan_data.get("org", "Unknown")),
            }

        urlscan_value: Any = self._api_status_text(api_results, "urlscan")
        urlscan_data = api_results.get("urlscan") if isinstance(api_results, dict) else None
        if isinstance(urlscan_data, dict):
            verdicts = urlscan_data.get("verdicts") or {}
            overall = verdicts.get("overall") if isinstance(verdicts, dict) else {}
            if isinstance(overall, dict) and overall:
                urlscan_value = {
                    "score": int(overall.get("score", 0) or 0),
                    "malicious": bool(overall.get("malicious", False)),
                    "categories": overall.get("categories") or [],
                }
            else:
                data = urlscan_data.get("data") or {}
                if isinstance(data, dict) and data:
                    classifications = data.get("classifications") or {}
                    urlscan_value = {
                        "phishing": bool((classifications or {}).get("phishing", False)),
                        "suspicious": bool((classifications or {}).get("suspicious", False)),
                    }

        hybrid_value: Any = self._api_status_text(api_results, "hybrid_analysis")
        hybrid_data = api_results.get("hybrid_analysis") if isinstance(api_results, dict) else None
        if isinstance(hybrid_data, dict):
            results = hybrid_data.get("results") or []
            if isinstance(results, list) and results:
                top = results[0] if isinstance(results[0], dict) else {}
                hybrid_value = {
                    "verdict": str(top.get("verdict", "unknown")),
                    "threat_score": int(top.get("threat_score", 0) or 0),
                    "family": str(top.get("vx_family", "unknown")),
                }

        if indicator_type == "IP":
            if isinstance(urlscan_value, str) and "fallback active" in urlscan_value:
                urlscan_value = "intelligence fallback active (reason: URLScan does not directly score IP indicators)"
            if isinstance(hybrid_value, str) and "fallback active" in hybrid_value:
                hybrid_value = "intelligence fallback active (reason: Hybrid Analysis is file-centric and does not directly score IP indicators)"
        elif indicator_type == "File":
            if isinstance(abuseipdb_value, str) and "fallback active" in abuseipdb_value:
                abuseipdb_value = "intelligence fallback active (reason: AbuseIPDB is IP reputation-focused and does not directly score file indicators)"
            if isinstance(shodan_value, str) and "fallback active" in shodan_value:
                shodan_value = "intelligence fallback active (reason: Shodan profiles internet services and does not directly score file artifacts)"
            if isinstance(urlscan_value, str) and "fallback active" in urlscan_value:
                urlscan_value = "intelligence fallback active (reason: URLScan evaluates URLs/domains and does not directly score file hashes)"

        return {
            "heuristic": heuristic,
            "virustotal": virustotal_value,
            "abuseipdb": abuseipdb_value,
            "shodan": shodan_value,
            "urlscan": urlscan_value,
            "hybrid_analysis": hybrid_value,
        }

    def _build_scan_records(self, threat_analysis: Dict[str, Any]) -> list[Dict[str, Any]]:
        threats = threat_analysis.get("threat_indicators", []) or []
        api_results = threat_analysis.get("api_results", {}) if isinstance(threat_analysis.get("api_results"), dict) else {}
        records: list[Dict[str, Any]] = []

        for index, item in enumerate(threats, start=1):
            if not isinstance(item, dict):
                item = {"indicator": str(item or "unknown")}

            indicator_value = str(item.get("indicator") or item.get("value") or "unknown")
            source = str(item.get("source") or item.get("type") or "activity_monitor")
            severity = str(item.get("severity") or item.get("verdict") or "suspicious").lower()
            base_confidence = self._normalize_confidence(item.get("confidence", item.get("score", 0.0)))
            indicator_type = str(item.get("indicator_type") or self._infer_indicator_type(indicator_value, source))
            status = self._status_from_severity(severity)
            attack_type = self._infer_attack_type(indicator_type, indicator_value, severity, source)

            detection_results = self._derive_scan_detection_results(api_results, item, indicator_type)
            heuristic = detection_results.get("heuristic")
            virustotal = detection_results.get("virustotal")
            abuseipdb = detection_results.get("abuseipdb")
            shodan = detection_results.get("shodan")
            urlscan = detection_results.get("urlscan")
            hybrid_analysis = detection_results.get("hybrid_analysis")

            # **INTELLIGENT ANALYSIS ENHANCEMENTS**
            
            # 1. Detect repetition patterns
            repetition = self._detect_repetition_pattern(indicator_value, records, [])
            
            # 2. Generate intelligent detection reason
            detection_reason = self._generate_detection_reason(
                indicator_value, indicator_type, status, severity,
                repetition, detection_results
            )
            
            # 3. Generate real behavior pattern analysis
            behavior_pattern = self._generate_behavior_pattern(
                indicator_value, indicator_type, attack_type,
                repetition, records
            )
            
            # 4. Generate meaningful payload characteristics
            has_api_coverage = any(
                str(v).lower() not in {"", "none", "unavailable", "unknown", "not_executed"}
                for v in (virustotal, abuseipdb, shodan, urlscan, hybrid_analysis)
            )
            payload_characteristics = self._generate_payload_characteristics(
                indicator_value, indicator_type, detection_results, has_api_coverage
            )
            
            # 5. Calculate dynamic confidence
            dynamic_confidence = self._calculate_dynamic_confidence(
                indicator_value, detection_results, repetition, 
                5 if has_api_coverage else 0
            ) * 100.0
            confidence = dynamic_confidence
            
            # 6. Generate MITRE ATT&CK mapping
            mitre_mapping = self._map_mitre_attack(indicator_type, attack_type, behavior_pattern)
            
            # 7. Generate kill chain analysis
            kill_chain = self._generate_kill_chain(indicator_type, attack_type, indicator_value)
            
            # 8. Generate attribution analysis
            attribution_insight = self._analyze_attribution(indicator_value, indicator_type, detection_results)
            
            # System risk assessment
            system_risk = "Critical" if status == "malicious" and confidence >= 80 else (
                "High" if status == "malicious" else (
                "Medium" if status == "suspicious" else "Low"
                )
            )
            
            recommended_action = (
                "Block immediately and isolate system; preserve forensic evidence and trigger incident response protocol."
                if status == "malicious"
                else "Escalate for immediate analyst review; apply temporary containment measures and monitor for lateral movement."
                if status == "suspicious"
                else "Continue routine monitoring; maintain logs for historical correlation analysis."
            )

            records.append(
                {
                    "scan_id": str(item.get("scan_id") or item.get("id") or f"SCAN-{index:05d}"),
                    "timestamp": item.get("timestamp") or item.get("time") or threat_analysis.get("timestamp"),
                    "indicator_type": indicator_type,
                    "indicator_value": indicator_value,
                    "detection_results": {
                        "heuristic": heuristic,
                        "virustotal": virustotal,
                        "abuseipdb": abuseipdb,
                        "shodan": shodan,
                        "urlscan": urlscan,
                        "hybrid_analysis": hybrid_analysis,
                    },
                    "classification": {
                        "status": status,
                        "confidence": round(confidence, 1),
                        "severity": severity,
                    },
                    "technical_analysis": {
                        "detection_reason": detection_reason,
                        "behavior_pattern": behavior_pattern,
                        "payload_characteristics": payload_characteristics,
                    },
                    "impact_analysis": {
                        "system_risk": system_risk,
                        "attack_type": attack_type,
                    },
                    "forensic_analysis": {
                        "mitre_att_ck": mitre_mapping,
                        "kill_chain_stage": kill_chain,
                        "attribution_indicators": attribution_insight,
                        "repetition_pattern": repetition,
                    },
                    "recommended_action": recommended_action,
                }
            )

        return records

    def _build_executive_insights(self, threat_analysis: Dict[str, Any]) -> Dict[str, Any]:
        scans = self._build_scan_records(threat_analysis)
        indicator_counts = Counter(str(scan.get("indicator_value", "unknown")) for scan in scans)
        repeated = [{"indicator": ind, "count": cnt} for ind, cnt in indicator_counts.items() if cnt > 1]
        repeated.sort(key=lambda item: item.get("count", 0), reverse=True)

        high_risk = [
            scan for scan in scans
            if str((scan.get("classification") or {}).get("status", "")).lower() == "malicious"
            or float((scan.get("classification") or {}).get("confidence", 0.0) or 0.0) >= 80.0
        ]
        high_risk.sort(key=lambda item: float((item.get("classification") or {}).get("confidence", 0.0) or 0.0), reverse=True)

        attack_counter = Counter(str((scan.get("impact_analysis") or {}).get("attack_type", "unknown")) for scan in scans)
        attack_types = [atype for atype, _ in attack_counter.most_common(3) if atype and atype != "unknown"]

        severity_counter = Counter(str((scan.get("classification") or {}).get("severity", "unknown")).lower() for scan in scans)
        interval_summaries = threat_analysis.get("interval_summaries") or []
        threat_series = [int((item.get("activity") or {}).get("threats_detected", 0) or 0) for item in interval_summaries if isinstance(item, dict)]
        trend = "stable"
        if len(threat_series) >= 2:
            if threat_series[-1] > threat_series[0]:
                trend = "increasing"
            elif threat_series[-1] < threat_series[0]:
                trend = "decreasing"

        repeated_ips_domains = [
            item for item in repeated
            if self._infer_indicator_type(item.get("indicator"), "") in {"IP", "Domain", "URL"}
        ]

        interval_briefs = []
        for summary in interval_summaries[:3]:
            if not isinstance(summary, dict):
                continue
            label = str(summary.get("interval", "24h")).upper()
            activity = summary.get("activity") or {}
            tdet = int(activity.get("threats_detected", 0) or 0)
            scans_count = int(activity.get("threat_scans", 0) or 0)
            density = (tdet / scans_count) if scans_count else 0.0
            signal = "elevated pressure" if density >= 0.25 or tdet >= 5 else "controlled pressure"
            interval_briefs.append(f"{label}: {tdet} threats over {scans_count} scans ({signal})")

        narrative = (
            f"Threat posture reflects {len(scans)} analyzed scans with {len(high_risk)} high-risk indicator(s). "
            f"Repeated indicators suggest persistence pressure: {', '.join(i['indicator'] for i in repeated_ips_domains[:3]) or 'no sustained repeaters identified'}. "
            f"Dominant attack patterns include {', '.join(attack_types) if attack_types else 'mixed low-signal activity'}, "
            f"with trend currently {trend}. Interval intelligence: {'; '.join(interval_briefs) if interval_briefs else 'single-window dataset; longitudinal comparison unavailable'}."
        )

        return {
            "scan_count": len(scans),
            "severity_distribution": dict(severity_counter),
            "high_risk_indicators": high_risk,
            "repeated_indicators": repeated,
            "repeated_ips_domains": repeated_ips_domains,
            "attack_types": attack_types,
            "trend": trend,
            "interval_briefs": interval_briefs,
            "narrative": narrative,
        }

    def _build_forensic_intelligence(self, threat_analysis: Dict[str, Any]) -> Dict[str, Any]:
        scans = self._build_scan_records(threat_analysis)
        indicator_history: dict[str, list[Dict[str, Any]]] = defaultdict(list)
        timeline = []

        for scan in scans:
            indicator = str(scan.get("indicator_value", "unknown"))
            status = str((scan.get("classification") or {}).get("status", "unknown")).lower()
            timestamp = scan.get("timestamp")
            indicator_history[indicator].append(
                {
                    "timestamp": timestamp,
                    "status": status,
                    "scan_id": scan.get("scan_id"),
                    "attack_type": (scan.get("impact_analysis") or {}).get("attack_type", "unknown"),
                }
            )
            timeline.append(
                {
                    "timestamp": timestamp,
                    "scan_id": scan.get("scan_id"),
                    "indicator": indicator,
                    "status": status,
                    "indicator_type": scan.get("indicator_type", "Unknown"),
                }
            )

        for indicator, events in indicator_history.items():
            indicator_history[indicator] = sorted(events, key=lambda e: str(e.get("timestamp") or ""))

        timeline = sorted(timeline, key=lambda e: str(e.get("timestamp") or ""))

        transitions = []
        contradictions_detected = []
        for indicator, events in indicator_history.items():
            statuses = [str(event.get("status", "unknown")).lower() for event in events]
            if "safe" in statuses and "malicious" in statuses:
                transitions.append(
                    {
                        "indicator": indicator,
                        "transition": "SAFE -> MALICIOUS",
                        "events": events,
                    }
                )
            if len(set(statuses)) > 1:
                contradictions_detected.append(
                    {
                        "indicator": indicator,
                        "statuses": sorted(set(statuses)),
                        "possible_reasons": [
                            "Time-based payload mutation",
                            "Sandbox evasion techniques",
                            "API-specific detection logic variance",
                            "Geographic or behavioral context change",
                        ],
                    }
                )

        repeated_entities = [
            {
                "indicator": indicator,
                "count": len(events),
                "indicator_type": self._infer_indicator_type(indicator, ""),
                "behavioral_classification": "high_frequency_persistence" if len(events) >= 5 else (
                    "medium_frequency_scanning" if len(events) >= 3 else "low_frequency_recurrence"
                ),
            }
            for indicator, events in indicator_history.items()
            if len(events) > 1
        ]
        repeated_entities.sort(key=lambda item: item.get("count", 0), reverse=True)

        grouped_threats: dict[str, list[str]] = defaultdict(list)
        attack_vector_counts = Counter()
        confidence_model_counts = Counter()
        attribution = Counter()
        mitre_tactics = Counter()
        kill_chain_coverage = Counter()

        for scan in scans:
            attack_type = str((scan.get("impact_analysis") or {}).get("attack_type", "unknown"))
            indicator = str(scan.get("indicator_value", "unknown"))
            grouped_threats[attack_type].append(indicator)
            attribution[attack_type] += 1

            # Collect MITRE ATT&CK tactics
            forensic = scan.get("forensic_analysis", {})
            mitre_data = forensic.get("mitre_att_ck", {})
            for tactic in mitre_data.get("tactics", []):
                mitre_tactics[tactic] += 1
            
            # Collect kill chain coverage
            for stage in forensic.get("kill_chain_stage", []):
                if "Reconnaissance" in stage:
                    kill_chain_coverage["Reconnaissance"] += 1
                elif "Weaponization" in stage:
                    kill_chain_coverage["Weaponization"] += 1
                elif "Delivery" in stage:
                    kill_chain_coverage["Delivery"] += 1
                elif "Exploitation" in stage:
                    kill_chain_coverage["Exploitation"] += 1
                elif "Installation" in stage:
                    kill_chain_coverage["Installation"] += 1
                elif "Command" in stage:
                    kill_chain_coverage["C&C"] += 1
                elif "Actions" in stage:
                    kill_chain_coverage["Actions on Objective"] += 1

            indicator_type = str(scan.get("indicator_type", "Unknown"))
            if indicator_type == "IP":
                attack_vector_counts["Network-based"] += 1
            elif indicator_type in {"URL", "Domain"}:
                attack_vector_counts["Web-based"] += 1
            elif indicator_type == "File":
                attack_vector_counts["File-based"] += 1
            else:
                attack_vector_counts["Unclassified"] += 1

            detection_results = scan.get("detection_results") or {}
            non_empty_sources = sum(
                1
                for key in ("heuristic", "virustotal", "abuseipdb", "shodan", "urlscan", "hybrid_analysis")
                if str(detection_results.get(key, "")).strip().lower() not in {"", "none", "unavailable", "unknown"}
            )
            status = str((scan.get("classification") or {}).get("status", "unknown")).lower()
            if status == "safe":
                confidence_model_counts["VERIFIED SAFE (High Confidence)"] += 1
            elif non_empty_sources >= 3:
                confidence_model_counts["MULTI-SOURCE CORROBORATION (High Confidence)"] += 1
            elif non_empty_sources >= 2:
                confidence_model_counts["DUAL-SOURCE EVIDENCE (Medium Confidence)"] += 1
            else:
                confidence_model_counts["SINGLE SOURCE / HEURISTIC (Lower Confidence)"] += 1

        return {
            "timeline": timeline,
            "safe_to_malicious_transitions": transitions,
            "pattern_correlation": {
                "repeated_entities": repeated_entities,
                "grouped_threats": {key: values[:12] for key, values in grouped_threats.items()},
                "repetition_behavioral_classification": {
                    item["indicator"]: item["behavioral_classification"]
                    for item in repeated_entities
                },
            },
            "contradictions_detected": contradictions_detected,
            "contradictions": contradictions_detected,
            "threat_attribution_analysis": dict(attribution),
            "threat_attribution": dict(attribution),
            "mitre_att_ck_coverage": dict(mitre_tactics),
            "kill_chain_coverage": dict(kill_chain_coverage),
            "confidence_scoring_model": dict(confidence_model_counts),
            "attack_vector_classification": dict(attack_vector_counts),
        }

    def _resolve_timezone_name(self, threat_data: Dict[str, Any]) -> str:
        configured = str(
            threat_data.get("report_timezone")
            or (getattr(settings, "REPORT_TIMEZONE", "") if settings else "")
            or os.getenv("REPORT_TIMEZONE", "UTC")
        ).strip()
        if not configured:
            return "UTC"
        try:
            ZoneInfo(configured)
            return configured
        except Exception:
            logger.warning("Invalid report timezone '%s', falling back to UTC", configured)
            return "UTC"

    def _format_timestamp_for_report(self, raw_ts: Any, tz_name: str) -> str:
        tz_obj = ZoneInfo(tz_name)
        dt_obj: Optional[datetime] = None

        if isinstance(raw_ts, datetime):
            dt_obj = raw_ts
        elif isinstance(raw_ts, (int, float)):
            try:
                dt_obj = datetime.fromtimestamp(float(raw_ts), tz=timezone.utc)
            except Exception:
                dt_obj = None
        elif isinstance(raw_ts, str):
            candidate = raw_ts.strip()
            if candidate.isdigit():
                try:
                    dt_obj = datetime.fromtimestamp(float(candidate), tz=timezone.utc)
                except Exception:
                    dt_obj = None
            if dt_obj is None and candidate:
                try:
                    dt_obj = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
                except Exception:
                    dt_obj = None

        if dt_obj is None:
            dt_obj = datetime.now(timezone.utc)
        if dt_obj.tzinfo is None:
            dt_obj = dt_obj.replace(tzinfo=timezone.utc)

        localized = dt_obj.astimezone(tz_obj)
        return localized.strftime("%Y-%m-%d %H:%M:%S %Z")

    def _report_time_window_label(self, threat_data: Dict[str, Any]) -> str:
        intervals = threat_data.get("intervals") or []
        if not intervals:
            return "Last 24 hours"
        if len(intervals) == 1:
            label = str(intervals[0]).strip().lower()
            return {"24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days"}.get(label, f"Selected window: {label}")
        return " / ".join(str(i).upper() for i in intervals)

    def _sanitize_ai_output(self, text: str, report_type: str) -> str:
        if not text:
            return ""
        cleaned = text.replace("\r\n", "\n").replace("\r", "\n")
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
        # Remove repetitive footer echoes and duplicate headings often returned by model retries.
        cleaned = re.sub(r"(SENTINEL-AI \| Automated Threat Detection.*)$", "", cleaned, flags=re.IGNORECASE | re.MULTILINE).strip()

        # Guard against refusal/placeholder outputs while allowing analytical uncertainty language in real reports.
        lowered = cleaned.lower()
        lead_window = lowered[:320]
        refusal_patterns = (
            r"\bi\s+cannot\b",
            r"\bi\s+can't\b",
            r"\bunable\s+to\s+provide\b",
            r"\bnot\s+enough\s+information\b",
            r"\binsufficient\s+data\b",
        )
        has_placeholder_only = bool(re.search(r"\b(?:n/?a|placeholder|lorem ipsum)\b", lowered))
        has_refusal_lead = any(re.search(pattern, lead_window) for pattern in refusal_patterns)

        words = cleaned.split()
        word_count = len(words)
        normalized_type = self._normalize_report_type(report_type)
        hard_floor = 70 if normalized_type == "executive_summary" else 90

        if has_placeholder_only and word_count < 140:
            return ""
        if has_refusal_lead and word_count < 220:
            return ""

        # Accept shorter outputs only if they contain structured analytical sections.
        has_structured_sections = bool(
            re.search(
                r"\b(executive\s+summary|risk\s+assessment|analysis|findings|recommendations?|mitigation|confidence|verdict|timeline|forensic)\b",
                lowered,
            )
        )
        has_explicit_markdown_structure = bool(
            re.search(r"(?m)^(?:#{1,3}\s+|[-*]\s+|\d+\.\s+)", cleaned)
        )
        structured_signal_count = len(re.findall(r"(?m)^(?:#{1,3}\s+|[-*]\s+|\d+\.\s+)", cleaned))
        soft_floor = 45

        if word_count < soft_floor:
            return ""
        if word_count < hard_floor and not (has_structured_sections or has_explicit_markdown_structure or structured_signal_count >= 2):
            return ""

        # Avoid single-line responses that pass word checks but are low readability.
        paragraph_count = len([line for line in cleaned.split("\n") if line.strip()])
        if paragraph_count < 2 and word_count < (hard_floor + 10) and not (has_structured_sections or has_explicit_markdown_structure):
            return ""

        return cleaned

    def _make_analysis_cache_key(self, threat_data: Dict[str, Any]) -> str:
        """Create a stable cache key for repeated Gemini or fallback analysis requests."""
        def _normalize(value: Any) -> Any:
            if isinstance(value, dict):
                return {str(key): _normalize(value[key]) for key in sorted(value)}
            if isinstance(value, list):
                return [_normalize(item) for item in value]
            if isinstance(value, tuple):
                return [_normalize(item) for item in value]
            if isinstance(value, datetime):
                return value.isoformat()
            if isinstance(value, Path):
                return str(value)
            return value

        payload = {
            "input": threat_data.get("input"),
            "input_type": threat_data.get("input_type"),
            "verdict": threat_data.get("verdict"),
            "confidence": threat_data.get("confidence"),
            "report_type": self._normalize_report_type(threat_data.get("report_type", "executive_summary")),
            "timestamp": threat_data.get("timestamp"),
            "threat_indicators": threat_data.get("threat_indicators", []),
            "api_results": threat_data.get("api_results", {}),
            "forensic_metadata": threat_data.get("forensic_metadata", {}),
            "interval_summaries": threat_data.get("interval_summaries", []),
            "behavioral_sequence": threat_data.get("behavioral_sequence", []),
        }
        serialized = json.dumps(_normalize(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return __import__("hashlib").sha256(serialized.encode("utf-8")).hexdigest()

    def _get_cached_analysis(self, cache_key: str) -> Optional[str]:
        entry = self._analysis_cache.get(cache_key)
        if not entry:
            return None
        cached_at, cached_value = entry
        if time.time() - cached_at > self._analysis_cache_ttl:
            self._analysis_cache.pop(cache_key, None)
            return None
        self._analysis_cache.move_to_end(cache_key)
        return cached_value

    def _store_cached_analysis(self, cache_key: str, analysis_text: str) -> None:
        if not analysis_text:
            return
        self._analysis_cache[cache_key] = (time.time(), analysis_text)
        self._analysis_cache.move_to_end(cache_key)
        while len(self._analysis_cache) > self._analysis_cache_size:
            self._analysis_cache.popitem(last=False)

    def _report_schema_for_prompt(self, report_type: str) -> str:
        normalized = self._normalize_report_type(report_type)
        if normalized == "technical_analysis":
            return (
                "Report format: TECHNICAL REPORT\\n"
                "Audience: SOC analysts, engineers, incident handlers.\\n"
                "Required sections (exact order):\\n"
                "1. Technical Overview\\n"
                "2. Scan Metadata and Time Context\\n"
                "3. Per-Scan Structured Technical Records (include every scan)\\n"
                "4. Detection Engine Results (heuristic, virustotal, abuseipdb, shodan, urlscan, hybrid_analysis)\\n"
                "5. Classification, Technical Analysis, Impact Analysis, Recommended Action per scan\\n"
                "6. Detection Logic Notes and Telemetry Gaps\\n"
                "7. Recommended Technical Mitigations (prioritized)\\n"
                "8. Technical Conclusion\\n"
                "Constraints: do not invent indicators, APIs, or timestamps; when provider data is missing, provide fallback intelligence and explicit reason.\\n"
                "Constraints: per-scan records must use keys scan_id, timestamp, indicator_type, indicator_value, detection_results, classification, technical_analysis, impact_analysis, recommended_action.\\n"
                "Tone: concise but deep technical reasoning with implementation-level language."
            )
        if normalized == "forensic_investigation":
            return (
                "Report format: FORENSIC EVALUATION REPORT\\n"
                "Audience: digital forensic reviewer, IR lead, investigator, compliance reviewer.\\n"
                "Required sections (exact order):\\n"
                "1. Forensic Evaluation Overview\\n"
                "2. Timeline Analysis (including SAFE -> MALICIOUS transitions)\\n"
                "3. Pattern Correlation (repeated IP/domain/URL grouping)\\n"
                "4. Contradiction Detection and Possible Reasons (API delay, payload switching, geo-based behavior)\\n"
                "5. Threat Attribution (C2, phishing kits, malware delivery patterns)\\n"
                "6. Confidence Scoring Model (single source low, corroborated medium, verified safe high)\\n"
                "7. Attack Vector Classification (network, web, file based)\\n"
                "8. Investigative Next Steps\\n"
                "9. Final Forensic Assessment\\n"
                "Constraints: separate observed facts from analytic judgement; avoid legal over-claims; never fabricate evidence.\\n"
                "Tone: formal, evidence-centric, cautious, defensible."
            )
        return (
            "Report format: EXECUTIVE SUMMARY REPORT\\n"
            "Audience: management, supervisors, project evaluators, non-technical decision makers.\\n"
            "Required sections (exact order):\\n"
            "1. Executive Overview\\n"
            "2. Threat Overview\\n"
            "3. Risk Level Summary\\n"
            "4. Key Incident Highlights\\n"
            "5. Repeated Threat Indicators (include repeated IPs/domains)\\n"
            "6. Attack Trend Summary (phishing, C2, malware delivery if present)\\n"
            "7. Immediate Actions (24-72h)\\n"
            "8. Executive Conclusion\\n"
            "Constraints: keep strategic and readable; avoid low-level dump; do not invent unavailable data.\\n"
            "Tone: formal, decision-support, concise with meaningful insight."
        )

    def _report_outline_items(self, report_type: str) -> list[tuple[str, str]]:
        normalized = self._normalize_report_type(report_type)
        if normalized == "technical_analysis":
            return [
                ("Technical verdict", "Summarizes the detection outcome, confidence, and uncertainty."),
                ("Detection chain", "Shows how static, behavioral, and intelligence signals supported the result."),
                ("Evidence matrix", "Lists the strongest and weakest corroborating data sources."),
                ("Control gaps", "Explains what telemetry or policy weakness allowed the issue to surface."),
                ("Validation plan", "Defines how engineering teams should re-test and confirm improvement."),
            ]
        if normalized == "forensic_investigation":
            return [
                ("Case overview", "States the scope, subject, time window, and primary assessment."),
                ("Evidence inventory", "Documents hashes, indicators, sources, and acquisition context."),
                ("Timeline reconstruction", "Rebuilds the event sequence in chronological order."),
                ("Corroboration review", "Explains which claims are independently supported and which remain limited."),
                ("Legal boundaries", "Separates proven facts from investigative hypotheses and escalation risks."),
            ]
        return [
            ("Risk summary", "Presents the current posture and the practical meaning for leadership."),
            ("Business impact", "Explains operational, continuity, and governance implications."),
            ("Key findings", "Highlights the most important observations in plain language."),
            ("Immediate decisions", "Clarifies what leadership should decide or authorize now."),
            ("Residual risk", "States what remains unresolved and what should be monitored."),
        ]

    def _report_purpose_text(self, report_type: str) -> str:
        normalized = self._normalize_report_type(report_type)
        if normalized == "technical_analysis":
            return (
                "This report is written for engineering, SOC, and incident-response teams. "
                "Its purpose is to show how the conclusion was formed, where the evidence is strongest, "
                "where telemetry is weak, and what should be validated next."
            )
        if normalized == "forensic_investigation":
            return (
                "This report is written for investigative and compliance use. "
                "Its purpose is to preserve evidence context, maintain a defensible timeline, "
                "and separate observed facts from interpretive conclusions."
            )
        return (
            "This report is written for leadership and operational decision-makers. "
            "Its purpose is to summarize the threat posture, business impact, and the decisions "
            "needed to reduce risk and maintain continuity."
        )

    def _interval_analysis_text(self, interval: str, threat_data: Dict[str, Any]) -> str:
        """Generate distinct analysis narrative per time interval"""
        report_type = self._normalize_report_type(threat_data.get("report_type", "executive_summary"))
        interval_summaries = threat_data.get("interval_summaries", [])
        
        # Find matching interval data
        interval_data = None
        for summary in interval_summaries:
            if summary.get("interval") == interval:
                interval_data = summary
                break
        
        if not interval_data:
            return f"Analysis for {interval} interval not available."
        
        activity = interval_data.get("activity", {})
        threats_detected = activity.get("threats_detected", 0)
        scans_performed = activity.get("threat_scans", activity.get("scans", 0))
        
        if interval == "24h":
            focus = "IMMEDIATE & RECENT activity patterns"
            trend_indicator = "short-term threat surface" if threats_detected > 0 else "stable short-term posture"
            severity_phrase = "emerging threats requiring immediate attention" if threats_detected > 2 else "contained activity levels"
        elif interval == "7d":
            focus = "WEEKLY trend analysis and pattern emergence"
            trend_indicator = "evolving threat landscape" if threats_detected > 5 else "consistent week-over-week patterns"
            severity_phrase = "sustained threat pressure across the week" if threats_detected > 10 else "week-over-week stability"
        else:  # 30d
            focus = "STRATEGIC threat posture and long-term patterns"
            trend_indicator = "chronic or recurring threat surface" if threats_detected > 20 else "mature defensive posture"
            severity_phrase = "persistent attack patterns requiring strategic response" if threats_detected > 30 else "effective long-term threat management"
        
        narrative = (
            f"**{interval.upper()} INTERVAL SUMMARY**: This period focused on {focus}.\n\n"
            f"Activity Volume: {scans_performed} scans performed, {threats_detected} threats detected.\n\n"
            f"Threat Characterization: {{trend_indicator}}\n\n"
            f"Key Interpretation: The {interval} window shows {severity_phrase}."
        )
        return narrative.replace("{{trend_indicator}}", trend_indicator)

    def _interval_report_interpretation(self, interval: str, threat_data: Dict[str, Any], report_type: str) -> str:
        """Generate report-type specific interval intelligence narrative."""
        base = self._interval_analysis_text(interval, threat_data)
        interval_summaries = threat_data.get("interval_summaries", [])
        current = next((item for item in interval_summaries if isinstance(item, dict) and str(item.get("interval", "")).lower() == interval.lower()), None)
        activity = (current or {}).get("activity", {}) if isinstance(current, dict) else {}
        threats_detected = int(activity.get("threats_detected", 0) or 0)
        scans_performed = int(activity.get("threat_scans", activity.get("scans", 0)) or 0)
        density = (threats_detected / scans_performed) if scans_performed else 0.0

        normalized = self._normalize_report_type(report_type)
        if normalized == "technical_analysis":
            return (
                f"{base} Technical interpretation: detection density={density:.2f}. "
                f"Focus on repeat indicators, telemetry blind spots, and provider corroboration depth for {interval.upper()}."
            )
        if normalized == "forensic_investigation":
            return (
                f"{base} Forensic interpretation: prioritize timeline clustering, contradiction review, and persistence signals in {interval.upper()} evidence."
            )
        return (
            f"{base} Executive interpretation: use this interval to align containment urgency and resource allocation with observed threat pressure."
        )

    def _interval_focus_rows(self, interval: str, threat_data: Dict[str, Any]) -> list[list[str]]:
        """Per-interval analysis matrix for distinct report focus"""
        interval_summaries = threat_data.get("interval_summaries", [])
        
        # Find matching interval data
        interval_data = None
        for summary in interval_summaries:
            if summary.get("interval") == interval:
                interval_data = summary
                break
        
        if not interval_data:
            return [["Period", interval], ["Status", "Data unavailable"]]
        
        activity = interval_data.get("activity", {})
        scans = activity.get("scans", 0)
        threats = activity.get("threats_detected", 0)
        websites = activity.get("websites_monitored", 0)
        
        if interval == "24h":
            return [
                ["Detection Window", "24 hours (immediate)"],
                ["Threat Scans", f"{scans} total scans"],
                ["Threats Identified", f"{threats} findings"],
                ["Focus", "Incident response priority"],
                ["Timeframe Use", "Immediate action planning"],
            ]
        elif interval == "7d":
            return [
                ["Detection Window", "7 days (trends)"],
                ["Threat Scans", f"{scans} total scans"],
                ["Threats Identified", f"{threats} findings"],
                ["Focus", "Pattern recognition"],
                ["Timeframe Use", "Weekly risk assessment"],
            ]
        else:  # 30d
            return [
                ["Detection Window", "30 days (strategic)"],
                ["Threat Scans", f"{scans} total scans"],
                ["Threats Identified", f"{threats} findings"],
                ["Focus", "Long-term posture"],
                ["Timeframe Use", "Strategic planning"],
            ]

    def _count_reports_in_window(self, seconds: int) -> int:
        if not hasattr(self, "_daily_reports"):
            return 0
        now = datetime.now()
        threshold = now - timedelta(seconds=max(1, int(seconds)))
        return sum(1 for ts in self._daily_reports if isinstance(ts, datetime) and ts >= threshold)

    def _should_use_gemini_for_report(self, threat_data: Dict[str, Any]) -> tuple[bool, str]:
        report_type = self._normalize_report_type(threat_data.get("report_type", "executive_summary"))
        now_ts = time.time()
        key_count = len(getattr(self, "gemini_keys", []) or [])
        if key_count <= 1 and now_ts < float(self._quota_cooldown_until or 0):
            remaining = int(max(1, self._quota_cooldown_until - now_ts))
            return False, f"provider cooldown active ({remaining}s remaining after quota/rate-limit)"

        if self.gemini_exec_only and report_type != "executive_summary":
            return False, f"policy: local-first for {report_type}"

        hourly_count = self._count_reports_in_window(3600)
        if hourly_count >= self.gemini_hourly_report_limit:
            return False, f"hourly limit reached ({self.gemini_hourly_report_limit}/hour)"

        return True, "ok"

    async def _generate_ai_analysis(self, threat_data: Dict[str, Any]) -> str:
        """Generate AI analysis using Gemini API"""
        cache_key = self._make_analysis_cache_key(threat_data)
        cached_analysis = self._get_cached_analysis(cache_key)
        if cached_analysis:
            logger.debug("Using cached analysis result for repeated request")
            return cached_analysis

        # Check daily limit (50 reports per day - conservative limit for free tier)
        if not hasattr(self, '_daily_reports'):
            self._daily_reports = []
            self._last_reset = datetime.now().date()
        
        # Reset counter if new day
        if datetime.now().date() > self._last_reset:
            self._daily_reports = []
            self._last_reset = datetime.now().date()
        
        # Check if we hit daily limit
        if len(self._daily_reports) >= self.gemini_daily_report_limit:
            self._last_gemini_failure_reason = f"daily limit reached ({self.gemini_daily_report_limit}/day)"
            logger.warning("Daily Gemini report limit (%s) reached. Using local fallback.", self.gemini_daily_report_limit)
            analysis_text = self._get_fallback_analysis(threat_data)
            self._store_cached_analysis(cache_key, analysis_text)
            return analysis_text

        should_use_gemini, usage_reason = self._should_use_gemini_for_report(threat_data)
        if not should_use_gemini:
            self._last_gemini_failure_reason = usage_reason
            logger.info("Skipping Gemini call: %s", usage_reason)
            analysis_text = self._get_fallback_analysis(threat_data)
            self._store_cached_analysis(cache_key, analysis_text)
            return analysis_text
        
        if not self.initialized or not GEMINI_AVAILABLE:
            self._last_gemini_failure_reason = "Gemini integration unavailable or not initialized"
            analysis_text = self._get_fallback_analysis(threat_data)
            self._store_cached_analysis(cache_key, analysis_text)
            return analysis_text
        
        # Prepare simplified prompt for Gemini (reduce tokens)
        prompt = self._prepare_analysis_prompt(threat_data)

        # Unified call with retry/backoff for modern and legacy clients
        async def _call_genai_with_retry(p: str, max_attempts: int = self.gemini_max_attempts) -> Optional[str]:
            # Rate limiter: ensure minimum interval between requests
            time_since_last = time.time() - self._last_request_time
            if time_since_last < self._min_request_interval:
                wait_time = self._min_request_interval - time_since_last
                logger.info(f"Rate limiting: waiting {wait_time:.1f}s before next Gemini request")
                await asyncio.sleep(wait_time)
            
            self._last_request_time = time.time()
            
            # Circuit open check
            if time.time() < self._circuit_open_until:
                now_ts = time.time()
                if now_ts - float(self._last_circuit_notice_at or 0.0) >= 60:
                    logger.info("Gemini circuit open until %s, skipping remote call", self._circuit_open_until)
                    self._last_circuit_notice_at = now_ts
                self._last_gemini_failure_reason = "Gemini circuit breaker open"
                return None

            def _build_genai_client(api_key: str):
                # Support both google.genai.Client and google.genai.client.Client API shapes.
                if hasattr(genai, "Client"):
                    return genai.Client(api_key=api_key)
                if hasattr(genai, "client") and hasattr(genai.client, "Client"):
                    return genai.client.Client(api_key=api_key)
                return None

            def _classify_error(message: str) -> str:
                lower = str(message or "").lower()
                if "429" in lower or "resource_exhausted" in lower or "quota" in lower or "rate limit" in lower:
                    return "quota"
                if "401" in lower or "403" in lower or "invalid api key" in lower or "permission" in lower or "unauthorized" in lower:
                    return "auth"
                if "model" in lower and ("not found" in lower or "unsupported" in lower):
                    return "model"
                if "timeout" in lower or "temporarily" in lower or "unavailable" in lower:
                    return "transient"
                return "other"

            def _extract_retry_delay_seconds(message: str) -> int:
                text = str(message or "")
                retry_patterns = [
                    re.compile(r"retryDelay'?:\s*'?(\d+)s'?,?", re.IGNORECASE),
                    re.compile(r"retry in\s+([0-9]+(?:\.[0-9]+)?)s", re.IGNORECASE),
                    re.compile(r"retry after\s+([0-9]+(?:\.[0-9]+)?)s", re.IGNORECASE),
                ]
                for pattern in retry_patterns:
                    match = pattern.search(text)
                    if match:
                        try:
                            return max(1, int(float(match.group(1))))
                        except Exception:
                            continue
                return 0

            last_error_message = ""
            key_pool = self.gemini_keys[:] if self.gemini_keys else ([self.gemini_key] if self.gemini_key else [])
            model_pool = self.gemini_model_candidates[:] if self.gemini_model_candidates else ["gemini-2.5-flash"]

            for attempt in range(1, max_attempts + 1):
                saw_transient = False
                # Try modern google.genai client first
                if hasattr(genai, "Client") or (hasattr(genai, "client") and hasattr(genai.client, "Client")):
                    for key_index, api_key in enumerate(key_pool):
                        try:
                            client = _build_genai_client(api_key)
                            if client is None:
                                raise RuntimeError("No supported google.genai Client class found")

                            for model_name in model_pool:
                                try:
                                    response = await asyncio.wait_for(
                                        asyncio.to_thread(lambda: client.models.generate_content(
                                            model=model_name,
                                            contents=p,
                                            config=GenerateContentConfig(
                                                temperature=0.4,
                                                top_p=0.9,
                                                max_output_tokens=2200,
                                                response_mime_type="text/plain",
                                            )
                                        )),
                                        timeout=self.gemini_request_timeout_seconds
                                    )
                                    text = self._extract_text_from_genai_response(response)
                                    if text:
                                        self._failure_count = 0
                                        self._last_gemini_failure_reason = ""
                                        self._daily_reports.append(datetime.now())
                                        logger.info("Gemini analysis succeeded using model %s (key #%d)", model_name, key_index + 1)
                                        return text
                                    self._failure_count = 0
                                    self._last_gemini_failure_reason = ""
                                    return str(response)
                                except asyncio.TimeoutError:
                                    last_error_message = f"timeout while calling model {model_name}"
                                    saw_transient = True
                                    continue
                                except Exception as model_exc:
                                    msg = str(model_exc)
                                    last_error_message = msg
                                    kind = _classify_error(msg)
                                    if kind == "model":
                                        continue
                                    if kind == "quota":
                                        now_ts = time.time()
                                        retry_delay = _extract_retry_delay_seconds(msg)
                                        effective_cooldown = max(
                                            int(self.gemini_quota_cooldown_seconds),
                                            int(retry_delay) if retry_delay else 0,
                                        )
                                        if len(key_pool) <= 1:
                                            self._quota_cooldown_until = max(
                                                float(self._quota_cooldown_until or 0.0),
                                                now_ts + float(effective_cooldown),
                                            )
                                        self._last_gemini_failure_reason = (
                                            f"provider quota/rate limited; cooldown {effective_cooldown}s"
                                        )
                                        if now_ts - float(self._last_quota_warning_at or 0.0) >= 120:
                                            logger.warning(
                                                "Gemini quota/rate issue on model %s key #%d; entering cooldown for %ss",
                                                model_name,
                                                key_index + 1,
                                                effective_cooldown,
                                            )
                                            self._last_quota_warning_at = now_ts
                                        else:
                                            logger.debug(
                                                "Gemini quota/rate issue on model %s key #%d (warning throttled)",
                                                model_name,
                                                key_index + 1,
                                            )
                                        continue
                                    if kind == "auth":
                                        logger.warning("Gemini auth issue on key #%d; trying fallback keys", key_index + 1)
                                        break
                                    if kind == "transient":
                                        saw_transient = True
                                        continue
                                    # Unknown errors: keep trying other models/keys.
                                    continue
                        except Exception as key_exc:
                            last_error_message = str(key_exc)
                            continue

                # Fallback to legacy google.generativeai if available (sync API)
                if hasattr(genai, "GenerativeModel"):
                    try:
                        loop = asyncio.get_event_loop()
                        model = genai.GenerativeModel(model_pool[0])
                        response = await asyncio.wait_for(
                            loop.run_in_executor(None, lambda: model.generate_content(p)),
                            timeout=self.gemini_request_timeout_seconds
                        )
                        text = self._extract_text_from_genai_response(response)
                        if text:
                            self._failure_count = 0
                            self._last_gemini_failure_reason = ""
                            self._daily_reports.append(datetime.now())
                            return text
                        self._failure_count = 0
                        self._last_gemini_failure_reason = ""
                        return getattr(response, "text", None)
                    except Exception as e:
                        msg = str(e)
                        last_error_message = msg
                        logger.warning("legacy generativeai attempt %d failed: %s", attempt, msg)
                        if _classify_error(msg) == "transient":
                            saw_transient = True

                self._failure_count += 1
                if self._failure_count >= self.circuit_threshold:
                    self._circuit_open_until = time.time() + self.circuit_open_seconds
                    self._last_gemini_failure_reason = last_error_message or "circuit threshold reached"
                    logger.debug("Gemini circuit opened until %s after %d failures", self._circuit_open_until, self._failure_count)
                    return None

                if attempt < max_attempts and saw_transient:
                    backoff = min(2 ** attempt, 20)
                    logger.info("Transient Gemini error, retrying in %s seconds (attempt %d/%d)", backoff, attempt, max_attempts)
                    await asyncio.sleep(backoff)
                    continue

                # If neither client yields or we should not retry further, break
                break

            self._last_gemini_failure_reason = last_error_message or "Gemini request failed"
            return None

        # Attempt to call Gemini with retries
        genai_result = await _call_genai_with_retry(prompt)
        if genai_result:
            sanitized = self._sanitize_ai_output(genai_result, threat_data.get("report_type", "executive_summary"))
            if sanitized:
                self._store_cached_analysis(cache_key, sanitized)
                return sanitized
            logger.warning(
                "Gemini returned incomplete analysis (words=%d, report_type=%s); using deterministic fallback",
                len(str(genai_result).split()),
                self._normalize_report_type(threat_data.get("report_type", "executive_summary")),
            )

        # Final fallback to deterministic local analysis
        logger.debug("Using local analysis (%s)", self._last_gemini_failure_reason or "Gemini unavailable")
        analysis_text = self._get_fallback_analysis(threat_data)
        self._store_cached_analysis(cache_key, analysis_text)
        return analysis_text

    def _extract_text_from_genai_response(self, response: Any) -> str:
        """Best-effort extraction of textual content from various GenAI response shapes.

        The modern `google.genai` and legacy `google.generativeai` clients return different
        shapes. This helper inspects common attributes and dict structures to return
        readable text when available, otherwise falls back to `str(response)`.
        """
        try:
            # Common modern shape: response.output -> list of outputs -> each has content (list)
            if getattr(response, "output", None):
                parts = []
                for out in response.output:
                    content = getattr(out, "content", None)
                    if content:
                        for item in content:
                            # item may be an object with .text or a dict
                            txt = None
                            if hasattr(item, "text"):
                                txt = getattr(item, "text")
                            elif isinstance(item, dict):
                                txt = item.get("text") or item.get("content")
                            if txt:
                                parts.append(str(txt))
                    else:
                        # fallback: maybe out has text
                        if hasattr(out, "text"):
                            parts.append(str(getattr(out, "text")))
                if parts:
                    return "\n\n".join(parts)

            # Another common pattern: response.candidates -> list
            if getattr(response, "candidates", None):
                texts = []
                for cand in response.candidates:
                    content = getattr(cand, "content", None) or (cand.get("content") if isinstance(cand, dict) else None)
                    if isinstance(content, list):
                        for item in content:
                            if hasattr(item, "text"):
                                texts.append(getattr(item, "text"))
                            elif isinstance(item, dict) and item.get("text"):
                                texts.append(item.get("text"))
                    elif isinstance(content, str):
                        texts.append(content)
                if texts:
                    return "\n\n".join(map(str, texts))

            # Direct text attribute
            if getattr(response, "text", None):
                return str(getattr(response, "text"))

            # If it's dict-like, try to find first text-like value
            if isinstance(response, dict):
                def _find_text(obj):
                    if isinstance(obj, str):
                        return obj
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            if k.lower() in ("text", "content", "output") and v:
                                res = _find_text(v)
                                if res:
                                    return res
                        for v in obj.values():
                            res = _find_text(v)
                            if res:
                                return res
                    if isinstance(obj, list):
                        for item in obj:
                            res = _find_text(item)
                            if res:
                                return res
                    return None

                t = _find_text(response)
                if t:
                    return str(t)

        except Exception:
            # Be conservative; fall through to default
            pass

        # Fallback: stringify response
        try:
            return str(response)
        except Exception:
            return ""

    def _prepare_analysis_prompt(self, threat_data: Dict[str, Any]) -> str:
        """Prepare detailed prompt for Gemini analysis with all API results"""

        input_val = threat_data.get("input", "Unknown")
        input_type = threat_data.get("input_type", "Unknown")
        verdict = threat_data.get("verdict", "unknown")
        confidence = threat_data.get("confidence", 0.0)
        threats = threat_data.get("threat_indicators", [])
        api_results = threat_data.get("api_results", {})

        # Format threat indicators with details
        if threats:
            threat_details = []
            for t in threats:
                if isinstance(t, str):
                    severity = "UNKNOWN"
                    source = "Unknown"
                    indicator = t
                    extra = []
                else:
                    severity = t.get("severity", "unknown").upper()
                    source = t.get("source", "Unknown")
                    indicator = t.get("indicator", "No details")
                    extra = []
                    if "score" in t:
                        extra.append(f"Score: {t['score']}")
                    if "count" in t:
                        extra.append(f"Count: {t['count']}")
                extra_str = f" ({', '.join(extra)})" if extra else ""
                threat_details.append(f"  - [{severity}] {source}: {indicator}{extra_str}")
            threats_str = "\n".join(threat_details)
        else:
            threats_str = "  No threats detected"

        # Format detailed API results
        api_details = []
        apis_called = api_results.get("apis_called", [])
        
        # AbuseIPDB Details
        if "abuseipdb" in api_results and api_results["abuseipdb"]:
            abuse_data = api_results["abuseipdb"].get("data", {})
            if abuse_data:
                api_details.append(f"""
AbuseIPDB Analysis:
  - Abuse Confidence: {abuse_data.get('abuseConfidenceScore', 0)}%
  - Total Reports: {abuse_data.get('totalReports', 0)}
  - Country: {abuse_data.get('countryCode', 'Unknown')}
  - ISP: {abuse_data.get('isp', 'Unknown')}
  - Domain: {abuse_data.get('domain', 'None')}
  - Usage: {abuse_data.get('usageType', 'Unknown')}
  - Last Report: {abuse_data.get('lastReportedAt', 'Never')}""")

        # Shodan Details
        if "shodan" in api_results and api_results["shodan"]:
            shodan_data = api_results["shodan"]
            if not shodan_data.get("error"):
                ports = shodan_data.get("ports", [])
                vulns = shodan_data.get("vulns", [])
                api_details.append(f"""
Shodan Analysis:
  - Organization: {shodan_data.get('org', 'Unknown')}
  - Country: {shodan_data.get('country_name', 'Unknown')}
  - OS: {shodan_data.get('os', 'Unknown')}
  - Open Ports: {', '.join(map(str, ports[:10])) if ports else 'None'}
  - Vulnerabilities: {len(vulns)} found
  - Hostnames: {', '.join(shodan_data.get('hostnames', [])[:3]) or 'None'}""")

        # VirusTotal Details
        if "virustotal" in api_results and api_results["virustotal"]:
            vt_data = api_results["virustotal"]
            if "data" in vt_data:
                attrs = vt_data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                api_details.append(f"""
VirusTotal Analysis:
  - Malicious: {stats.get('malicious', 0)} engines
  - Suspicious: {stats.get('suspicious', 0)} engines
  - Undetected: {stats.get('undetected', 0)} engines
  - Harmless: {stats.get('harmless', 0)} engines
  - Total Engines: {sum(stats.values())}
  - Reputation: {attrs.get('reputation', 0)}""")

        # URLScan Details
        if "urlscan" in api_results and api_results["urlscan"]:
            url_data = api_results["urlscan"]
            if "verdicts" in url_data:
                overall = url_data.get("verdicts", {}).get("overall", {})
                api_details.append(f"""
URLScan Analysis:
  - Risk Score: {overall.get('score', 0)}
  - Malicious: {overall.get('malicious', False)}
  - Categories: {', '.join(overall.get('categories', [])) or 'None'}
  - Brands: {', '.join(url_data.get('brands', [])[:5]) or 'None'}
  - Tags: {', '.join(url_data.get('tags', [])[:5]) or 'None'}""")

        # Hybrid Analysis Details
        if "hybrid_analysis" in api_results and api_results["hybrid_analysis"]:
            ha_data = api_results["hybrid_analysis"]
            if "results" in ha_data and ha_data["results"]:
                item = ha_data["results"][0]
                api_details.append(f"""
Hybrid Analysis:
  - Verdict: {item.get('verdict', 'Unknown')}
  - Threat Score: {item.get('threat_score', 0)}/100
  - Malware Family: {item.get('vx_family', 'Unknown')}
  - Environment: {item.get('environment_description', 'Unknown')}""")

        api_results_str = "\n".join(api_details) if api_details else "No detailed API data available"

        # Format forensic metadata
        forensic_metadata = threat_data.get("forensic_metadata", {})
        report_type = self._normalize_report_type(threat_data.get("report_type", "executive_summary"))
        report_timezone = self._resolve_timezone_name(threat_data)
        generated_at = self._format_timestamp_for_report(threat_data.get("timestamp"), report_timezone)
        time_range_label = self._report_time_window_label(threat_data)
        interval_summary_text = self._format_interval_summary_text(threat_data)
        behavioral_sequence_text = self._format_behavioral_sequence(threat_data)
        forensic_str = ""
        if forensic_metadata and forensic_metadata.get("corroboration_count") is not None:
            corroboration_count = forensic_metadata.get("corroboration_count", 0)
            corroboration_met = forensic_metadata.get("corroboration_threshold_met", False)
            unique_sources = forensic_metadata.get("unique_sources", [])
            total_indicators = forensic_metadata.get("total_indicators", 0)
            critical_indicators = forensic_metadata.get("critical_indicators", 0)
            medium_indicators = forensic_metadata.get("medium_indicators", 0)
            low_indicators = forensic_metadata.get("low_indicators", 0)
            
            forensic_str = f"""
FORENSIC RELIABILITY ANALYSIS:
- Evidence Sources: {', '.join(unique_sources) if unique_sources else 'None'}
- Corroboration Count: {corroboration_count} sources
- Forensic Threshold Met: {'YES (≥2 sources)' if corroboration_met else 'NO (single source - manual review recommended)'}
- Total Threat Indicators: {total_indicators}
  * Critical: {critical_indicators}
  * Medium: {medium_indicators}
  * Low: {low_indicators}
- Reliability Rating: {'HIGH - Multi-source corroboration' if corroboration_met else 'MODERATE - Single source detection'}
"""

        prompt = f"""
You are a senior cybersecurity threat analyst. Analyze this security scan and provide a professional report.

TARGET INFORMATION:
- Target: {input_val}
- Type: {input_type}
- Report Generated At: {generated_at}
- Report Timezone: {report_timezone}
- Time Range Covered: {time_range_label}
- Report Type: {report_type}
- Interval Coverage:
{interval_summary_text}

INITIAL VERDICT:
- Assessment: {verdict.upper()}
- Confidence: {confidence * 100:.1f}%
{forensic_str}
BEHAVIORAL SEQUENCE:
{behavioral_sequence_text}

THREAT INDICATORS:
{threats_str}

DETAILED API RESULTS:
{api_results_str}

APIs Used: {', '.join(apis_called) if apis_called else 'None'}

{self._report_schema_for_prompt(report_type)}

Global constraints:
- Use only supplied data and explicitly mark missing values as unavailable.
- Never invent threat indicators, API outputs, evidence sources, or timestamps.
- Keep section headers explicit and match requested schema.
- Distinguish observations from interpretation where relevant.
- Keep professional, factual wording. Target 650-1100 words for technical/forensic, 450-800 for executive.
- Do not answer with a single short paragraph; expand each required section with at least 2 complete sentences.
- For technical and forensic reports, include the requested headings in order and provide enough detail to exceed 300 words when data is available.
- If a section has limited source data, explain the limitation rather than compressing the whole report into a brief summary.
"""

        return prompt

    def _get_fallback_analysis(self, threat_data: Dict[str, Any]) -> str:
        """Generate detailed fallback analysis when Gemini is unavailable"""

        report_type = self._normalize_report_type(threat_data.get("report_type", "executive_summary"))
        verdict = threat_data.get("verdict", "unknown").upper()
        confidence_value = threat_data.get("confidence", 0.0)
        if confidence_value is None:
            confidence_value = 0.0
        try:
            confidence = float(confidence_value) * 100
        except (TypeError, ValueError):
            confidence = 0.0

        threats = threat_data.get("threat_indicators", [])
        api_results = threat_data.get("api_results", {})
        input_val = threat_data.get("input", "Unknown")
        input_type = threat_data.get("input_type", "Unknown")
        forensic_metadata = threat_data.get("forensic_metadata", {})
        detection_coverage = self._build_detection_coverage_overview(threat_data)
        apis_called = api_results.get("apis_called", [])
        report_timezone = self._resolve_timezone_name(threat_data)
        generated_at = self._format_timestamp_for_report(threat_data.get("timestamp"), report_timezone)
        time_range_label = self._report_time_window_label(threat_data)
        interval_summary_text = self._format_interval_summary_text(threat_data)
        behavioral_sequence_text = self._format_behavioral_sequence(threat_data)

        if apis_called:
            coverage_line = (
                f"The target has been assessed as {verdict} with {confidence:.1f}% confidence based on "
                f"{len(apis_called)} security intelligence source(s): {', '.join(apis_called)}."
            )
        else:
            coverage_line = (
                f"The target has been assessed as {verdict} with {confidence:.1f}% confidence based on "
                "available local and heuristic analysis (external API corroboration unavailable)."
            )

        coverage_methods = detection_coverage.get("method_names", []) if isinstance(detection_coverage, dict) else []
        coverage_methods_text = ", ".join(coverage_methods[:12]) if coverage_methods else "No structured local analysis methods were available in the report payload."
        fallback_reason = detection_coverage.get("fallback_reason") if isinstance(detection_coverage, dict) else ""
        api_summary = detection_coverage.get("api_summary") if isinstance(detection_coverage, dict) else ""

        if report_type == "technical_analysis":
            analysis = f"""## TECHNICAL VERDICT SUMMARY

Target: {input_val} (Type: {input_type})
Assessment: {verdict}
Confidence: {confidence:.1f}%
Report Generated At: {generated_at}
Report Timezone: {report_timezone}
Time Range Covered: {time_range_label}

{coverage_line}

## DETECTION COVERAGE AND FALLBACK MODE

- Analysis mode: {str(detection_coverage.get('mode', 'unknown')).replace('_', ' ').title()}
- Local methods: {coverage_methods_text}
- External API coverage: {api_summary or 'Unavailable'}
{'- Fallback reason: ' + str(fallback_reason) if fallback_reason else ''}

## DETECTION PIPELINE BREAKDOWN

{interval_summary_text}

## BEHAVIORAL SEQUENCE SUMMARY

{behavioral_sequence_text}

## TECHNICAL RISK CONTEXT

- Primary engineering concern: {'active threat behavior requiring containment controls' if verdict in {'MALICIOUS', 'SUSPICIOUS'} else 'no immediate malicious behavior observed; continue control validation'}.
- Detection surface quality: {'multi-signal correlation available' if threats else 'limited signal density in current window'}.
- Key technical objective: reduce detection blind spots, strengthen corroboration coverage, and improve triage precision.

## CONTROL AND DETECTION ENGINEERING NOTES

- Validate static indicators (signatures, entropy, IOC extraction) against runtime telemetry before suppressing alerts.
- Review endpoint and network controls for policy gaps exposed in the selected interval windows.
- Prioritize improvements to rules producing high-volume low-confidence suspicious findings.

## TECHNICAL ACTIONS

1. Review PE/COFF and signature findings first.
2. Validate any high-entropy or packed sections against the runtime behavior.
3. Tune detections for the observed IOC patterns and API coverage gaps.

## TECHNICAL INTERPRETATION

- This analysis is intended to explain how the technical conclusion was reached, not just what the conclusion is.
- Static, behavioral, and intelligence-derived signals should be read together; no single field should be treated as conclusive when corroboration is weak.
- When the window contains repeated or clustered indicators, engineering teams should treat that as a signal to inspect rule coverage, exception logic, and missing telemetry rather than only the verdict label.
- If the finding is malicious or suspicious, the technical priority is to identify the control gap that allowed the signal to surface and to reduce recurrence with measurable validation.

"""
        elif report_type == "forensic_investigation":
            analysis = f"""## CASE OVERVIEW

Case Subject: {input_val} (Type: {input_type})
Primary Assessment: {verdict}
Confidence: {confidence:.1f}%
Report Generated At: {generated_at}
Report Timezone: {report_timezone}
Time Range Covered: {time_range_label}

## SCOPE AND EVIDENCE CONTEXT

{coverage_line}

## DETECTION COVERAGE AND FALLBACK MODE

- Analysis mode: {str(detection_coverage.get('mode', 'unknown')).replace('_', ' ').title()}
- Local methods: {coverage_methods_text}
- External API coverage: {api_summary or 'Unavailable'}
{'- Fallback reason: ' + str(fallback_reason) if fallback_reason else ''}

## TIMELINE WINDOW SUMMARY

{interval_summary_text}

## BEHAVIORAL SEQUENCE

{behavioral_sequence_text}

## EVIDENCE INTEGRITY AND HANDLING

- Preserve original artifacts, timestamps, hashes, and source metadata before remediation actions.
- Maintain chain-of-custody notes for each indicator, including acquisition time and verification status.
- Separate observed facts from hypotheses and confidence statements in all investigation updates.

## INVESTIGATIVE INTERPRETATION

- Working hypothesis: {'adversarial or harmful activity is supported by available evidence' if verdict in {'MALICIOUS', 'SUSPICIOUS'} else 'no confirmed malicious activity in current evidence set'}.
- Alternative hypothesis: benign or test traffic may resemble suspicious patterns where corroboration is incomplete.
- Required follow-up: obtain additional independent corroboration before legal/compliance escalation for single-source findings.

## FORENSIC NOTES

1. Preserve source artifacts and hashes.
2. Reconcile indicator sources before remediation.
3. Treat single-source findings as lower-confidence leads.

## FORENSIC INTERPRETATION

- This dossier is written for investigative continuity: it preserves what was observed, when it was observed, and how the sources relate to one another.
- Independent corroboration materially strengthens evidentiary weight; a single-source result should be treated as investigatory, not definitive.
- Where the activity window shows repeated indicators, the report treats repetition as potential pattern evidence, but still distinguishes repetition from proof of attribution.
- The goal is to provide a defensible narrative that can support further investigation, documentation, and escalation without overstating certainty.

## EVIDENCE SUFFICIENCY

- Proven: the preserved timeline, source metadata, and reported indicators in the current scan window.
- Supported: the classification and reliability narrative based on available corroboration.
- Unresolved: attribution, intent, scope of compromise, and any claim that would require external validation or legal-grade confirmation.

"""
        else:
            analysis = f"""## EXECUTIVE OVERVIEW

Target: {input_val} (Type: {input_type})
Assessment: {verdict}
Confidence: {confidence:.1f}%
Report Generated At: {generated_at}
Report Timezone: {report_timezone}
Time Range Covered: {time_range_label}

{coverage_line}

## DETECTION COVERAGE AND FALLBACK MODE

- Analysis mode: {str(detection_coverage.get('mode', 'unknown')).replace('_', ' ').title()}
- Local methods: {coverage_methods_text}
- External API coverage: {api_summary or 'Unavailable'}
{'- Fallback reason: ' + str(fallback_reason) if fallback_reason else ''}

## ASSESSMENT SCOPE AND TIME CONTEXT

{interval_summary_text}

## OPERATIONAL TIMELINE

{behavioral_sequence_text}

## ENTERPRISE RISK NARRATIVE

- Current risk posture: {'elevated and requiring timely containment decisions' if verdict in {'MALICIOUS', 'SUSPICIOUS'} else 'stable with routine monitoring posture'}.
- Business exposure lens: assess service continuity risk, user trust impact, and potential compliance implications.
- Leadership intent: confirm accountability, deadlines, and escalation thresholds for remediation.

## DECISION SUPPORT BRIEF

- What changed: this interval shows the latest threat telemetry and activity concentration trends.
- Why it matters: unresolved suspicious or malicious findings can increase operational and governance risk.
- What is needed next: explicit ownership, 24-72 hour actions, and verification checkpoints.

## DECISION FOCUS

1. Validate containment urgency.
2. Communicate business impact.
3. Track follow-up actions and ownership.

## EXECUTIVE INTERPRETATION

- This summary is designed to answer three questions clearly: what happened, why it matters, and what leadership should do next.
- The report blends threat indicators, interval trend data, and corroboration strength so the business can act without needing to interpret raw telemetry.
- A malicious result means the organization should favor decisive containment and communication; a suspicious result means the organization should favor controlled validation and targeted monitoring.
- Even when the report falls back to local analysis, it remains a structured summary of the available evidence rather than a placeholder sentence.
"""

        analysis += "\n## FORENSIC RELIABILITY ASSESSMENT\n\n"

        # Add forensic metadata
        if forensic_metadata and forensic_metadata.get("corroboration_count") is not None:
            corroboration_count = forensic_metadata.get("corroboration_count", 0)
            corroboration_met = forensic_metadata.get("corroboration_threshold_met", False)
            unique_sources = forensic_metadata.get("unique_sources", [])
            total_indicators = forensic_metadata.get("total_indicators", len(threats))
            apis_checked_count = int(forensic_metadata.get("apis_checked", len(apis_called)) or 0)
            total_apis_available = int(forensic_metadata.get("total_apis_available", len(apis_called)) or 0)
            unavailable_reasons = forensic_metadata.get("external_corroboration_unavailable_reasons", [])
            
            if total_indicators == 0:
                analysis += f"**FORENSIC STATUS: BASELINE CLEAR**\n\n"
                analysis += "No threat indicators were identified in this scan. Corroboration thresholds are not applicable for clean results. "
                analysis += "Reliability is primarily reflected through scan coverage (number of completed checks and intelligence sources queried).\n\n"
            elif corroboration_met:
                analysis += f"**FORENSIC STATUS: HIGH RELIABILITY**\n\n"
                analysis += f"This threat assessment has been corroborated by {corroboration_count} independent security intelligence sources: {', '.join(unique_sources)}.\n\n"
                analysis += "Multi-source corroboration (≥2 sources) significantly increases the reliability and confidence of this assessment. "
                analysis += "The independent confirmation from multiple threat intelligence providers provides strong forensic evidence "
                analysis += "for the detected threats, making this assessment suitable for security incident documentation and compliance reporting.\n\n"
            elif corroboration_count == 1:
                analysis += f"**FORENSIC STATUS: LIMITED CORROBORATION**\n\n"
                analysis += f"This threat assessment is currently supported by one source: {', '.join(unique_sources) if unique_sources else 'N/A'}.\n\n"
                analysis += "⚠️ FORENSIC CAUTION: Single-source detection has moderate reliability. Obtain at least one independent confirmation "
                analysis += "before initiating irreversible remediation or legal/compliance actions.\n\n"
            else:
                if total_apis_available > 0 and apis_checked_count == 0:
                    analysis += f"**FORENSIC STATUS: EVIDENCE-LIMITED (EXTERNAL CORROBORATION UNAVAILABLE)**\n\n"
                    analysis += (
                        "Threat signals were detected, but relevant external corroboration sources were not reachable/configured for this scan window. "
                        "This is an evidence-availability limitation, not proof that the signal is false.\n\n"
                    )
                    if unavailable_reasons:
                        analysis += f"External corroboration blockers: {', '.join(unavailable_reasons)}.\n\n"
                    analysis += (
                        "⚠️ INVESTIGATION GUIDANCE: Preserve endpoint/network artifacts, re-run scan when API coverage is restored, and seek at least "
                        "one independent external confirmation before legal/compliance escalation.\n\n"
                    )
                elif apis_checked_count > 0:
                    analysis += f"**FORENSIC STATUS: API-CHECKED, NO POSITIVE CORROBORATION**\n\n"
                    analysis += (
                        "Threat signals were detected, but completed external checks did not independently confirm the same threat pattern. "
                        "Treat as investigational and continue evidence collection.\n\n"
                    )
                    analysis += "⚠️ FORENSIC CAUTION: Re-scan and validate with additional sources to reduce false positives and improve evidence quality.\n\n"
                else:
                    analysis += f"**FORENSIC STATUS: UNCORROBORATED**\n\n"
                    analysis += "Threat signals were detected, but no independent source corroboration is currently available.\n\n"
                    analysis += "⚠️ FORENSIC CAUTION: Re-scan and validate with additional sources to reduce false positives and improve evidence quality.\n\n"
            
            # Add indicator breakdown
            if total_indicators > 0:
                analysis += f"**Evidence Breakdown:**\n"
                analysis += f"- Total Threat Indicators: {total_indicators}\n"
                analysis += f"- Critical Severity: {forensic_metadata.get('critical_indicators', 0)}\n"
                analysis += f"- Medium Severity: {forensic_metadata.get('medium_indicators', 0)}\n"
                analysis += f"- Low Severity: {forensic_metadata.get('low_indicators', 0)}\n\n"
        else:
            analysis += "Forensic metadata not available for this scan.\n\n"

        if report_type == "forensic_investigation":
            analysis += "## ARTIFACT INVENTORY AND SOURCE RELIABILITY\n\n"
        elif report_type == "technical_analysis":
            analysis += "## DETAILED TECHNICAL ANALYSIS\n\n"
        else:
            analysis += "## LEADERSHIP DECISION CONTEXT\n\n"

        # Add API-specific findings
        if apis_called:
            analysis += f"This analysis utilized {len(apis_called)} security intelligence APIs: {', '.join(apis_called)}.\n\n"

        interval_summaries = threat_data.get("interval_summaries") or []
        if interval_summaries:
            analysis += "## INTERVAL COMPARISON\n\n"
            for item in interval_summaries:
                activity = item.get("activity") or {}
                vulns = item.get("vulns") or {}
                label = str(item.get("interval", "24h")).upper()
                analysis += (
                    f"- {label}: threat scans {activity.get('threat_scans', 0)}, threats detected {activity.get('threats_detected', 0)}, "
                    f"websites {activity.get('websites_visited', 0)}, applications {activity.get('applications_launched', 0)}, "
                    f"network connections {activity.get('network_connections', 0)}, endpoint vulnerabilities {vulns.get('total', 0) if isinstance(vulns, dict) else 0}.\n"
                )
            analysis += "\n"

        methods = self._get_analysis_methods_used(threat_data)
        if report_type != "executive_summary":
            analysis += "## ANALYSIS QUALITY MATRIX\n\n"
            if methods:
                for method in methods[:10]:
                    method_name = str(method.get("name", "Unknown"))
                    method_status = str(method.get("status", "UNKNOWN"))
                    method_details = str(method.get("details", ""))
                    analysis += f"- {method_name}: {method_status} | {method_details}\n"
                analysis += "\n"
            else:
                analysis += "- No method telemetry was available in the current payload.\n\n"
        else:
            analysis += "## EXECUTIVE KEY FINDINGS\n\n"
            analysis += f"- Overall verdict posture: {verdict}.\n"
            analysis += f"- Indicators identified in current assessment: {len(threats)}.\n"
            analysis += f"- Corroborating sources observed: {forensic_metadata.get('corroboration_count', 0)}.\n"
            analysis += f"- Immediate business action: {self._get_report_action_plan(threat_data)[0]}.\n\n"

        if report_type == "executive_summary":
            analysis += "## BUSINESS IMPACT SUMMARY\n\n"
            analysis += (
                f"- Operational impact posture: {'Elevated' if verdict in {'MALICIOUS', 'SUSPICIOUS'} else 'Routine'} risk.\n"
                f"- Control burden in selected intervals: {interval_summary_text}.\n"
                "- Leadership focus: containment decision, service continuity, and stakeholder communication cadence.\n\n"
            )
        elif report_type == "technical_analysis":
            analysis += "## ENGINEERING ANALYSIS TRACK\n\n"
            analysis += (
                "- Prioritize detector tuning for top indicators and correlate with endpoint vulnerability findings.\n"
                "- Validate scan telemetry coverage against required API and behavioral evidence paths.\n"
                "- Confirm rule efficacy with replay simulation before production rule promotion.\n\n"
            )
        else:
            analysis += "## EVIDENCE HANDLING AND CHAIN OF CUSTODY\n\n"
            analysis += (
                "- Preserve original timestamps, hashes, and source provenance before remediation actions.\n"
                "- Maintain immutable evidence lineage for each indicator and correlated event.\n"
                "- Record analyst actions and decision points for legal/compliance defensibility.\n\n"
            )

        # Analyze threat indicators
        if threats and report_type != "executive_summary":
            analysis += f"### Threat Indicators Detected ({len(threats)})\n\n"
            analysis += "The following security threats were identified during the scan:\n\n"
            
            # Group by severity
            critical_threats = [t for t in threats if t.get('severity') == 'critical']
            medium_threats = [t for t in threats if t.get('severity') == 'medium']
            low_threats = [t for t in threats if t.get('severity') == 'low']
            
            if critical_threats:
                analysis += "**CRITICAL THREATS:**\n"
                for threat in critical_threats:
                    source = threat.get('source', 'Unknown')
                    indicator = threat.get('indicator', 'No details')
                    analysis += f"- **{source}**: {indicator}\n"
                    if 'score' in threat:
                        analysis += f"  Risk Score: {threat['score']}\n"
                analysis += "\n"
            
            if medium_threats:
                analysis += "**MEDIUM THREATS:**\n"
                for threat in medium_threats:
                    source = threat.get('source', 'Unknown')
                    indicator = threat.get('indicator', 'No details')
                    analysis += f"- **{source}**: {indicator}\n"
                analysis += "\n"
            
            if low_threats:
                analysis += "**LOW-LEVEL THREATS:**\n"
                for threat in low_threats:
                    source = threat.get('source', 'Unknown')
                    indicator = threat.get('indicator', 'No details')
                    analysis += f"- **{source}**: {indicator}\n"
                analysis += "\n"
        elif report_type != "executive_summary":
            analysis += "### No Threats Detected\n\n"
            analysis += "No significant security threats were detected during the comprehensive scan across all security intelligence APIs.\n\n"

        # Add API-specific details
        if report_type == "forensic_investigation":
            analysis += "## TECHNICAL FINDINGS AND FORENSIC ARTIFACTS\n\n"
        elif report_type == "technical_analysis":
            analysis += "## TECHNICAL FINDINGS\n\n"
        else:
            analysis += "## BUSINESS IMPACT SIGNALS\n\n"
        
        if report_type != "executive_summary" and "abuseipdb" in api_results and api_results["abuseipdb"]:
            abuse_data = api_results["abuseipdb"].get("data", {})
            if abuse_data:
                score = abuse_data.get("abuseConfidenceScore", 0)
                analysis += f"**AbuseIPDB:**\n"
                analysis += f"- Abuse Confidence: {score}%\n"
                analysis += f"- Total Reports: {abuse_data.get('totalReports', 0)}\n"
                analysis += f"- ISP: {abuse_data.get('isp', 'Unknown')}\n"
                analysis += f"- Country: {abuse_data.get('countryCode', 'Unknown')}\n\n"

        if report_type != "executive_summary" and "shodan" in api_results and api_results["shodan"]:
            shodan_data = api_results["shodan"]
            if not shodan_data.get("error"):
                analysis += f"**Shodan:**\n"
                analysis += f"- Organization: {shodan_data.get('org', 'Unknown')}\n"
                analysis += f"- Open Ports: {len(shodan_data.get('ports', []))}\n"
                analysis += f"- Vulnerabilities: {len(shodan_data.get('vulns', []))}\n\n"

        if report_type != "executive_summary" and "virustotal" in api_results and api_results["virustotal"]:
            vt_data = api_results["virustotal"]
            if "data" in vt_data:
                stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                analysis += f"**VirusTotal:**\n"
                analysis += f"- Malicious Detections: {malicious}/{sum(stats.values())}\n"
                analysis += f"- Suspicious: {stats.get('suspicious', 0)}\n"
                analysis += f"- Clean: {stats.get('harmless', 0)}\n\n"

        analysis += "## RISK ASSESSMENT\n\n"
        
        if verdict == "MALICIOUS":
            risk_level = "CRITICAL"
            analysis += f"**Risk Level: {risk_level}**\n\n"
            analysis += "This target poses a critical security risk and should be treated with maximum caution. "
            analysis += "Immediate action is required to block or quarantine this threat.\n\n"
        elif verdict == "SUSPICIOUS":
            risk_level = "MEDIUM-HIGH"
            analysis += f"**Risk Level: {risk_level}**\n\n"
            analysis += "This target exhibits suspicious characteristics that warrant further investigation and caution. "
            analysis += "Consider implementing additional monitoring or blocking measures.\n\n"
        else:
            risk_level = "LOW"
            analysis += f"**Risk Level: {risk_level}**\n\n"
            analysis += "This target appears to be safe based on the current security assessments. "
            analysis += "However, continued monitoring is recommended as threats can emerge over time.\n\n"

        if report_type == "forensic_investigation":
            analysis += "## INVESTIGATION RECOMMENDATIONS\n\n"
        elif report_type == "technical_analysis":
            analysis += "## TECHNICAL RECOMMENDATIONS\n\n"
        else:
            analysis += "## EXECUTIVE 24-72 HOUR ACTIONS\n\n"
        
        if verdict == "MALICIOUS":
            analysis += "**Immediate Actions:**\n"
            analysis += "1. Block all traffic to/from this target immediately\n"
            analysis += "2. Investigate any systems that have communicated with this target\n"
            analysis += "3. Initiate incident response procedures\n"
            analysis += "4. Preserve logs and forensic data\n\n"
            analysis += "**Remediation:**\n"
            analysis += "1. Scan all affected systems for malware\n"
            analysis += "2. Reset credentials for potentially compromised accounts\n"
            analysis += "3. Review firewall and security policies\n"
            analysis += "4. Document the incident for future reference\n\n"
        elif verdict == "SUSPICIOUS":
            analysis += "**Recommended Actions:**\n"
            analysis += "1. Enable enhanced monitoring for this target\n"
            analysis += "2. Restrict access based on business requirements\n"
            analysis += "3. Conduct additional investigation if interaction is necessary\n"
            analysis += "4. Update threat intelligence feeds\n\n"
        else:
            analysis += "**General Recommendations:**\n"
            analysis += "1. Continue routine security monitoring\n"
            analysis += "2. Keep security policies up to date\n"
            analysis += "3. Maintain regular scan schedules\n"
            analysis += "4. Train staff on security awareness\n\n"

        if report_type == "technical_analysis":
            analysis += "**Engineering Priority Addendum:**\n"
            analysis += "1. Map each high-severity indicator to a concrete detection rule and test-case.\n"
            analysis += "2. Quantify false-positive pressure and tune thresholds with replay validation.\n"
            analysis += "3. Align endpoint, network, and intel telemetry to reduce single-source dependency.\n"
            analysis += "4. Track remediation completion with measurable control effectiveness metrics.\n\n"
        elif report_type == "forensic_investigation":
            analysis += "**Investigation Addendum:**\n"
            analysis += "1. Record evidence provenance for every artifact used in conclusion statements.\n"
            analysis += "2. Build a chronological event ledger linking observed activity to source evidence.\n"
            analysis += "3. Document confidence per claim and annotate uncertainty where corroboration is limited.\n"
            analysis += "4. Prepare legal/compliance-ready summary language with explicit evidentiary boundaries.\n\n"
        else:
            analysis += "**Leadership Addendum:**\n"
            analysis += "1. Assign accountable owners for containment, validation, and stakeholder communication.\n"
            analysis += "2. Require daily status checkpoints until risk posture returns to acceptable baseline.\n"
            analysis += "3. Confirm policy/process updates that prevent recurrence of the same threat pattern.\n"
            analysis += "4. Track residual risk and sign-off criteria for closure.\n\n"

        analysis += "## CONCLUSION\n\n"
        
        if threats:
            threat_summary = f"detected {len(threats)} threat indicator(s)"
        else:
            threat_summary = "found no significant threats"
        
        analysis += f"This comprehensive security analysis {threat_summary} "
        analysis += f"across multiple intelligence sources. "
        
        if verdict == "MALICIOUS":
            analysis += "The target represents a confirmed security threat requiring immediate action."
        elif verdict == "SUSPICIOUS":
            analysis += "The target exhibits characteristics that warrant caution and further investigation."
        else:
            analysis += "The target appears safe based on current intelligence, though ongoing monitoring is advised."

        if report_type == "executive_summary":
            analysis += (
                " Executive conclusion emphasis: leadership should treat this as a decision document, "
                "not a raw alert dump. The core question is whether the observed pattern changes risk, affects continuity, "
                "or requires immediate ownership and communication."
            )
        elif report_type == "technical_analysis":
            analysis += (
                " Technical conclusion emphasis: the important outcome is not only the verdict itself, but which control layers "
                "observed the activity, where telemetry was weak, and which engineering changes will reduce future ambiguity."
            )
        else:
            analysis += (
                " Forensic conclusion emphasis: preserve the evidence trail, separate verified observations from inference, "
                "and keep the narrative defensible for internal review, compliance, or legal follow-up."
            )

        analysis += f"\n\nConfidence Level: {confidence:.1f}%\n"
        analysis += f"APIs Consulted: {', '.join(apis_called) if apis_called else 'None'}\n"
        analysis += f"Observed Threat Indicators: {len(threats)}\n"
        analysis += f"Corroborating Sources: {forensic_metadata.get('corroboration_count', 0)}\n"
        analysis += "\n## ANALYSIS PROVENANCE AND LIMITATIONS\n\n"
        if report_type == "executive_summary":
            analysis += (
                "This executive report was produced from available local telemetry, interval trend data, and corroboration metadata at generation time. "
                "It is intended to consolidate the organization’s current risk picture into a business-friendly narrative that can guide decisions. "
                "If external intelligence was limited, the report retains the operational signal, explains the uncertainty in plain language, and avoids overstating confidence. "
                "That makes it useful for leadership review, incident prioritization, and follow-up ownership even when the evidence is incomplete.\n\n"
            )
        elif report_type == "technical_analysis":
            analysis += (
                "This technical report was produced from available local telemetry, detection-method outputs, and interval coverage artifacts captured at generation time. "
                "It should be read as an engineering explanation of the detection chain: which signals fired, what they matched, what the interval history looks like, and where the evidence is strong or weak. "
                "Engineering actions should prioritize controls with the strongest corroboration, but the report also preserves lower-confidence items so they can be re-tested rather than discarded. "
                "If the report fell back to local analysis, the system still reconstructed the most defensible technical narrative from the data available at that moment.\n\n"
            )
        else:
            analysis += (
                "This forensic report was produced from available local telemetry, source-correlation metadata, and preserved timeline artifacts captured at generation time. "
                "It is meant to support investigation continuity by documenting the sequence of events, the relationship between indicators, and the evidence that links one observation to the next. "
                "Where corroboration is incomplete, the report explicitly distinguishes supported observations from interpretive conclusions. "
                "Claims that would affect legal, compliance, or disciplinary decisions should still be reinforced with independent corroboration wherever feasible.\n\n"
            )

        return analysis

    def _get_report_action_plan(self, threat_analysis: Dict[str, Any]) -> list[str]:
        """Return a concise prioritized action plan for professional reports."""
        recommendations = threat_analysis.get("recommendations") or []
        if recommendations:
            return [str(item).strip() for item in recommendations if str(item).strip()][:5]

        verdict = str(threat_analysis.get("verdict", "unknown")).lower()
        if verdict in {"malicious", "critical"}:
            return [
                "Isolate or block the target immediately.",
                "Review affected hosts, sessions, and recent communications.",
                "Preserve logs and forensic evidence for follow-up analysis.",
                "Open an incident ticket and track containment actions.",
            ]
        if verdict == "suspicious":
            return [
                "Place the target under enhanced monitoring.",
                "Validate business need before allowing further interaction.",
                "Collect corroborating telemetry from endpoint, proxy, and DNS logs.",
                "Escalate to analyst review if activity persists.",
            ]
        return [
            "No immediate containment is required.",
            "Keep the target in routine monitoring baselines.",
            "Retain this assessment for audit and trend reporting.",
        ]

    def _get_api_coverage_rows(self, threat_analysis: Dict[str, Any]) -> list[list[str]]:
        """Build report rows summarizing which intelligence sources participated."""
        input_type = str(threat_analysis.get("input_type") or "").strip().lower()
        api_results = threat_analysis.get("api_results", {}) if isinstance(threat_analysis.get("api_results"), dict) else {}
        api_status = api_results.get("api_status", {}) if isinstance(api_results.get("api_status"), dict) else {}
        rows = [["Source", "Status", "Configured", "Applicable"]]

        provider_meta = [
            ("virustotal", "VirusTotal"),
            ("abuseipdb", "AbuseIPDB"),
            ("shodan", "Shodan"),
            ("urlscan", "URLScan.io"),
            ("hybrid_analysis", "Hybrid Analysis"),
        ]
        for api_key, fallback_name in provider_meta:
            api_meta = api_status.get(api_key, {}) if isinstance(api_status, dict) else {}
            api_data = api_results.get(api_key)
            if not isinstance(api_meta, dict):
                api_meta = {}
            raw_status = str(api_meta.get("status", "not_executed") or "not_executed").strip().lower()
            configured = bool(api_meta.get("configured", bool(api_data)))
            applicable = bool(api_meta.get("applicable", input_type not in {"advanced_report"}))
            if raw_status in {"success", "completed", "ok", "checked", "online", "available", "clean", "no_threat"}:
                status = "Data collected"
            elif raw_status in {"rate_limited", "quota_exceeded"}:
                status = "Quota limited; fallback intelligence used"
            elif raw_status in {"error", "failed", "timeout"}:
                status = "Collection failed; fallback intelligence used"
            elif raw_status in {"pending", "in_progress", "queued"}:
                status = "Provider analysis did not complete in this scan window"
            elif raw_status == "skipped_local_mode":
                status = "External APIs disabled for local-only analysis"
            else:
                reason = []
                if not configured:
                    reason.append("not configured")
                if not applicable:
                    reason.append("out of scope")
                status = f"Fallback intelligence used ({', '.join(reason) if reason else 'provider unavailable'})"
            rows.append(
                [
                    str(api_meta.get("name", fallback_name)),
                    status,
                    "Yes" if configured else "No",
                    "Yes" if applicable else "No",
                ]
            )

        if input_type == "advanced_report":
            rows.append(["Local telemetry", "Used for IDS/IPS and activity analysis", "Yes", "Yes"])

        return rows

    def _get_endpoint_vuln_summary(self, hours: int = 24) -> Optional[Dict[str, int]]:
        """Summarize endpoint vulnerability findings from local activity_logs DB.

        Returns per-severity counts for the requested time window, or None when
        no vulnerability table/data is available.
        """
        try:
            project_root = Path(__file__).resolve().parents[3]
            candidates = [
                project_root / "activity_logs.db",
                project_root / "server" / "activity_logs.db",
                project_root / "client" / "activity_logs.db",
            ]

            cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

            for db_path in candidates:
                if not db_path.exists():
                    continue

                conn = sqlite3.connect(str(db_path))
                try:
                    cur = conn.cursor()
                    cur.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='vulnerabilities'"
                    )
                    if not cur.fetchone():
                        continue

                    cur.execute(
                        """
                        SELECT UPPER(COALESCE(severity, 'INFO')) as sev, COUNT(*)
                        FROM vulnerabilities
                        WHERE timestamp >= ?
                        GROUP BY UPPER(COALESCE(severity, 'INFO'))
                        """,
                        (cutoff,),
                    )
                    rows = cur.fetchall()
                    if not rows:
                        continue

                    counts = {sev: int(cnt) for sev, cnt in rows}
                    summary = {
                        "critical": counts.get("CRITICAL", 0),
                        "high": counts.get("HIGH", 0),
                        "medium": counts.get("MEDIUM", 0),
                        "low": counts.get("LOW", 0),
                        "info": counts.get("INFO", 0),
                    }
                    summary["total"] = sum(summary.values())
                    return summary
                finally:
                    conn.close()

            return None
        except Exception as e:
            logger.debug(f"Could not read endpoint vulnerability summary: {e}")
            return None

    def _create_pdf_report(
        self, threat_analysis: Dict[str, Any], ai_analysis: str
    ) -> bytes:
        """Create PDF report using ReportLab"""

        from io import BytesIO

        # Create PDF in memory
        pdf_buffer = BytesIO()
        doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)

        report_type = self._normalize_report_type(threat_analysis.get("report_type", "executive_summary"))
        is_executive_report = report_type == "executive_summary"
        is_technical_report = report_type == "technical_analysis"
        is_forensic_report = report_type == "forensic_investigation"

        profile_palette = {
            "executive_summary": {
                "title": colors.HexColor("#12355b"),
                "heading": colors.HexColor("#0b5cab"),
                "accent": colors.HexColor("#1d4ed8"),
                "table_header": colors.HexColor("#1e3a8a"),
                "soft": colors.HexColor("#eff6ff"),
            },
            "technical_analysis": {
                "title": colors.HexColor("#1f2937"),
                "heading": colors.HexColor("#0f766e"),
                "accent": colors.HexColor("#0f766e"),
                "table_header": colors.HexColor("#115e59"),
                "soft": colors.HexColor("#ecfeff"),
            },
            "forensic_investigation": {
                "title": colors.HexColor("#3f1d2e"),
                "heading": colors.HexColor("#7c2d12"),
                "accent": colors.HexColor("#7c2d12"),
                "table_header": colors.HexColor("#7c2d12"),
                "soft": colors.HexColor("#fff7ed"),
            },
        }.get(report_type, {
            "title": colors.HexColor("#1a1a1a"),
            "heading": colors.HexColor("#0066cc"),
            "accent": colors.HexColor("#0f172a"),
            "table_header": colors.HexColor("#0f172a"),
            "soft": colors.HexColor("#f8fafc"),
        })

        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            textColor=profile_palette["title"],
            spaceAfter=6,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        )

        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading2"],
            fontSize=14,
            textColor=profile_palette["heading"],
            spaceAfter=12,
            spaceBefore=12,
            fontName="Helvetica-Bold",
        )

        normal_style = ParagraphStyle(
            "CustomNormal",
            parent=styles["Normal"],
            fontSize=10,
            spaceAfter=8,
            leading=14,
            wordWrap="CJK",
        )

        table_cell_style = ParagraphStyle(
            "TableCell",
            parent=normal_style,
            fontSize=8.6,
            leading=10.5,
            spaceAfter=0,
            wordWrap="CJK",
        )

        table_header_cell_style = ParagraphStyle(
            "TableHeaderCell",
            parent=table_cell_style,
            fontName="Helvetica-Bold",
            textColor=colors.whitesmoke,
        )

        def _linkify_text(value: Any) -> str:
            text = str(value or "-")
            escaped = (
                text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
            pattern = re.compile(r"(https?://[^\s<]+|hxxps?://[^\s<]+)", re.IGNORECASE)

            def _repl(match: re.Match) -> str:
                display = match.group(0)
                href = display.replace("hxxps://", "https://").replace("hxxp://", "http://")
                return f'<link href="{href}" color="blue">{display}</link>'

            return pattern.sub(_repl, escaped)

        def _cell(value: Any, header: bool = False) -> Paragraph:
            style = table_header_cell_style if header else table_cell_style
            return Paragraph(_linkify_text(value), style)

        def _wrap_rows(rows: list[list[Any]], header_rows: int = 1) -> list[list[Any]]:
            wrapped = []
            for row_index, row in enumerate(rows):
                wrapped.append([_cell(col, header=row_index < header_rows) for col in row])
            return wrapped

        def _shorten_text(value: Any, limit: int = 120) -> str:
            text = str(value or "")
            text = text.replace("\n", " ").replace("\r", " ").strip()
            if len(text) <= limit:
                return text
            return text[: max(0, limit - 3)].rstrip() + "..."

        emphasis_style = ParagraphStyle(
            "Emphasis",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#2f3b52"),
            backColor=profile_palette["soft"],
            borderPadding=8,
        )

        section_badge_style = ParagraphStyle(
            "SectionBadge",
            parent=styles["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#ffffff"),
            backColor=profile_palette["accent"],
            borderPadding=6,
            alignment=TA_CENTER,
            spaceAfter=8,
        )

        # Build document elements
        elements = []

        # Header
        header_title = {
            "executive_summary": "SENTINEL-AI EXECUTIVE RISK REPORT",
            "technical_analysis": "SENTINEL-AI TECHNICAL ANALYSIS REPORT",
            "forensic_investigation": "SENTINEL-AI FORENSIC INVESTIGATION REPORT",
        }.get(report_type, "SENTINEL-AI THREAT ANALYSIS REPORT")
        elements.append(Paragraph(header_title, title_style))
        badge_text = {
            "executive_summary": "Leadership Decision Brief",
            "technical_analysis": "Engineering and SOC Deep-Dive",
            "forensic_investigation": "Evidence-Centric Investigation Dossier",
        }.get(report_type, "Threat Analysis")
        elements.append(Paragraph(badge_text, section_badge_style))
        elements.append(Spacer(1, 0.2 * inch))

        # Report Info
        timestamp = threat_analysis.get("timestamp", datetime.now(timezone.utc).isoformat())
        report_timezone = self._resolve_timezone_name(threat_analysis)
        generated_at = self._format_timestamp_for_report(timestamp, report_timezone)
        time_range_label = self._report_time_window_label(threat_analysis)
        input_val = threat_analysis.get("input", "Unknown")
        input_type = threat_analysis.get("input_type", "Unknown")
        verdict = threat_analysis.get("verdict", "unknown")
        confidence_value = threat_analysis.get("confidence", 0.0)
        if confidence_value is None:
            confidence_value = 0.0
        try:
            confidence = float(confidence_value)
        except (TypeError, ValueError):
            confidence = 0.0
        verdict_key = str(verdict).lower()
        
        # Forensic metadata
        forensic_metadata = threat_analysis.get("forensic_metadata", {})
        corroboration_count = forensic_metadata.get("corroboration_count", 0)
        corroboration_met = forensic_metadata.get("corroboration_threshold_met", False)
        threat_indicators_count = len(threat_analysis.get("threat_indicators", []))
        apis_checked_count = int(forensic_metadata.get("apis_checked", 0) or 0)
        total_apis_available = int(forensic_metadata.get("total_apis_available", 0) or 0)

        verdict_palette = {
            "safe": {"bg": colors.HexColor("#e8f5e9"), "fg": colors.HexColor("#1b5e20")},
            "clean": {"bg": colors.HexColor("#e8f5e9"), "fg": colors.HexColor("#1b5e20")},
            "malicious": {"bg": colors.HexColor("#fff3e0"), "fg": colors.HexColor("#e65100")},
            "suspicious": {"bg": colors.HexColor("#ffebee"), "fg": colors.HexColor("#b71c1c")},
        }
        verdict_style = verdict_palette.get(verdict_key, {"bg": colors.HexColor("#eceff1"), "fg": colors.HexColor("#263238")})

        if threat_indicators_count == 0:
            forensic_threshold_text = "N/A (no threat indicators)"
            forensic_cell_bg = colors.HexColor("#e8f5e9")
            forensic_cell_fg = colors.HexColor("#1b5e20")
        elif corroboration_met:
            forensic_threshold_text = "YES (multi-source corroborated)"
            forensic_cell_bg = colors.HexColor("#e8f5e9")
            forensic_cell_fg = colors.HexColor("#1b5e20")
        elif corroboration_count == 1:
            forensic_threshold_text = "NO (single source - limited reliability)"
            forensic_cell_bg = colors.HexColor("#fff3e0")
            forensic_cell_fg = colors.HexColor("#e65100")
        else:
            if total_apis_available > 0 and apis_checked_count == 0:
                forensic_threshold_text = "NO (external corroboration unavailable)"
                forensic_cell_bg = colors.HexColor("#fff8e1")
                forensic_cell_fg = colors.HexColor("#8d6e63")
            elif apis_checked_count > 0:
                forensic_threshold_text = "NO (API-checked, no positive corroboration)"
                forensic_cell_bg = colors.HexColor("#ffebee")
                forensic_cell_fg = colors.HexColor("#b71c1c")
            else:
                forensic_threshold_text = "NO (uncorroborated)"
                forensic_cell_bg = colors.HexColor("#ffebee")
                forensic_cell_fg = colors.HexColor("#b71c1c")

        info_data = [
            ["Report Generated:", generated_at],
            ["Timezone:", report_timezone],
            ["Time Range Covered:", time_range_label],
            ["Target:", input_val],
            ["Target Type:", input_type.upper()],
            ["Report Profile:", report_type.replace("_", " ").title()],
            ["Verdict:", verdict.upper()],
            ["Confidence:", f"{confidence * 100:.1f}%"],
            ["Sources Corroborating:", str(corroboration_count)],
            ["Forensic Threshold Met:", forensic_threshold_text],
        ]
        info_data_wrapped = [[_cell(label), _cell(value)] for label, value in info_data]
        info_table = Table(info_data_wrapped, colWidths=[2 * inch, 4 * inch])
        info_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), profile_palette["soft"]),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ("BACKGROUND", (1, 6), (1, 6), verdict_style["bg"]),
                    ("TEXTCOLOR", (1, 6), (1, 6), verdict_style["fg"]),
                    ("FONTNAME", (1, 6), (1, 6), "Helvetica-Bold"),
                    ("BACKGROUND", (1, 9), (1, 9), forensic_cell_bg),
                    ("TEXTCOLOR", (1, 9), (1, 9), forensic_cell_fg),
                    ("FONTNAME", (1, 9), (1, 9), "Helvetica-Bold"),
                ]
            )
        )

        elements.append(info_table)
        elements.append(Spacer(1, 0.3 * inch))

        threats = threat_analysis.get("threat_indicators", [])
        scan_records = self._build_scan_records(threat_analysis)
        executive_insights = self._build_executive_insights(threat_analysis)
        forensic_intelligence = self._build_forensic_intelligence(threat_analysis)
        action_plan = self._get_report_action_plan(threat_analysis)
        is_advanced_report = str(threat_analysis.get("input_type") or "").strip().lower() == "advanced_report"
        file_analysis = self._normalize_file_analysis(threat_analysis)
        risk_contract = file_analysis.get("risk_contract", {}) if isinstance(file_analysis.get("risk_contract"), dict) else {}
        if is_advanced_report and not risk_contract:
            risk_contract = {
                "numeric_score": round(float(confidence or 0.0) * 100.0, 1),
                "confidence": f"{float(confidence or 0.0) * 100.0:.1f}%",
                "reason_codes": [],
            }
        reason_codes = risk_contract.get("reason_codes", []) if isinstance(risk_contract.get("reason_codes"), list) else []
        executive_snapshot = (
            f"<b>Executive Snapshot:</b> Verdict <b>{verdict.upper()}</b> with "
            f"confidence <b>{confidence * 100:.1f}%</b>. The assessment recorded "
            f"<b>{len(threats)}</b> threat indicator(s), <b>{forensic_metadata.get('apis_checked', 0)}</b> "
            f"relevant API check(s), and a corroboration count of "
            f"<b>{forensic_metadata.get('corroboration_count', 0)}</b>. "
            f"Primary operator action: <b>{action_plan[0]}</b>"
        )
        elements.append(Paragraph(executive_snapshot, emphasis_style))
        elements.append(Spacer(1, 0.15 * inch))

        interval_summaries = threat_analysis.get("interval_summaries") or self._build_interval_summaries(threat_analysis)
        selected_window = interval_summaries[0] if interval_summaries else {}
        selected_interval = str(selected_window.get("interval", "24h")).lower() if isinstance(selected_window, dict) else "24h"
        interval_hours_map = {"24h": 24, "7d": 24 * 7, "30d": 24 * 30}
        selected_hours = interval_hours_map.get(selected_interval, 24)

        outline_rows = [["Report Purpose", self._report_purpose_text(report_type)]]
        for index, (section_name, section_purpose) in enumerate(self._report_outline_items(report_type), start=1):
            outline_rows.append([f"{index}. {section_name}", section_purpose])

        elements.append(Paragraph("REPORT OUTLINE", heading_style))
        outline_table = Table(_wrap_rows(outline_rows), colWidths=[2.0 * inch, 4.0 * inch])
        outline_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, profile_palette["soft"]]),
            ("FONTSIZE", (0, 0), (-1, -1), 8.7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(outline_table)
        elements.append(Spacer(1, 0.18 * inch))

        report_focus_rows = []
        report_focus_title = ""
        if report_type == "executive_summary":
            report_focus_title = "EXECUTIVE DECISION SNAPSHOT"
            report_focus_rows = [
                ["Decision posture", "Containment recommended" if verdict_key in {"malicious", "suspicious"} else "Monitoring recommended"],
                ["Risk signal", verdict.upper()],
                ["Confidence", f"{confidence * 100:.1f}%"],
                ["Primary action", action_plan[0] if action_plan else "Continue monitoring"],
                ["Corroboration", f"{corroboration_count} source(s)"],
            ]
        elif report_type == "technical_analysis":
            report_focus_title = "TECHNICAL FINDINGS MATRIX"
            behavioral_events = threat_analysis.get('behavioral_sequence', []) or threat_analysis.get('forensic_metadata', {}).get('behavioral_sequence', []) or []
            api_call_count = len(threat_analysis.get('api_results', {}).get('apis_called', []) or [])
            if is_advanced_report:
                total_scan_events = sum(int((item.get('activity') or {}).get('threat_scans', 0) or 0) for item in interval_summaries if isinstance(item, dict))
                report_focus_title = "TELEMETRY EVIDENCE MATRIX"
                report_focus_rows = [
                    ["IDS / IPS verdict", f"{verdict.upper()} | {confidence * 100:.1f}% confidence"],
                    ["Activity logging", f"{len(interval_summaries)} interval window(s), {total_scan_events} scan event(s)"],
                    ["Behavioral events", str(len(behavioral_events))],
                    ["Threat intel APIs", f"{api_call_count} API source(s)"],
                    ["IOC / indicator correlation", f"{len(threats)} indicator(s), {forensic_metadata.get('corroboration_count', 0)} corroborating source(s)"],
                    ["Static / PE", "Not applicable to telemetry report"],
                    ["Signature / YARA", "Not applicable to telemetry report"],
                    ["Entropy", "Not applicable to telemetry report"],
                ]
            else:
                static_status, static_detail = self._summarize_static_pe_analysis(threat_analysis, file_analysis, is_advanced_report)
                report_focus_rows = [
                    ["Static / PE", f"{static_status} - {static_detail}"],
                    ["Signature / YARA", ", ".join(file_analysis.get("signatures", [])[:5]) or "No signature hits"],
                    ["Entropy", f"{float(file_analysis.get('entropy', 0.0) or 0.0):.3f}" if file_analysis.get('entropy') is not None else "n/a"],
                    ["IOC extraction", str(sum(len(v) for v in (file_analysis.get('iocs', {}) or {}).values()))],
                    ["Behavioral events", str(len(behavioral_events))],
                    ["Threat intel APIs", str(api_call_count)],
                ]
        elif report_type == "forensic_investigation":
            report_focus_title = "FORENSIC CASEWORK SNAPSHOT"
            source_details = forensic_metadata.get("source_details", []) if isinstance(forensic_metadata.get("source_details"), list) else []
            report_focus_rows = [
                ["Evidence sources", ", ".join(sorted({str(item.get('source', 'unknown')) for item in source_details if isinstance(item, dict)})) or "No external sources"],
                ["Chain of custody", "Preserved" if forensic_metadata.get("corroboration_threshold_met") else "Review required"],
                ["Timeline depth", f"{len(threat_analysis.get('behavioral_sequence', []) or forensic_metadata.get('behavioral_sequence', []) or [])} event(s)"],
                ["Reliability", "High" if corroboration_met else "Moderate" if corroboration_count else "Low"],
                ["Evidence inventory", f"{len(threats)} indicator(s) / {corroboration_count} source(s)"],
            ]

        if report_focus_title and report_focus_rows:
            elements.append(Paragraph(report_focus_title, heading_style))
            focus_rows = [["Focus Area", "Value"]] + report_focus_rows
            focus_table = Table(_wrap_rows(focus_rows), colWidths=[2.2 * inch, 3.8 * inch])
            focus_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, profile_palette["soft"]]),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elements.append(focus_table)
            elements.append(Spacer(1, 0.18 * inch))

        if is_executive_report:
            elements.append(Paragraph("BUSINESS IMPACT & DECISIONS", heading_style))
            summary_lines = [
                f"Decision urgency: {'Immediate' if verdict_key in {'malicious', 'suspicious'} else 'Routine'}",
                f"Operational posture: {'Containment recommended' if verdict_key in {'malicious', 'suspicious'} else 'Monitoring recommended'}",
                f"Top action: {action_plan[0] if action_plan else 'Continue monitoring'}",
            ]
            for line in summary_lines:
                elements.append(Paragraph(f"• {line}", normal_style))
            elements.append(Spacer(1, 0.15 * inch))

        if is_technical_report:
            pipeline_rows = [["Layer", "Evidence"]]
            behavioral_events = threat_analysis.get('behavioral_sequence', []) or threat_analysis.get('forensic_metadata', {}).get('behavioral_sequence', []) or []
            api_call_count = len(threat_analysis.get('api_results', {}).get('apis_called', []) or [])
            api_checked_count = int(forensic_metadata.get('apis_checked', api_call_count) or 0)
            api_applicable_count = int(forensic_metadata.get('total_apis_available', api_call_count) or 0)
            if api_applicable_count > 0:
                api_pipeline_text = f"{api_checked_count}/{api_applicable_count} applicable source(s) completed"
                if api_checked_count == 0:
                    api_pipeline_text += " (fallback intelligence mode)"
            else:
                api_pipeline_text = "No applicable external source for this input type"
            if is_advanced_report:
                elements.append(Paragraph("IDS / IPS & TELEMETRY PIPELINE", heading_style))
                total_scan_events = sum(int((item.get('activity') or {}).get('threat_scans', 0) or 0) for item in interval_summaries if isinstance(item, dict))
                pipeline_rows.append(["IDS / IPS Decision", f"{verdict.upper()} | {confidence * 100:.1f}% confidence"])
                pipeline_rows.append(["Activity Logging", f"{len(interval_summaries)} interval window(s), {total_scan_events} scan event(s)"])
                pipeline_rows.append(["Behavior / Monitor", f"{len(behavioral_events)} ordered event(s)"])
                pipeline_rows.append(["Threat Intel", api_pipeline_text])
                pipeline_rows.append(["IOC / Indicator Correlation", f"{len(threats)} threat indicator(s), {forensic_metadata.get('corroboration_count', 0)} corroborating source(s)"])
                pipeline_rows.append(["Static / PE", "Not applicable to telemetry report"])
                pipeline_rows.append(["Signature / YARA", "Not applicable to telemetry report"])
                pipeline_rows.append(["Entropy", "Not applicable to telemetry report"])
                pipeline_rows.append(["ML / Heuristic", f"Score {risk_contract.get('numeric_score', round(confidence * 100, 1))} | Confidence {risk_contract.get('confidence', f'{confidence * 100:.1f}%')}"])
            else:
                elements.append(Paragraph("DETECTION PIPELINE DETAILS", heading_style))
                static_status, static_detail = self._summarize_static_pe_analysis(threat_analysis, file_analysis, is_advanced_report)
                pipeline_rows.append(["Static / PE", f"{static_status} - {static_detail}"])
                pipeline_rows.append(["Signature / YARA", ", ".join(file_analysis.get("signatures", [])[:6]) or "No signature hits"])
                pipeline_rows.append(["IOC Extraction", ", ".join(sum((file_analysis.get("iocs", {}) or {}).values(), [])[:8]) or "None"])
                pipeline_rows.append(["Behavior / Network", f"{len(behavioral_events)} ordered events"])
                pipeline_rows.append(["Threat Intel", api_pipeline_text])
                pipeline_rows.append(["ML / Heuristic", f"Score {risk_contract.get('numeric_score', 'n/a')} | Confidence {risk_contract.get('confidence', 'n/a')}"])
            pipeline_table = Table(_wrap_rows(pipeline_rows), colWidths=[1.6 * inch, 4.4 * inch])
            pipeline_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, profile_palette["soft"]]),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elements.append(pipeline_table)
            elements.append(Spacer(1, 0.15 * inch))

        if is_forensic_report:
            elements.append(Paragraph("EVIDENCE INVENTORY & TIMELINE", heading_style))
            evidence_rows = [["Evidence", "Type", "Value"]]
            if reason_codes:
                for reason in reason_codes[:6]:
                    if isinstance(reason, dict):
                        evidence_rows.append([reason.get("code", "UNKNOWN"), "Detector", reason.get("explanation", "")])
            for idx, threat in enumerate(threats[:4], start=1):
                evidence_rows.append([f"Threat {idx}", str(threat.get("source", "unknown")), str(threat.get("indicator", ""))])
            if forensic_metadata.get("source_details"):
                for detail in forensic_metadata.get("source_details", [])[:4]:
                    evidence_rows.append([str(detail.get("source", "unknown")), str(detail.get("severity", "unknown")), str(detail.get("indicator", ""))])
            if len(evidence_rows) == 1:
                evidence_rows.append(["N/A", "N/A", "No evidence inventory available"])
            evidence_table = Table(_wrap_rows(evidence_rows), colWidths=[1.35 * inch, 0.95 * inch, 4.05 * inch])
            evidence_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, profile_palette["soft"]]),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elements.append(evidence_table)
            elements.append(Spacer(1, 0.15 * inch))

            behavioral_sequence = threat_analysis.get("behavioral_sequence") or forensic_metadata.get("behavioral_sequence") or []
            if behavioral_sequence:
                elements.append(Paragraph("BEHAVIORAL SEQUENCE", heading_style))
                sequence_rows = [["Timestamp", "Stage", "Source", "Details"]]
                for event in behavioral_sequence[:8]:
                    if not isinstance(event, dict):
                        continue
                    sequence_rows.append([
                        self._format_timestamp_for_report(event.get("timestamp", "unknown"), report_timezone),
                        str(event.get("stage", "telemetry")),
                        str(event.get("source", "unknown")),
                        _shorten_text(event.get("details", ""), 88),
                    ])
                if len(sequence_rows) > 1:
                    sequence_table = Table(_wrap_rows(sequence_rows), colWidths=[1.25 * inch, 1.1 * inch, 1.25 * inch, 3.75 * inch])
                    sequence_table.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, profile_palette["soft"]]),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]))
                    elements.append(sequence_table)
                    elements.append(Spacer(1, 0.15 * inch))
        
        # Activity Monitoring Section (if available)
        try:
            from .activity_database import activity_db
            activity_summary = selected_window.get("activity") or activity_db.get_activity_summary(hours=selected_hours)
            
            if activity_summary and activity_summary.get('threat_scans', 0) > 0:
                elements.append(Paragraph(f"ACTIVITY MONITORING SUMMARY (Last {selected_interval.upper()})", heading_style))
                
                activity_data = [
                    ["Metric", "Count"],
                    ["Threat Scans Performed", str(activity_summary.get('threat_scans', 0))],
                    ["Threats Detected", str(activity_summary.get('threats_detected', 0))],
                    ["Websites Monitored", str(activity_summary.get('websites_visited', 0))],
                    ["Applications Monitored", str(activity_summary.get('applications_launched', 0))],
                    ["Network Connections", str(activity_summary.get('network_connections', 0))],
                ]
                
                activity_table = Table(_wrap_rows(activity_data), colWidths=[3 * inch, 2 * inch])
                activity_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 11),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, profile_palette["soft"]]),
                        ("WORDWRAP", (0, 0), (-1, -1), True),  # Enable word wrapping
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),  # Align text to top
                    ])
                )
                
                elements.append(activity_table)
                elements.append(Spacer(1, 0.2 * inch))

                # Endpoint vulnerability scan summary (short/simple table)
                vuln_summary = selected_window.get("vulns") or self._get_endpoint_vuln_summary(hours=selected_hours)
                if vuln_summary and vuln_summary.get("total", 0) > 0:
                    elements.append(Paragraph(f"ENDPOINT VULNERABILITY SUMMARY (Last {selected_interval.upper()})", heading_style))

                    vuln_data = [
                        ["Severity", "Findings"],
                        ["Critical", str(vuln_summary.get("critical", 0))],
                        ["High", str(vuln_summary.get("high", 0))],
                        ["Medium", str(vuln_summary.get("medium", 0))],
                        ["Low", str(vuln_summary.get("low", 0))],
                        ["Info", str(vuln_summary.get("info", 0))],
                        ["Total", str(vuln_summary.get("total", 0))],
                    ]

                    vuln_table = Table(_wrap_rows(vuln_data), colWidths=[3 * inch, 2 * inch])
                    vuln_table.setStyle(
                        TableStyle([
                            ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 10),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                            ("TOPPADDING", (0, 0), (-1, -1), 7),
                            ("GRID", (0, 0), (-1, -1), 1, colors.black),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, profile_palette["soft"]]),
                            ("BACKGROUND", (0, 6), (-1, 6), colors.HexColor("#eef2ff")),
                            ("FONTNAME", (0, 6), (-1, 6), "Helvetica-Bold"),
                            ("WORDWRAP", (0, 0), (-1, -1), True),  # Enable word wrapping
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),  # Align text to top
                        ])
                    )
                    elements.append(vuln_table)
                    elements.append(Spacer(1, 0.2 * inch))
                
                # Recent threats from activity monitoring
                recent_threats = activity_db.get_recent_threats(limit=5, hours=selected_hours)
                if recent_threats:
                    elements.append(Paragraph("Recent Threats Detected", heading_style))
                    
                    for threat in recent_threats:
                        local_ts = self._format_timestamp_for_report(threat.get("time"), report_timezone)
                        threat_text = f"• [{local_ts}] {str(threat.get('type', 'unknown')).upper()}: {_shorten_text(threat.get('value'), 90)} - {str(threat.get('verdict', 'unknown')).upper()} (Confidence: {float(threat.get('confidence', 0.0)):.1%}, Sources: {threat.get('sources', 0)})"
                        elements.append(Paragraph(threat_text, normal_style))
                    
                    elements.append(Spacer(1, 0.2 * inch))
        except Exception as e:
            logger.debug(f"Could not include activity monitoring in report: {e}")

        if is_executive_report:
            elements.append(Paragraph("EXECUTIVE RISK SIGNALS", heading_style))
            interval_summaries_exec = threat_analysis.get("interval_summaries") or self._build_interval_summaries(threat_analysis)
            latest_window = interval_summaries_exec[0] if interval_summaries_exec else {}
            latest_activity = latest_window.get("activity") or {}
            latest_vulns = latest_window.get("vulns") or {}
            exec_rows = [
                ["Risk posture", "Elevated" if verdict_key in {"malicious", "suspicious"} else "Routine"],
                ["Threat indicators", str(len(threats))],
                ["Recent monitored threats", str(latest_activity.get("threats_detected", 0))],
                ["Endpoint vulnerability findings", str(latest_vulns.get("total", 0) if isinstance(latest_vulns, dict) else 0)],
                ["Corroboration status", forensic_threshold_text],
            ]
            exec_table = Table([["Leadership Signal", "Current State"]] + exec_rows, colWidths=[2.3 * inch, 3.7 * inch])
            exec_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#9ca3af")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, profile_palette["soft"]]),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elements.append(exec_table)
            elements.append(Spacer(1, 0.2 * inch))

            elements.append(Paragraph("THREAT OVERVIEW", heading_style))
            elements.append(Paragraph(executive_insights.get("narrative", "No overview available."), normal_style))

            elements.append(Paragraph("RISK LEVEL SUMMARY", heading_style))
            sev_dist = executive_insights.get("severity_distribution", {}) if isinstance(executive_insights.get("severity_distribution"), dict) else {}
            risk_rows = [["Risk Tier", "Count"]]
            for tier in ("critical", "high", "malicious", "suspicious", "medium", "low", "safe"):
                count = int(sev_dist.get(tier, 0) or 0)
                if count > 0:
                    risk_rows.append([tier.upper(), str(count)])
            if len(risk_rows) == 1:
                risk_rows.append(["NO ALERTED TIERS", "0"])
            risk_table = Table(_wrap_rows(risk_rows), colWidths=[2.2 * inch, 3.8 * inch])
            risk_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#9ca3af")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, profile_palette["soft"]]),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]))
            elements.append(risk_table)
            elements.append(Spacer(1, 0.15 * inch))

            elements.append(Paragraph("KEY INCIDENT HIGHLIGHTS", heading_style))
            top_incidents = executive_insights.get("high_risk_indicators", []) if isinstance(executive_insights.get("high_risk_indicators"), list) else []
            if top_incidents:
                for incident in top_incidents[:5]:
                    cls = incident.get("classification", {}) if isinstance(incident.get("classification"), dict) else {}
                    impact = incident.get("impact_analysis", {}) if isinstance(incident.get("impact_analysis"), dict) else {}
                    elements.append(
                        Paragraph(
                            f"• {incident.get('indicator_value', 'unknown')} | status={str(cls.get('status', 'unknown')).upper()} | "
                            f"confidence={float(cls.get('confidence', 0.0) or 0.0):.1f}% | attack={impact.get('attack_type', 'unknown')}",
                            normal_style,
                        )
                    )
            else:
                elements.append(Paragraph("No high-risk incidents identified in this interval.", normal_style))

            elements.append(Paragraph("REPEATED THREAT INDICATORS", heading_style))
            repeated_network = executive_insights.get("repeated_ips_domains", []) if isinstance(executive_insights.get("repeated_ips_domains"), list) else []
            if repeated_network:
                for item in repeated_network[:8]:
                    elements.append(
                        Paragraph(
                            f"• {item.get('indicator', 'unknown')} repeated {int(item.get('count', 0) or 0)} time(s)",
                            normal_style,
                        )
                    )
            else:
                elements.append(Paragraph("No repeated IP/domain/URL indicators detected in this reporting window.", normal_style))

            elements.append(Paragraph("ATTACK TREND SUMMARY", heading_style))
            attack_types = executive_insights.get("attack_types", []) if isinstance(executive_insights.get("attack_types"), list) else []
            trend = str(executive_insights.get("trend", "stable")).upper()
            elements.append(
                Paragraph(
                    f"Trend direction: {trend}. Dominant attack classifications: {', '.join(attack_types) if attack_types else 'none identified'}.",
                    normal_style,
                )
            )
            elements.append(Paragraph("EXECUTIVE PER-SCAN SUMMARY", heading_style))
            if scan_records:
                per_scan_rows = [["Scan ID", "Indicator", "Status", "Confidence", "Attack Type", "Action"]]
                for scan in scan_records[:20]:
                    cls = scan.get("classification", {}) if isinstance(scan.get("classification"), dict) else {}
                    impact = scan.get("impact_analysis", {}) if isinstance(scan.get("impact_analysis"), dict) else {}
                    per_scan_rows.append([
                        str(scan.get("scan_id", "unknown")),
                        _shorten_text(scan.get("indicator_value", ""), 45),
                        str(cls.get("status", "unknown")).upper(),
                        f"{float(cls.get('confidence', 0.0) or 0.0):.1f}%",
                        str(impact.get("attack_type", "unknown")),
                        _shorten_text(scan.get("recommended_action", ""), 52),
                    ])
                per_scan_table = Table(_wrap_rows(per_scan_rows), colWidths=[0.9 * inch, 1.35 * inch, 0.7 * inch, 0.7 * inch, 0.95 * inch, 1.4 * inch])
                per_scan_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#9ca3af")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, profile_palette["soft"]]),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]))
                elements.append(per_scan_table)
            else:
                elements.append(Paragraph("No scan records available for executive scan summary.", normal_style))
            elements.append(Spacer(1, 0.2 * inch))
        else:
            # Analysis Methods Used Section
            elements.append(Paragraph("ANALYSIS METHODS USED", heading_style))
            
            # Get analysis methods from threat_analysis data
            analysis_methods = self._get_analysis_methods_used(threat_analysis)
            
            methods_data = [["Method", "Status", "Details"]]
            for method in analysis_methods:
                methods_data.append([
                    method["name"],
                    method["status"],
                    method["details"]
                ])
            
            methods_table = Table(
                _wrap_rows(methods_data),
                colWidths=[2.2 * inch, 1.2 * inch, 3.6 * inch]
            )
            methods_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, profile_palette["soft"]]),
                    ("WORDWRAP", (0, 0), (-1, -1), True),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ])
            )
            elements.append(methods_table)
            elements.append(Spacer(1, 0.2 * inch))

            # Intelligence source coverage
            coverage_heading = (
                "TELEMETRY COVERAGE"
                if str(threat_analysis.get("input_type") or "").strip().lower() == "advanced_report"
                else "INTELLIGENCE SOURCE COVERAGE"
            )
            elements.append(Paragraph(coverage_heading, heading_style))
            coverage_table = Table(
                _wrap_rows(self._get_api_coverage_rows(threat_analysis)),
                colWidths=[1.8 * inch, 1.5 * inch, 1.2 * inch, 1.2 * inch],
            )
            coverage_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, profile_palette["soft"]]),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("WORDWRAP", (0, 0), (-1, -1), True),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            elements.append(coverage_table)
            elements.append(Spacer(1, 0.2 * inch))

        if interval_summaries:
            elements.append(Paragraph("INTERVAL COVERAGE SUMMARY", heading_style))
            interval_rows = [["Period", "Threat Scans", "Threats", "Websites", "Apps", "Network", "Vulns"]]
            for item in interval_summaries:
                activity = item.get("activity") or {}
                vulns = item.get("vulns") or {}
                interval_rows.append([
                    str(item.get("interval", "24h")).upper(),
                    str(activity.get("threat_scans", 0)),
                    str(activity.get("threats_detected", 0)),
                    str(activity.get("websites_visited", 0)),
                    str(activity.get("applications_launched", 0)),
                    str(activity.get("network_connections", 0)),
                    str(vulns.get("total", 0) if isinstance(vulns, dict) else 0),
                ])

            interval_table = Table(
                _wrap_rows(interval_rows),
                colWidths=[0.85 * inch, 0.9 * inch, 0.75 * inch, 0.85 * inch, 0.75 * inch, 0.8 * inch, 0.7 * inch],
            )
            interval_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, profile_palette["soft"]]),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                ])
            )
            elements.append(interval_table)
            elements.append(Spacer(1, 0.2 * inch))

            elements.append(Paragraph("INTERVAL INTELLIGENCE INTERPRETATION", heading_style))
            for item in interval_summaries[:3]:
                if not isinstance(item, dict):
                    continue
                label = str(item.get("interval", "24h")).lower()
                interpretation = self._interval_report_interpretation(label, threat_analysis, report_type)
                elements.append(Paragraph(_shorten_text(interpretation, 420), normal_style))
            elements.append(Spacer(1, 0.2 * inch))

        if is_technical_report:
            elements.append(Paragraph("PER-SCAN TECHNICAL ANALYSIS RECORDS", heading_style))
            if scan_records:
                for scan in scan_records:
                    detection = scan.get("detection_results", {}) if isinstance(scan.get("detection_results"), dict) else {}
                    classification = scan.get("classification", {}) if isinstance(scan.get("classification"), dict) else {}
                    technical = scan.get("technical_analysis", {}) if isinstance(scan.get("technical_analysis"), dict) else {}
                    impact = scan.get("impact_analysis", {}) if isinstance(scan.get("impact_analysis"), dict) else {}

                    rows = [
                        ["scan_id", str(scan.get("scan_id", "unknown"))],
                        ["timestamp", str(scan.get("timestamp", "unknown"))],
                        ["indicator_type", str(scan.get("indicator_type", "Unknown"))],
                        ["indicator_value", _shorten_text(scan.get("indicator_value", ""), 120)],
                        ["detection.heuristic", _shorten_text(detection.get("heuristic", "heuristic analysis applied"), 110)],
                        ["detection.virustotal", _shorten_text(detection.get("virustotal", "no provider result recorded"), 110)],
                        ["detection.abuseipdb", _shorten_text(detection.get("abuseipdb", "no provider result recorded"), 110)],
                        ["detection.shodan", _shorten_text(detection.get("shodan", "no provider result recorded"), 110)],
                        ["detection.urlscan", _shorten_text(detection.get("urlscan", "no provider result recorded"), 110)],
                        ["detection.hybrid_analysis", _shorten_text(detection.get("hybrid_analysis", "no provider result recorded"), 110)],
                        ["classification.status", str(classification.get("status", "unknown"))],
                        ["classification.confidence", f"{float(classification.get('confidence', 0.0) or 0.0):.1f}%"],
                        ["classification.severity", str(classification.get("severity", "unknown"))],
                        ["technical.detection_reason", _shorten_text(technical.get("detection_reason", ""), 120)],
                        ["technical.behavior_pattern", _shorten_text(technical.get("behavior_pattern", ""), 120)],
                        ["technical.payload_characteristics", _shorten_text(technical.get("payload_characteristics", ""), 120)],
                        ["impact.system_risk", str(impact.get("system_risk", "unknown"))],
                        ["impact.attack_type", str(impact.get("attack_type", "unknown"))],
                        ["recommended_action", _shorten_text(scan.get("recommended_action", ""), 120)],
                    ]

                    scan_table = Table(_wrap_rows([["Field", "Value"]] + rows), colWidths=[2.1 * inch, 3.9 * inch])
                    scan_table.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, profile_palette["soft"]]),
                        ("FONTSIZE", (0, 0), (-1, -1), 8.2),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]))
                    elements.append(scan_table)
                    elements.append(Spacer(1, 0.12 * inch))
            else:
                elements.append(Paragraph("No scan records available for technical per-scan analysis.", normal_style))
                elements.append(Spacer(1, 0.12 * inch))

        # Prioritized action plan
        elements.append(Paragraph("PRIORITIZED ACTION PLAN", heading_style))
        for index, action in enumerate(action_plan, start=1):
            elements.append(Paragraph(f"{index}. {action}", normal_style))
        elements.append(Spacer(1, 0.2 * inch))

        if is_forensic_report:
            elements.append(Paragraph("CHAIN OF CUSTODY NOTES", heading_style))
            elements.append(
                Paragraph(
                    "Preserve original artifacts, hashes, timestamps, and analyst action logs before any destructive remediation. "
                    "Treat this report as an investigative summary and retain source evidence for compliance/legal workflows.",
                    normal_style,
                )
            )
            elements.append(Spacer(1, 0.2 * inch))

        # Forensic Evidence Section
        if is_forensic_report and forensic_metadata and forensic_metadata.get("source_details"):
            elements.append(Paragraph("FORENSIC EVIDENCE TRACKING", heading_style))
            
            source_details = forensic_metadata.get("source_details", [])
            if source_details:
                evidence_data = [["Source", "Severity", "Detection Details", "Timestamp"]]
                
                for detail in source_details:
                    local_ts = self._format_timestamp_for_report(detail.get("timestamp", ""), report_timezone)
                    evidence_data.append([
                        detail.get("source", "Unknown"),
                        detail.get("severity", "unknown").upper(),
                        _shorten_text(detail.get("indicator", ""), 84),
                        local_ts,
                    ])
                
                evidence_table = Table(
                    _wrap_rows(evidence_data), colWidths=[1.2 * inch, 0.9 * inch, 2.5 * inch, 1.4 * inch]
                )
                evidence_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, profile_palette["soft"]]),
                        ("WORDWRAP", (0, 0), (-1, -1), True),  # Enable word wrapping
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),  # Align text to top
                    ])
                )
                elements.append(evidence_table)
                
                # Add corroboration note
                if corroboration_met:
                    corroboration_note = (
                        f"<b>FORENSIC NOTE:</b> This threat has been corroborated by "
                        f"{corroboration_count} independent sources, meeting the forensic "
                        f"reliability threshold (≥2 sources). This significantly increases "
                        f"confidence in the verdict."
                    )
                elif len(threats) == 0:
                    corroboration_note = (
                        "<b>FORENSIC NOTE:</b> No threat indicators were detected in this scan. "
                        "Single-source corroboration checks are not required for clean results."
                    )
                else:
                    corroboration_note = (
                        f"<b>FORENSIC CAUTION:</b> This threat has limited corroboration "
                        f"({corroboration_count} source). Multi-source corroboration (≥2 sources) "
                        f"is recommended for higher forensic reliability before critical response actions."
                    )
                
                elements.append(Spacer(1, 0.1 * inch))
                elements.append(Paragraph(corroboration_note, normal_style))
                elements.append(Spacer(1, 0.2 * inch))

        # Advanced forensic intelligence (if available)
        advanced_forensic = (
            threat_analysis.get("forensic_analysis")
            or forensic_metadata.get("advanced_analysis")
            or {}
        )
        if is_forensic_report and advanced_forensic:
            elements.append(Paragraph("ADVANCED FORENSIC INTELLIGENCE", heading_style))

            orchestration = advanced_forensic.get("orchestration", {})
            methods = advanced_forensic.get("detection_methods", {})
            cor_summary = advanced_forensic.get("corroboration_summary", {})

            advanced_rows = [
                ["Orchestration Coverage", f"{orchestration.get('coverage_percent', 0)}%"],
                ["APIs Applicable/Called", f"{orchestration.get('apis_expected_applicable', orchestration.get('apis_expected', 0))}/{orchestration.get('apis_called', 0)}"],
                ["APIs Tracked (Total)", str(orchestration.get("apis_expected", 0))],
                ["Detection Method Mix", f"H={methods.get('heuristic_indicators', 0)} | S={methods.get('signature_based_indicators', 0)} | TI={methods.get('threat_intel_indicators', 0)}"],
                ["Corroboration Reliability", str(cor_summary.get("reliability", "unknown")).upper()],
            ]

            advanced_table = Table(_wrap_rows(advanced_rows, header_rows=0), colWidths=[2.2 * inch, 3.8 * inch])
            advanced_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8eef8")),
                    ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#90a4ae")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ])
            )
            elements.append(advanced_table)
            elements.append(Spacer(1, 0.1 * inch))

            elements.append(Spacer(1, 0.2 * inch))

        if is_forensic_report:
            elements.append(Paragraph("FORENSIC TIMELINE ANALYSIS", heading_style))
            timeline_events = forensic_intelligence.get("timeline", []) if isinstance(forensic_intelligence.get("timeline"), list) else []
            if timeline_events:
                timeline_rows = [["Timestamp", "Scan ID", "Indicator", "Status", "Type"]]
                for event in timeline_events[:30]:
                    timeline_rows.append([
                        str(event.get("timestamp", "unknown")),
                        str(event.get("scan_id", "unknown")),
                        _shorten_text(event.get("indicator", ""), 60),
                        str(event.get("status", "unknown")).upper(),
                        str(event.get("indicator_type", "Unknown")),
                    ])
                timeline_table = Table(_wrap_rows(timeline_rows), colWidths=[1.35 * inch, 1.05 * inch, 2.0 * inch, 0.8 * inch, 0.8 * inch])
                timeline_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, profile_palette["soft"]]),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]))
                elements.append(timeline_table)
            else:
                elements.append(Paragraph("No timeline events available.", normal_style))

            transitions = forensic_intelligence.get("safe_to_malicious_transitions", []) if isinstance(forensic_intelligence.get("safe_to_malicious_transitions"), list) else []
            elements.append(Paragraph("SAFE TO MALICIOUS TRANSITIONS", heading_style))
            if transitions:
                for transition in transitions[:10]:
                    elements.append(Paragraph(f"• {transition.get('indicator', 'unknown')} transitioned SAFE -> MALICIOUS", normal_style))
            else:
                elements.append(Paragraph("No SAFE -> MALICIOUS transitions detected.", normal_style))

            elements.append(Paragraph("PATTERN CORRELATION", heading_style))
            pattern = forensic_intelligence.get("pattern_correlation", {}) if isinstance(forensic_intelligence.get("pattern_correlation"), dict) else {}
            repeated_entities = pattern.get("repeated_entities", []) if isinstance(pattern.get("repeated_entities"), list) else []
            grouped_threats = pattern.get("grouped_threats", {}) if isinstance(pattern.get("grouped_threats"), dict) else {}
            if repeated_entities:
                for item in repeated_entities[:10]:
                    elements.append(
                        Paragraph(
                            f"• {item.get('indicator', 'unknown')} ({item.get('indicator_type', 'Unknown')}) repeated {int(item.get('count', 0) or 0)} time(s)",
                            normal_style,
                        )
                    )
            else:
                elements.append(Paragraph("No repeated indicator entities identified.", normal_style))
            for attack_type, related in list(grouped_threats.items())[:6]:
                elements.append(Paragraph(f"• Group {attack_type}: {', '.join(str(v) for v in related[:4])}", normal_style))

            elements.append(Paragraph("CONTRADICTION DETECTION", heading_style))
            contradictions = forensic_intelligence.get("contradictions_detected", []) if isinstance(forensic_intelligence.get("contradictions_detected"), list) else []
            if contradictions:
                for contradiction in contradictions[:8]:
                    reasons = contradiction.get("possible_reasons", []) if isinstance(contradiction.get("possible_reasons"), list) else []
                    elements.append(
                        Paragraph(
                            f"• {contradiction.get('indicator', 'unknown')} reported conflicting statuses {', '.join(contradiction.get('statuses', []))}. "
                            f"Possible causes: {', '.join(reasons)}.",
                            normal_style,
                        )
                    )
            else:
                elements.append(Paragraph("No conflicting scan contradictions detected.", normal_style))

            elements.append(Paragraph("THREAT ATTRIBUTION", heading_style))
            attribution = forensic_intelligence.get("threat_attribution_analysis", {}) if isinstance(forensic_intelligence.get("threat_attribution_analysis"), dict) else {}
            if attribution:
                for key, value in sorted(attribution.items(), key=lambda kv: int(kv[1]), reverse=True):
                    elements.append(Paragraph(f"• {key}: {int(value)} correlated event(s)", normal_style))
            else:
                elements.append(Paragraph("No attribution patterns detected.", normal_style))

            elements.append(Paragraph("MITRE ATT&CK COVERAGE", heading_style))
            mitre_cov = forensic_intelligence.get("mitre_att_ck_coverage", {}) if isinstance(forensic_intelligence.get("mitre_att_ck_coverage"), dict) else {}
            if mitre_cov:
                for tactic, count in sorted(mitre_cov.items(), key=lambda kv: int(kv[1]), reverse=True):
                    elements.append(Paragraph(f"• {tactic}: {int(count)} mapped event(s)", normal_style))
            else:
                elements.append(Paragraph("No MITRE tactic mapping available for this interval.", normal_style))

            elements.append(Paragraph("KILL CHAIN COVERAGE", heading_style))
            kill_chain_cov = forensic_intelligence.get("kill_chain_coverage", {}) if isinstance(forensic_intelligence.get("kill_chain_coverage"), dict) else {}
            if kill_chain_cov:
                for stage, count in sorted(kill_chain_cov.items(), key=lambda kv: int(kv[1]), reverse=True):
                    elements.append(Paragraph(f"• {stage}: {int(count)} mapped event(s)", normal_style))
            else:
                elements.append(Paragraph("No kill-chain stage mapping available for this interval.", normal_style))

            elements.append(Paragraph("CONFIDENCE SCORING MODEL", heading_style))
            confidence_model = forensic_intelligence.get("confidence_scoring_model", {}) if isinstance(forensic_intelligence.get("confidence_scoring_model"), dict) else {}
            confidence_rows = [["Model Rule", "Count"]]
            for label in (
                "SINGLE SOURCE / HEURISTIC (Lower Confidence)",
                "DUAL-SOURCE EVIDENCE (Medium Confidence)",
                "MULTI-SOURCE CORROBORATION (High Confidence)",
                "VERIFIED SAFE (High Confidence)",
            ):
                confidence_rows.append([label, str(int(confidence_model.get(label, 0) or 0))])
            confidence_table = Table(_wrap_rows(confidence_rows), colWidths=[3.6 * inch, 2.4 * inch])
            confidence_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, profile_palette["soft"]]),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ]))
            elements.append(confidence_table)

            elements.append(Paragraph("ATTACK VECTOR CLASSIFICATION", heading_style))
            vectors = forensic_intelligence.get("attack_vector_classification", {}) if isinstance(forensic_intelligence.get("attack_vector_classification"), dict) else {}
            vector_rows = [["Vector", "Count"]]
            for label in ("Network-based", "Web-based", "File-based", "Unclassified"):
                vector_rows.append([label, str(int(vectors.get(label, 0) or 0))])
            vector_table = Table(_wrap_rows(vector_rows), colWidths=[3.0 * inch, 3.0 * inch])
            vector_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, profile_palette["soft"]]),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ]))
            elements.append(vector_table)

            elements.append(Paragraph("FORENSIC PER-SCAN CASE RECORDS", heading_style))
            if scan_records:
                forensic_rows = [["Scan ID", "Timestamp", "Indicator", "Status", "Confidence", "Forensic Interpretation"]]
                for scan in scan_records[:30]:
                    cls = scan.get("classification", {}) if isinstance(scan.get("classification"), dict) else {}
                    technical = scan.get("technical_analysis", {}) if isinstance(scan.get("technical_analysis"), dict) else {}
                    forensic_rows.append([
                        str(scan.get("scan_id", "unknown")),
                        str(scan.get("timestamp", "unknown")),
                        _shorten_text(scan.get("indicator_value", ""), 45),
                        str(cls.get("status", "unknown")).upper(),
                        f"{float(cls.get('confidence', 0.0) or 0.0):.1f}%",
                        _shorten_text(technical.get("detection_reason", ""), 90),
                    ])
                forensic_scan_table = Table(_wrap_rows(forensic_rows), colWidths=[0.8 * inch, 1.1 * inch, 1.2 * inch, 0.7 * inch, 0.7 * inch, 1.5 * inch])
                forensic_scan_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, profile_palette["soft"]]),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.7),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]))
                elements.append(forensic_scan_table)
            else:
                elements.append(Paragraph("No scan records available for forensic case records.", normal_style))
            elements.append(Spacer(1, 0.2 * inch))

        # Threat Summary (audience-specific rendering)
        summary_title = {
            "executive_summary": "MOST IMPORTANT INDICATORS",
            "technical_analysis": "TECHNICAL THREAT EVIDENCE",
            "forensic_investigation": "OBSERVED INDICATORS AND ARTIFACT REFERENCES",
        }.get(report_type, "THREAT SUMMARY")
        elements.append(Paragraph(summary_title, heading_style))

        if threats:
            threat_data = [["Source", "Severity", "Indicator"]]
            max_rows = 12 if report_type == "executive_summary" else 45 if report_type == "technical_analysis" else 30
            for threat in threats[:max_rows]:
                threat_data.append(
                    [
                        _shorten_text(threat.get("source", "Unknown"), 24),
                        str(threat.get("severity", "unknown")).upper(),
                        _shorten_text(threat.get("indicator", ""), 90),
                    ]
                )

            if len(threats) > max_rows:
                threat_data.append([
                    "...",
                    "...",
                    f"{len(threats) - max_rows} additional indicator(s) omitted for readability",
                ])

            threat_table = Table(
                _wrap_rows(threat_data), colWidths=[1.5 * inch, 1.2 * inch, 3.3 * inch]
            )
            threat_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), profile_palette["table_header"]),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, profile_palette["soft"]],
                        ),
                        ("WORDWRAP", (0, 0), (-1, -1), True),  # Enable word wrapping
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),  # Align text to top
                    ]
                )
            )

            elements.append(threat_table)
        else:
            elements.append(Paragraph("No threats detected.", normal_style))

        elements.append(Spacer(1, 0.3 * inch))

        # AI Analysis
        elements.append(PageBreak())
        ai_section_title = {
            "executive_summary": "EXECUTIVE DECISION NARRATIVE",
            "technical_analysis": "TECHNICAL ANALYSIS NARRATIVE",
            "forensic_investigation": "FORENSIC INVESTIGATION NARRATIVE",
        }.get(report_type, "AI ANALYSIS & RECOMMENDATIONS")
        elements.append(Paragraph(ai_section_title, heading_style))

        # Parse AI analysis into paragraphs
        for paragraph_text in ai_analysis.split("\n"):
            if paragraph_text.strip().startswith("##"):
                elements.append(
                    Paragraph(paragraph_text.replace("##", "").strip(), heading_style)
                )
            elif paragraph_text.strip().startswith("#"):
                elements.append(
                    Paragraph(paragraph_text.replace("#", "").strip(), heading_style)
                )
            elif paragraph_text.strip():
                elements.append(Paragraph(paragraph_text.strip(), normal_style))

        # Footer
        elements.append(Spacer(1, 0.5 * inch))
        footer_text = "SENTINEL-AI | Automated Threat Detection & Analysis | Powered by Google Gemini"
        elements.append(
            Paragraph(
                footer_text,
                ParagraphStyle(
                    "Footer",
                    parent=styles["Normal"],
                    fontSize=8,
                    textColor=colors.grey,
                    alignment=TA_CENTER,
                ),
            )
        )

        # Build PDF
        doc.build(elements)

        # Get PDF bytes
        pdf_buffer.seek(0)
        return pdf_buffer.read()

    def _create_comprehensive_interval_report(
        self, threat_analysis: Dict[str, Any], ai_analysis: str
    ) -> bytes:
        """Create a comprehensive multi-interval PDF with distinct per-interval analysis sections"""
        from io import BytesIO
        
        # Create PDF in memory
        pdf_buffer = BytesIO()
        doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "IntervalTitle",
            parent=styles["Heading1"],
            fontSize=24,
            textColor=colors.HexColor("#1a1a1a"),
            spaceAfter=6,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        )
        
        interval_heading = ParagraphStyle(
            "IntervalHeading",
            parent=styles["Heading2"],
            fontSize=16,
            textColor=colors.HexColor("#0066cc"),
            spaceAfter=12,
            spaceBefore=12,
            fontName="Helvetica-Bold",
            backColor=colors.HexColor("#e6f2ff"),
        )
        
        normal_style = ParagraphStyle(
            "Normal",
            parent=styles["Normal"],
            fontSize=10,
            spaceAfter=8,
            leading=14,
        )
        
        def _cell(value: Any, header: bool = False):
            style = ParagraphStyle(
                "Cell",
                parent=normal_style,
                fontSize=8 if not header else 9,
                fontName="Helvetica-Bold" if header else "Helvetica",
                textColor=colors.whitesmoke if header else colors.black,
            )
            text = str(value or "-")
            return Paragraph(text, style)
        
        def _wrap_rows(rows: list[list[Any]], header_rows: int = 1):
            wrapped = []
            for row_index, row in enumerate(rows):
                wrapped.append([_cell(col, header=row_index < header_rows) for col in row])
            return wrapped
        
        elements = []
        report_type = self._normalize_report_type(threat_analysis.get("report_type", "executive_summary"))
        verdict = threat_analysis.get("verdict", "unknown").upper()
        confidence = threat_analysis.get("confidence", 0.0)
        
        # Title page
        elements.append(Paragraph("SENTINEL-AI COMPREHENSIVE REPORT", title_style))
        elements.append(Paragraph(f"Multi-Interval Analysis: 24H | 7D | 30D", normal_style))
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(Paragraph(f"Report Type: {report_type.replace('_', ' ').title()}", normal_style))
        elements.append(Paragraph(f"Verdict: {verdict} (Confidence: {confidence*100:.1f}%)", normal_style))
        elements.append(PageBreak())
        
        # Generate sections for each interval
        intervals = ["24h", "7d", "30d"]
        interval_labels = {"24h": "24 HOURS (Immediate)", "7d": "7 DAYS (Weekly Trends)", "30d": "30 DAYS (Strategic)"}
        
        for interval in intervals:
            elements.append(Paragraph(f"ANALYSIS: {interval_labels[interval]}", interval_heading))
            elements.append(Spacer(1, 0.1 * inch))
            
            # Interval-specific narrative
            narrative = self._interval_analysis_text(interval, threat_analysis)
            elements.append(Paragraph(narrative, normal_style))
            elements.append(Spacer(1, 0.15 * inch))
            
            # Interval focus matrix
            elements.append(Paragraph(f"METRICS & FOCUS - {interval.upper()}", styles["Heading3"]))
            focus_rows = self._interval_focus_rows(interval, threat_analysis)
            focus_table = Table(_wrap_rows(focus_rows), colWidths=[2.0 * inch, 4.0 * inch])
            focus_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ])
            )
            elements.append(focus_table)
            elements.append(Spacer(1, 0.3 * inch))
            
            if interval != intervals[-1]:
                elements.append(PageBreak())
        
        # Build PDF
        doc.build(elements)
        
        # Get PDF bytes
        pdf_buffer.seek(0)
        return pdf_buffer.read()

    def _normalize_file_analysis(self, threat_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Return the richest available file-analysis payload for report rendering."""
        candidates = [
            threat_analysis.get("file_analysis"),
            threat_analysis.get("local_analysis"),
        ]
        analysis_data = threat_analysis.get("analysis_data")
        if isinstance(analysis_data, dict):
            candidates.extend([
                analysis_data.get("file_analysis"),
                analysis_data.get("local_analysis"),
            ])

        normalized: Dict[str, Any] = {}
        for candidate in candidates:
            if isinstance(candidate, dict) and candidate:
                normalized.update(candidate)

        return normalized

    def _build_detection_coverage_overview(self, threat_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize the detection stack so fallback reports stay explicit about coverage."""
        file_analysis = self._normalize_file_analysis(threat_analysis)
        forensic = threat_analysis.get("forensic_metadata", {}) if isinstance(threat_analysis.get("forensic_metadata"), dict) else {}
        api_results = threat_analysis.get("api_results", {}) if isinstance(threat_analysis.get("api_results"), dict) else {}
        api_status = api_results.get("api_status", {}) if isinstance(api_results.get("api_status"), dict) else {}
        ai_analysis = threat_analysis.get("ai_analysis", {}) if isinstance(threat_analysis.get("ai_analysis"), dict) else {}
        behavioral_sequence = threat_analysis.get("behavioral_sequence") or forensic.get("behavioral_sequence") or []

        methods: list[Dict[str, Any]] = []

        def add_method(name: str, status: str, details: str) -> None:
            methods.append({"name": name, "status": status, "details": details})

        signatures = file_analysis.get("signatures", []) if isinstance(file_analysis.get("signatures"), list) else []
        if file_analysis:
            add_method(
                "Signature Matching",
                "COMPLETED",
                f"Signature, byte-pattern, and heuristic matching contributed {len(signatures)} hit(s).",
            )

        entropy_value = file_analysis.get("entropy") if isinstance(file_analysis, dict) else None
        if entropy_value is not None:
            try:
                entropy = float(entropy_value)
            except (TypeError, ValueError):
                entropy = 0.0
            add_method(
                "Shannon Entropy Analysis",
                "COMPLETED",
                f"Calculated file entropy at {entropy:.3f} for packing and obfuscation assessment.",
            )

        ioc_total = sum(len(v) for v in (file_analysis.get("iocs", {}) or {}).values())
        suspicious_strings = len(file_analysis.get("suspicious_strings", []) or [])
        if file_analysis:
            add_method(
                "IOC & Context Heuristics",
                "COMPLETED" if (ioc_total or suspicious_strings) else "LIMITED",
                f"Extracted {ioc_total} IOC value(s) and {suspicious_strings} suspicious context string(s).",
            )

        document_analysis = file_analysis.get("document_analysis") if isinstance(file_analysis.get("document_analysis"), dict) else {}
        ole_info = file_analysis.get("ole_info") if isinstance(file_analysis.get("ole_info"), dict) else {}
        if document_analysis or ole_info:
            document_kind = str((document_analysis or {}).get("kind") or (ole_info or {}).get("kind") or "office_document")
            add_method(
                "OLE / Office Heuristic Analysis",
                "COMPLETED",
                f"Document/container heuristics evaluated {document_kind} artifacts for macro, link, and embedded-object signals.",
            )

        pe_info = file_analysis.get("pe_info") or file_analysis.get("coff_info")
        if pe_info:
            add_method(
                "PE/COFF Binary Analysis",
                "COMPLETED",
                f"PE/COFF metadata captured {len((pe_info or {}).get('sections', []))} section(s) and {len((pe_info or {}).get('imports', []))} import set(s).",
            )

        disassembly_info = file_analysis.get("disassembly_info") if isinstance(file_analysis.get("disassembly_info"), dict) else {}
        if disassembly_info:
            add_method(
                "Code Disassembly",
                "COMPLETED",
                f"Capstone/lief-style disassembly produced {len(disassembly_info.get('suspicious_patterns', []))} suspicious pattern(s).",
            )

        ml_result = file_analysis.get("ml_classification") if isinstance(file_analysis.get("ml_classification"), dict) else {}
        if ml_result:
            add_method(
                "Machine Learning Classification",
                "COMPLETED",
                f"Local ML classification predicted {ml_result.get('prediction', 'UNKNOWN')} with confidence {float(ml_result.get('confidence', 0.0) or 0.0):.2f}.",
            )

        if ai_analysis:
            anomaly_detection = ai_analysis.get("anomaly_detection", {}) if isinstance(ai_analysis.get("anomaly_detection"), dict) else {}
            threat_prediction = ai_analysis.get("threat_prediction", {}) if isinstance(ai_analysis.get("threat_prediction"), dict) else {}
            behavioral_analysis = ai_analysis.get("behavioral_analysis", {}) if isinstance(ai_analysis.get("behavioral_analysis"), dict) else {}
            reputation_score = ai_analysis.get("reputation_score", {}) if isinstance(ai_analysis.get("reputation_score"), dict) else {}

            if anomaly_detection:
                add_method(
                    "AI / ML Anomaly Detection",
                    "COMPLETED",
                    f"Anomaly score {float(anomaly_detection.get('score', 0.0) or 0.0):.3f} with factors: {', '.join(anomaly_detection.get('factors', [])[:4]) or 'none reported'}.",
                )
            if threat_prediction:
                add_method(
                    "AI / ML Threat Prediction",
                    "COMPLETED",
                    f"Threat probability {float(threat_prediction.get('probability', 0.0) or 0.0):.3f} and level {threat_prediction.get('threat_level', 'unknown')}.",
                )
            if behavioral_analysis:
                add_method(
                    "Behavioral Analysis",
                    "COMPLETED",
                    f"Detected {len(behavioral_analysis.get('behaviors_detected', []) or [])} behavioral signal(s) with risk {behavioral_analysis.get('risk_level', 'unknown')}.",
                )
            if reputation_score:
                add_method(
                    "Reputation Scoring",
                    "COMPLETED",
                    f"Reputation score settled at {reputation_score.get('score', 'n/a')} ({reputation_score.get('rating', 'unknown')}).",
                )

        if behavioral_sequence:
            add_method(
                "Behavioral Sequence & Orchestration",
                "COMPLETED",
                f"Ordered {len(behavioral_sequence)} behavioral event(s) into a timeline for orchestration-aware analysis.",
            )

        corroboration = threat_analysis.get("corroboration_analysis")
        if corroboration or forensic.get("corroboration_count") is not None:
            add_method(
                "Corroboration Engine",
                "COMPLETED" if corroboration else "LIMITED",
                f"Cross-source corroboration evaluated {int(forensic.get('corroboration_count', 0) or 0)} source(s).",
            )

        api_status_values = [str((meta or {}).get("status", "unknown") or "unknown").lower() for meta in api_status.values() if isinstance(meta, dict)]
        checked_count = sum(1 for status in api_status_values if status in {"checked", "clean", "no_threat", "available", "online"})
        applicable_expected = int(forensic.get("total_apis_available", 0) or 0)
        if api_results or api_status:
            if checked_count > 0:
                api_status_label = "COMPLETED"
                api_status_details = f"{checked_count}/{applicable_expected or checked_count} applicable external source(s) completed."
            elif any(status in {"rate_limited", "quota_exceeded", "not_configured", "not_authorized", "error", "skipped_local_mode"} for status in api_status_values):
                api_status_label = "LIMITED"
                api_status_details = "External API coverage was constrained, so local heuristics and ML fallback carried the verdict."
            else:
                api_status_label = "LIMITED"
                api_status_details = "External API payload was present but no provider completed in this scan window."
            add_method("Threat Intelligence APIs", api_status_label, api_status_details)

        unavailable_reasons = forensic.get("external_corroboration_unavailable_reasons", []) if isinstance(forensic.get("external_corroboration_unavailable_reasons"), list) else []
        fallback_reason = threat_analysis.get("api_coverage_explanation") or (", ".join(str(item) for item in unavailable_reasons) if unavailable_reasons else "")

        if checked_count > 0 and methods:
            analysis_mode = "hybrid"
        elif methods:
            analysis_mode = "local_fallback"
        elif api_results:
            analysis_mode = "api_assisted"
        else:
            analysis_mode = "insufficient_data"

        local_method_names = []
        for method in methods:
            name = str(method.get("name", "")).strip()
            if name and name not in local_method_names:
                local_method_names.append(name)

        if not fallback_reason:
            if analysis_mode == "local_fallback":
                fallback_reason = "External API coverage was unavailable or incomplete, so local analysis methods were used to drive the conclusion."
            elif analysis_mode == "insufficient_data":
                fallback_reason = "No external API payload or local evidence bundle was present in the report input."

        return {
            "mode": analysis_mode,
            "methods": methods,
            "method_names": local_method_names,
            "fallback_reason": fallback_reason,
            "api_summary": f"{checked_count}/{applicable_expected or checked_count or 0} applicable API source(s) completed",
        }

    def _summarize_static_pe_analysis(self, threat_analysis: Dict[str, Any], file_analysis: Dict[str, Any], is_advanced_report: bool) -> tuple[str, str]:
        """Return a readable static/PE summary for report tables."""
        if is_advanced_report:
            return "Not applicable to telemetry report", "Static analysis is only shown for file-based technical reports."

        input_type = str(threat_analysis.get("input_type") or "").strip().lower()
        is_file_scan = input_type in {"file", "file_hash", "hash", "artifact"} or bool(file_analysis)
        if not is_file_scan:
            return "Not applicable", "Target profile is not a file artifact in this report payload."

        if not isinstance(file_analysis, dict) or not file_analysis:
            return "Limited", "File scan context exists, but the static analysis payload was not attached to this report."

        signatures = file_analysis.get("signatures", []) if isinstance(file_analysis.get("signatures"), list) else []
        entropy_value = file_analysis.get("entropy")
        try:
            entropy_text = f"{float(entropy_value):.3f}"
        except (TypeError, ValueError):
            entropy_text = "n/a"

        pe_info = file_analysis.get("pe_info") if isinstance(file_analysis.get("pe_info"), dict) else {}
        disassembly_info = file_analysis.get("disassembly_info") if isinstance(file_analysis.get("disassembly_info"), dict) else {}
        ml_result = file_analysis.get("ml_classification") if isinstance(file_analysis.get("ml_classification"), dict) else {}
        ioc_total = sum(len(v) for v in (file_analysis.get("iocs", {}) or {}).values())

        static_components = []
        if signatures:
            static_components.append(f"{len(signatures)} signature hit(s)")
        if entropy_text != "n/a":
            static_components.append(f"entropy {entropy_text}")
        if ioc_total:
            static_components.append(f"{ioc_total} IOC(s)")
        if disassembly_info:
            static_components.append(f"{len(disassembly_info.get('suspicious_patterns', []))} suspicious code pattern(s)")
        if ml_result:
            static_components.append(f"ML prediction {ml_result.get('prediction', 'UNKNOWN')}")

        if pe_info:
            arch = str(pe_info.get("arch") or "unknown").upper()
            pe_bits = [f"PE {arch}"]
            if pe_info.get("suspicious"):
                pe_bits.append("suspicious header traits detected")
            if pe_info.get("is_dll"):
                pe_bits.append("DLL format")
            elif pe_info.get("is_dll") is False:
                pe_bits.append("executable image")
            return "Available", f"Static analysis completed ({', '.join(static_components) if static_components else 'no extra static signals'}). PE metadata present: {'; '.join(pe_bits)}."

        static_detail = ", ".join(static_components) if static_components else "no static signatures were recorded"
        return "Available", f"Static analysis completed ({static_detail}). PE header metadata was not present, so this sample is treated as non-PE or PE parsing was unavailable."

    def _get_analysis_methods_used(self, threat_analysis: Dict[str, Any]) -> list:
        """Get list of analysis methods used in the scan"""
        methods = []
        coverage = self._build_detection_coverage_overview(threat_analysis)
        if coverage.get("methods"):
            methods.extend(coverage.get("methods", []))
        input_type = str(threat_analysis.get("input_type") or "").strip().lower()
        if input_type == "advanced_report":
            interval_summaries = threat_analysis.get("interval_summaries") or []
            forensic_metadata = threat_analysis.get("forensic_metadata", {}) if isinstance(threat_analysis.get("forensic_metadata"), dict) else {}
            behavioral_sequence = threat_analysis.get("behavioral_sequence") or forensic_metadata.get("behavioral_sequence") or []
            threat_indicators = threat_analysis.get("threat_indicators") or []
            api_results = threat_analysis.get("api_results", {}) if isinstance(threat_analysis.get("api_results"), dict) else {}
            apis_called = api_results.get("apis_called", []) or []
            apis_expected = api_results.get("apis_expected", []) or []
            source_details = forensic_metadata.get("source_details", []) or []

            total_scans = sum(int((item.get("activity") or {}).get("threat_scans", 0) or 0) for item in interval_summaries if isinstance(item, dict))
            total_threats = sum(int((item.get("activity") or {}).get("threats_detected", 0) or 0) for item in interval_summaries if isinstance(item, dict))
            total_vulns = sum(int((item.get("vulns") or {}).get("total", 0) or 0) for item in interval_summaries if isinstance(item, dict))

            methods.append({
                "name": "Activity Telemetry Aggregation",
                "status": "COMPLETED" if interval_summaries else "LIMITED",
                "details": f"Aggregated {len(interval_summaries)} interval window(s): {total_scans} scan event(s), {total_threats} detected threat event(s).",
            })
            methods.append({
                "name": "Monitoring & Log Correlation",
                "status": "COMPLETED" if behavioral_sequence else "LIMITED",
                "details": f"Correlated {len(behavioral_sequence)} monitor event(s) with interval telemetry and {len(source_details)} corroborating source detail(s).",
            })
            methods.append({
                "name": "IDS / IPS Decision Logic",
                "status": "COMPLETED" if threat_indicators else "LIMITED",
                "details": f"Applied IDS/IPS verdict logic across {len(threat_indicators)} threat indicator(s) to derive the report posture.",
            })
            methods.append({
                "name": "Endpoint Vulnerability Correlation",
                "status": "COMPLETED" if interval_summaries else "LIMITED",
                "details": f"Correlated endpoint exposure with {total_vulns} vulnerability finding(s) across selected intervals.",
            })
            methods.append({
                "name": "Threat Indicator Consolidation",
                "status": "COMPLETED" if threat_indicators else "LIMITED",
                "details": f"Consolidated {len(threat_indicators)} threat indicator(s) into the comprehensive report context.",
            })
            methods.append({
                "name": "Behavioral Sequence & Corroboration",
                "status": "COMPLETED" if (behavioral_sequence or source_details) else "LIMITED",
                "details": f"Assembled {len(behavioral_sequence)} behavioral event(s) and {len(source_details)} corroborating source detail(s).",
            })
            methods.append({
                "name": "Threat Intelligence APIs",
                "status": "COMPLETED" if apis_called else ("LIMITED" if apis_expected else "NOT EXECUTED"),
                "details": (
                    f"Threat intelligence providers queried: {', '.join(apis_called)}."
                    if apis_called
                    else ("Provider coverage metadata was included but no provider completed in this run." if apis_expected else "This comprehensive report was generated from local monitoring telemetry without direct external provider execution.")
                ),
            })
            return methods

        # Get file analysis data if available
        file_data = self._normalize_file_analysis(threat_analysis)
        scanner_methods = file_data.get("analysis_methods_used", []) if isinstance(file_data, dict) else []
        if isinstance(scanner_methods, list) and scanner_methods:
            methods.extend(scanner_methods)

        is_file_scan = input_type in {"file", "file_hash", "hash", "artifact"} or bool(file_data)
        analysis_family = str(file_data.get("analysis_family") or threat_analysis.get("analysis_family") or "").strip().lower()
        forensic_metadata = threat_analysis.get("forensic_metadata", {}) if isinstance(threat_analysis.get("forensic_metadata"), dict) else {}
        has_file_payload = bool(file_data)
        lief_available = importlib.util.find_spec("lief") is not None
        capstone_available = importlib.util.find_spec("capstone") is not None
        sklearn_available = (
            importlib.util.find_spec("sklearn") is not None
            or importlib.util.find_spec("scikit_learn") is not None
        )
        
        # 1. Signature Analysis
        signatures = file_data.get("signatures", []) if isinstance(file_data, dict) else []
        sig_count = len(signatures)
        if has_file_payload:
            methods.append({
                "name": "Signature Matching",
                "status": "COMPLETED",
                "details": f"YARA rules, byte-pattern signatures, and regex heuristics applied. Found {sig_count} signature matches."
            })
        elif is_file_scan:
            methods.append({
                "name": "Signature Matching",
                "status": "LIMITED",
                "details": "File scan context exists, but signature evidence was not included in this payload."
            })
        else:
            methods.append({
                "name": "Signature Matching",
                "status": "NOT EXECUTED",
                "details": "Target profile is not a file artifact in this report payload; file signature matching was not executed."
            })
        
        # 2. Entropy Analysis
        entropy_value = file_data.get("entropy") if isinstance(file_data, dict) else None
        if entropy_value is not None:
            try:
                entropy = float(entropy_value)
            except (TypeError, ValueError):
                entropy = 0.0
            methods.append({
                "name": "Shannon Entropy Analysis",
                "status": "COMPLETED",
                "details": f"Calculated file entropy: {entropy:.3f}. Used for packed/encrypted file detection."
            })
        elif is_file_scan:
            methods.append({
                "name": "Shannon Entropy Analysis",
                "status": "LIMITED",
                "details": "File scan context exists, but entropy telemetry was not present in this report payload."
            })
        else:
            methods.append({
                "name": "Shannon Entropy Analysis",
                "status": "NOT EXECUTED",
                "details": "Target profile is not a file artifact in this report payload; entropy analysis was not executed."
            })

        # 2b. IOC and contextual string heuristics
        ioc_count = sum(len(v) for v in (file_data.get("iocs", {}) or {}).values())
        suspicious_count = len(file_data.get("suspicious_strings", []) or [])
        methods.append({
            "name": "IOC & Context Heuristics",
            "status": "COMPLETED" if (ioc_count or suspicious_count or has_file_payload) else ("LIMITED" if is_file_scan else "NOT EXECUTED"),
            "details": (
                f"Extracted {ioc_count} IOC value(s) and {suspicious_count} suspicious context string(s) for heuristic enrichment."
                if (ioc_count or suspicious_count or has_file_payload)
                else ("File scan context exists, but IOC/context telemetry was not present in this report payload." if is_file_scan else "Target profile is not a file artifact in this report payload; IOC/context file heuristics were not executed.")
            ),
        })

        # 2c. OLE / Office macro heuristics
        ole_info = file_data.get("ole_info") if isinstance(file_data, dict) else None
        if isinstance(ole_info, dict) and ole_info:
            methods.append({
                "name": "OLE / Office Heuristic Analysis",
                "status": "COMPLETED",
                "details": (
                    f"Macro-capable container detected with {len(ole_info.get('macro_indicators', []))} marker(s), "
                    f"{ole_info.get('embedded_object_count', 0)} embedded object signal(s), and contextual Office artifact scanning."
                ),
            })
        
        # 3. PE/COFF Analysis
        pe_info = file_data.get("pe_info") or file_data.get("coff_info")
        if pe_info or analysis_family == "pe_coff" or forensic_metadata.get("pe_machine"):
            methods.append({
                "name": "PE/COFF Binary Analysis",
                "status": "COMPLETED",
                "details": (
                    f"Advanced PE parsing with lief and pefile. Sections: {len((pe_info or {}).get('sections', []))}, "
                    f"Imports: {len((pe_info or {}).get('imports', []))}, Anomalies: {len((pe_info or {}).get('anomalies', []))}, "
                    f"PDB paths: {len((pe_info or {}).get('pdb_paths', []))}."
                )
            })
        elif not is_file_scan:
            methods.append({
                "name": "PE/COFF Binary Analysis",
                "status": "NOT EXECUTED",
                "details": "Target profile is not a file artifact in this report payload; PE/COFF analysis was not executed."
            })
        elif not lief_available:
            methods.append({
                "name": "PE/COFF Binary Analysis",
                "status": "LIMITED",
                "details": "lief library not available in runtime; install lief to enable PE/COFF binary analysis."
            })
        else:
            methods.append({
                "name": "PE/COFF Binary Analysis",
                "status": "LIMITED",
                "details": "File scan context exists but no parseable PE/COFF structures were returned in this payload."
            })
        
        # 4. Disassembly Analysis
        disassembly = file_data.get("disassembly_info", {})
        if disassembly:
            suspicious_patterns = len(disassembly.get("suspicious_patterns", []))
            methods.append({
                "name": "Code Disassembly",
                "status": "COMPLETED",
                "details": f"Capstone-based disassembly analysis. Found {suspicious_patterns} suspicious code patterns and {disassembly.get('total_instructions', 0)} total instructions."
            })
        elif not is_file_scan:
            methods.append({
                "name": "Code Disassembly",
                "status": "NOT EXECUTED",
                "details": "Target profile is not a file artifact in this report payload; disassembly analysis was not executed."
            })
        elif not capstone_available:
            methods.append({
                "name": "Code Disassembly",
                "status": "LIMITED",
                "details": "Capstone library not available in runtime; install capstone to enable disassembly analysis."
            })
        else:
            methods.append({
                "name": "Code Disassembly",
                "status": "LIMITED",
                "details": "File scan context exists but executable instruction sections were not available for disassembly in this payload."
            })
        
        # 5. ML Classification
        ml_result = file_data.get("ml_classification", {})
        if ml_result:
            prediction = ml_result.get("prediction", "UNKNOWN")
            confidence = ml_result.get("confidence", 0)
            methods.append({
                "name": "Machine Learning Classification",
                "status": "COMPLETED",
                "details": f"Scikit-learn based malware classification. Prediction: {prediction} (Confidence: {confidence:.2f})"
            })
        elif not is_file_scan:
            methods.append({
                "name": "Machine Learning Classification",
                "status": "NOT EXECUTED",
                "details": "Target profile is not a file artifact in this report payload; ML file classifier was not executed."
            })
        elif not sklearn_available:
            methods.append({
                "name": "Machine Learning Classification",
                "status": "LIMITED",
                "details": "scikit-learn not available in runtime; install scikit-learn to enable ML classification."
            })
        else:
            methods.append({
                "name": "Machine Learning Classification",
                "status": "LIMITED",
                "details": "File scan context exists but ML classification output was not available in this payload."
            })
        
        # 6. Threat Intelligence APIs
        api_results = threat_analysis.get("api_results", {})
        apis_called = api_results.get("apis_called", [])
        apis_expected = api_results.get("apis_expected", [])
        api_status = api_results.get("api_status", {}) if isinstance(api_results, dict) else {}
        status_metas = [
            meta for meta in (api_status.values() if isinstance(api_status, dict) else [])
            if isinstance(meta, dict)
        ]
        applicable_metas = [meta for meta in status_metas if bool(meta.get("applicable"))]
        applicable_status_values = [str(meta.get("status", "unknown")).lower() for meta in applicable_metas]

        checked_count = sum(1 for s in applicable_status_values if s in {"checked", "online", "available", "clean", "no_threat"})
        pending_count = sum(1 for s in applicable_status_values if s == "pending")
        not_applicable_count = sum(1 for s in (str(meta.get("status", "unknown")).lower() for meta in status_metas) if s == "not_applicable")
        unauthorized_count = sum(1 for s in applicable_status_values if s == "not_authorized")
        rate_limited_count = sum(1 for s in applicable_status_values if s == "rate_limited")
        missing_config_count = sum(1 for s in applicable_status_values if s in {"missing_key", "not_configured"})
        expected_count = len(applicable_metas)
        total_tracked_count = max(len(apis_expected), len(status_metas))
        fm_checked = int(forensic_metadata.get("apis_checked", 0) or 0)
        fm_total = int(forensic_metadata.get("total_apis_available", 0) or 0)
        target_supports_ti = input_type in {"ip", "domain", "url", "file", "file_hash", "hash", "artifact", "network", "email"}

        if expected_count == 0:
            if fm_checked > 0:
                api_method_status = "COMPLETED"
                api_method_details = (
                    f"Threat intelligence checks completed for {fm_checked} provider(s) "
                    f"based on forensic metadata context."
                )
            elif target_supports_ti or fm_total > 0 or bool(apis_called):
                api_method_status = "LIMITED"
                api_method_details = (
                    "Threat intelligence provider output was not included in this report payload; "
                    "run a fresh scan/report to capture full provider coverage details."
                )
            else:
                api_method_status = "NOT EXECUTED"
                api_method_details = (
                    f"Threat intelligence APIs were not executed for this target profile "
                    f"({not_applicable_count}/{total_tracked_count} marked not applicable in provider map)."
                )
        elif checked_count >= expected_count:
            api_method_status = "COMPLETED"
            api_method_details = (
                f"Checked {checked_count}/{expected_count} applicable threat intelligence sources: "
                f"{', '.join(apis_called) if apis_called else 'source list unavailable'}"
            )
        elif checked_count == 0 and rate_limited_count > 0 and (rate_limited_count + pending_count) >= expected_count:
            api_method_status = "RATE LIMITED"
            api_method_details = (
                f"No applicable provider completed due to rate limiting/pending completion "
                f"({rate_limited_count} rate-limited, {pending_count} pending of {expected_count} applicable)."
            )
        elif checked_count == 0 and unauthorized_count > 0:
            api_method_status = "UNAUTHORIZED"
            api_method_details = (
                f"Applicable providers returned authorization failures "
                f"({unauthorized_count}/{expected_count}); verify API plan permissions and account scope."
            )
        elif checked_count == 0 and missing_config_count >= max(1, expected_count):
            api_method_status = "NOT CONFIGURED"
            api_method_details = "Threat intelligence providers are not configured with valid API keys."
        else:
            api_method_status = "PARTIAL"
            api_method_details = (
                f"Checked {checked_count}/{expected_count} applicable threat intelligence sources "
                f"({rate_limited_count} rate-limited, {unauthorized_count} unauthorized, {pending_count} pending)."
            )

        methods.append({
            "name": "Threat Intelligence APIs",
            "status": api_method_status,
            "details": api_method_details,
        })
        
        # 7. Behavioral Analysis (if available)
        behavioral = threat_analysis.get("behavioral_analysis", {})
        ai_behavioral = threat_analysis.get("ai_analysis", {}).get("behavioral_analysis", {}) if isinstance(threat_analysis.get("ai_analysis"), dict) else {}
        if behavioral or ai_behavioral:
            behavioral_payload = behavioral if behavioral else ai_behavioral
            methods.append({
                "name": "Behavioral Analysis",
                "status": "COMPLETED",
                "details": f"Analyzed {len(behavioral_payload.get('indicators', []))} behavioral indicators and {len(behavioral_payload.get('anomalies', []))} anomalies."
            })

        ai_analysis = threat_analysis.get("ai_analysis", {}) if isinstance(threat_analysis.get("ai_analysis"), dict) else {}
        anomaly_detection = ai_analysis.get("anomaly_detection", {}) if isinstance(ai_analysis.get("anomaly_detection"), dict) else {}
        threat_prediction = ai_analysis.get("threat_prediction", {}) if isinstance(ai_analysis.get("threat_prediction"), dict) else {}
        if anomaly_detection:
            methods.append({
                "name": "AI / ML Anomaly Detection",
                "status": "COMPLETED",
                "details": f"Anomaly score {float(anomaly_detection.get('score', 0.0) or 0.0):.3f} with factors: {', '.join(anomaly_detection.get('factors', [])[:4]) or 'none reported'}."
            })
        if threat_prediction:
            methods.append({
                "name": "AI / ML Threat Prediction",
                "status": "COMPLETED",
                "details": f"Threat probability {float(threat_prediction.get('probability', 0.0) or 0.0):.3f} and level {threat_prediction.get('threat_level', 'unknown')}."
            })

        if ai_analysis.get("behavioral_analysis") or ai_analysis.get("reputation_score"):
            methods.append({
                "name": "Detection Orchestration",
                "status": "COMPLETED",
                "details": "Local heuristics, behavioral signals, AI/ML scoring, and corroboration logic were fused into the final verdict."
            })

        # 7b. Corroboration and sequence analysis
        forensic_metadata = threat_analysis.get("forensic_metadata", {}) or {}
        behavioral_sequence = threat_analysis.get("behavioral_sequence") or forensic_metadata.get("behavioral_sequence") or []
        source_details = forensic_metadata.get("source_details", []) or []
        methods.append({
            "name": "Behavioral Sequence & Corroboration",
            "status": "COMPLETED" if (behavioral_sequence or source_details) else "LIMITED",
            "details": f"Assembled {len(behavioral_sequence)} behavioral event(s) and {len(source_details)} corroborating source detail(s) for timeline reconstruction.",
        })
        
        # 8. Network Analysis (if applicable)
        network = threat_analysis.get("network_analysis", {})
        if network:
            methods.append({
                "name": "Network Traffic Analysis",
                "status": "COMPLETED",
                "details": f"Analyzed network connections and traffic patterns. Found {len(network.get('suspicious_connections', []))} suspicious connections."
            })

        unique_methods = []
        seen_names = set()
        for method in methods:
            method_name = str(method.get("name", "")).strip()
            if not method_name or method_name in seen_names:
                continue
            seen_names.add(method_name)
            unique_methods.append(method)

        return unique_methods


# Global instance
report_generator = ReportGenerator()
