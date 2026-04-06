"""
PDF Report Generator using Gemini API
Generates AI-analyzed threat reports in PDF format
"""

import asyncio
import importlib.util
import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, Optional
import time

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
        key_candidates = [
            (getattr(settings, "GEMINI_API_KEY", "") if settings else ""),
            os.getenv("GEMINI_API_KEY", ""),
            os.getenv("GOOGLE_API_KEY", ""),
        ]
        for idx in range(1, 6):
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
        self._last_gemini_failure_reason = ""
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
        self.gemini_exec_only = str(os.getenv("GEMINI_EXECUTIVE_ONLY", "true")).strip().lower() in {"1", "true", "yes", "on"}
        
        # Rate limiter: configurable request spacing to reduce provider throttling.
        self._last_request_time = 0
        try:
            self._min_request_interval = float(os.getenv("GEMINI_MIN_REQUEST_INTERVAL", "2.0"))
        except Exception:
            self._min_request_interval = 2.0
        self._min_request_interval = max(0.2, self._min_request_interval)

        model_candidates = os.getenv(
            "GEMINI_MODEL_CANDIDATES",
            "gemini-2.5-flash,gemini-1.5-flash,gemini-1.5-pro"
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
            return None

    def _format_scan_results_section(self, threat_analysis: Dict[str, Any]) -> str:
        """Format a clear, detailed scan results section for the report."""
        from .threat_analyzer import ALL_EXTERNAL_APIS
        api_results = threat_analysis.get("api_results", {})
        api_status = api_results.get("api_status", {})
        apis_called = api_results.get("apis_called", [])
        apis_expected = api_results.get("apis_expected", [api["name"] for api in ALL_EXTERNAL_APIS])
        lines = [f"APIs Expected: {', '.join(apis_expected)}"]
        lines.append(f"APIs Called: {', '.join(apis_called)}")
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
            status = meta.get("status", "unknown")
            configured = meta.get("configured", False)
            applicable = meta.get("applicable", False)
            error = meta.get("error")
            # For test/demo domains, override status string for clarity
            if explanation and status == "not_applicable":
                status_str = "not_applicable (test/demo domain)"
            elif status == "not_configured":
                status_str = "not_configured (API key missing)"
            elif status == "rate_limited":
                status_str = "exceed_quota (rate limited)"
            else:
                status_str = status
            lines.append(f"- {name}: status={status_str}, configured={configured}, applicable={applicable}{' | error: ' + error if error else ''}")
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
        lines = []
        lines.append(f"Corroboration Count: {forensic.get('corroboration_count', 0)}")
        lines.append(f"Corroboration Threshold Met: {forensic.get('corroboration_threshold_met', False)}")
        lines.append(f"APIs Checked: {forensic.get('apis_checked', 0)} / {forensic.get('total_apis_available', 0)}")
        lines.append(f"Scan Coverage: {forensic.get('scan_coverage', '')}")
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

        lines = []
        for index, event in enumerate(sequence, start=1):
            lines.append(
                f"{index}. {event.get('timestamp', 'unknown')} | {event.get('stage', 'telemetry')} | {event.get('source', 'unknown')} | {event.get('details', '')}"
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
        value = str(report_type or "executive_summary").strip().lower()
        if value in {"technical", "technical_report"}:
            return "technical_analysis"
        if value in {"forensic", "forensic_analysis", "digital_forensics", "forensic_investigation"}:
            return "forensic_investigation"
        return "executive_summary"

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
                "Report format: TECHNICAL ANALYSIS\\n"
                "Sections required:\\n"
                "1. Technical Verdict Summary (concise)\\n"
                "2. Detection Pipeline Breakdown (static, signatures, behavior, intel APIs, ML)\\n"
                "3. Indicator Correlation Matrix (source-wise corroboration)\\n"
                "4. Attack Surface and TTP Mapping\\n"
                "5. False-Positive/Falsification Risk Discussion\\n"
                "6. Engineering Remediation Plan (prioritized, technical steps)\\n"
                "7. Monitoring/Detection Rule Improvements\\n"
                "Tone: deep technical, SOC/IR engineer perspective, include concrete evidence and confidence caveats."
            )
        if normalized == "forensic_investigation":
            return (
                "Report format: FORENSIC INVESTIGATION DOSSIER\\n"
                "Sections required:\\n"
                "1. Case Overview and Scope\\n"
                "2. Chain-of-Custody Notes and Evidence Integrity Considerations\\n"
                "3. Artifact Inventory (hashes, indicators, telemetry sources)\\n"
                "4. Timeline Reconstruction (chronological events)\\n"
                "5. Source Corroboration and Reliability Assessment\\n"
                "6. Attribution Confidence and Alternate Hypotheses\\n"
                "7. Legal/Compliance-Ready Conclusions and Next Actions\\n"
                "Tone: forensic investigator perspective, strict evidence language, avoid over-claiming."
            )
        return (
            "Report format: EXECUTIVE SUMMARY\\n"
            "Sections required:\\n"
            "1. Executive Risk Snapshot\\n"
            "2. Business Impact Summary\\n"
            "3. Key Findings (top 5)\\n"
            "4. Reliability and Confidence Notes (plain language)\\n"
            "5. Immediate Decisions Required\\n"
            "6. 24-72 Hour Action Plan\\n"
            "Tone: leadership-facing, concise, decision-oriented, minimal jargon."
        )

    def _count_reports_in_window(self, seconds: int) -> int:
        if not hasattr(self, "_daily_reports"):
            return 0
        now = datetime.now()
        threshold = now - timedelta(seconds=max(1, int(seconds)))
        return sum(1 for ts in self._daily_reports if isinstance(ts, datetime) and ts >= threshold)

    def _should_use_gemini_for_report(self, threat_data: Dict[str, Any]) -> tuple[bool, str]:
        report_type = self._normalize_report_type(threat_data.get("report_type", "executive_summary"))
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
                logger.warning("Gemini circuit open until %s, skipping remote call", self._circuit_open_until)
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
                                                temperature=0.7,
                                                top_p=0.9,
                                                max_output_tokens=1400
                                            )
                                        )),
                                        timeout=20.0
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
                                        # Try next key first; retry attempts are still available.
                                        logger.warning("Gemini quota/rate issue on model %s key #%d", model_name, key_index + 1)
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
                            timeout=20.0
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
            self._store_cached_analysis(cache_key, genai_result)
            return genai_result

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
- Scan Time: {threat_data.get('timestamp', 'Unknown')}
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

Keep professional, cite specific data, 550-850 words total.
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
        apis_called = api_results.get("apis_called", [])
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

        if report_type == "technical_analysis":
            analysis = f"""## TECHNICAL VERDICT SUMMARY

Target: {input_val} (Type: {input_type})
Assessment: {verdict}
Confidence: {confidence:.1f}%
Scan Date: {threat_data.get('timestamp', 'Unknown')}

{coverage_line}

## DETECTION PIPELINE BREAKDOWN

{interval_summary_text}

## BEHAVIORAL SEQUENCE SUMMARY

{behavioral_sequence_text}

## TECHNICAL ACTIONS

1. Review PE/COFF and signature findings first.
2. Validate any high-entropy or packed sections against the runtime behavior.
3. Tune detections for the observed IOC patterns and API coverage gaps.

"""
        elif report_type == "forensic_investigation":
            analysis = f"""## CASE OVERVIEW

Case Subject: {input_val} (Type: {input_type})
Primary Assessment: {verdict}
Confidence: {confidence:.1f}%
Evidence Time Reference: {threat_data.get('timestamp', 'Unknown')}

## SCOPE AND EVIDENCE CONTEXT

{coverage_line}

## TIMELINE WINDOW SUMMARY

{interval_summary_text}

## BEHAVIORAL SEQUENCE

{behavioral_sequence_text}

## FORENSIC NOTES

1. Preserve source artifacts and hashes.
2. Reconcile indicator sources before remediation.
3. Treat single-source findings as lower-confidence leads.

"""
        else:
            analysis = f"""## EXECUTIVE SUMMARY

Target: {input_val} (Type: {input_type})
Assessment: {verdict}
Confidence: {confidence:.1f}%
Scan Date: {threat_data.get('timestamp', 'Unknown')}

{coverage_line}

## INTERVAL COVERAGE

{interval_summary_text}

## OPERATIONAL TIMELINE

{behavioral_sequence_text}

## DECISION FOCUS

1. Validate containment urgency.
2. Communicate business impact.
3. Track follow-up actions and ownership.
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
            analysis += "## DETAILED ANALYSIS\n\n"

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

        analysis += "## ANALYSIS QUALITY MATRIX\n\n"
        methods = self._get_analysis_methods_used(threat_data)
        if methods:
            for method in methods[:8]:
                method_name = str(method.get("name", "Unknown"))
                method_status = str(method.get("status", "UNKNOWN"))
                method_details = str(method.get("details", ""))
                analysis += f"- {method_name}: {method_status} | {method_details}\n"
            analysis += "\n"
        else:
            analysis += "- No method telemetry was available in the current payload.\n\n"

        # Analyze threat indicators
        if threats:
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
        else:
            analysis += "### No Threats Detected\n\n"
            analysis += "No significant security threats were detected during the comprehensive scan across all security intelligence APIs.\n\n"

        # Add API-specific details
        if report_type == "forensic_investigation":
            analysis += "## TECHNICAL FINDINGS AND FORENSIC ARTIFACTS\n\n"
        else:
            analysis += "## TECHNICAL FINDINGS\n\n"
        
        if "abuseipdb" in api_results and api_results["abuseipdb"]:
            abuse_data = api_results["abuseipdb"].get("data", {})
            if abuse_data:
                score = abuse_data.get("abuseConfidenceScore", 0)
                analysis += f"**AbuseIPDB:**\n"
                analysis += f"- Abuse Confidence: {score}%\n"
                analysis += f"- Total Reports: {abuse_data.get('totalReports', 0)}\n"
                analysis += f"- ISP: {abuse_data.get('isp', 'Unknown')}\n"
                analysis += f"- Country: {abuse_data.get('countryCode', 'Unknown')}\n\n"

        if "shodan" in api_results and api_results["shodan"]:
            shodan_data = api_results["shodan"]
            if not shodan_data.get("error"):
                analysis += f"**Shodan:**\n"
                analysis += f"- Organization: {shodan_data.get('org', 'Unknown')}\n"
                analysis += f"- Open Ports: {len(shodan_data.get('ports', []))}\n"
                analysis += f"- Vulnerabilities: {len(shodan_data.get('vulns', []))}\n\n"

        if "virustotal" in api_results and api_results["virustotal"]:
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
        else:
            analysis += "## RECOMMENDATIONS\n\n"
        
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

        analysis += f"\n\nConfidence Level: {confidence:.1f}%\n"
        analysis += f"APIs Consulted: {', '.join(apis_called) if apis_called else 'None'}\n"
        analysis += "\n---\n"
        analysis += "*Analysis continued through the local forensic pipeline to maintain report continuity.*"

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
        api_status = threat_analysis.get("api_results", {}).get("api_status", {}) or {}
        rows = [["Source", "Status", "Configured", "Applicable"]]

        if not api_status:
            rows.append(["N/A", "No telemetry", "No", "No"])
            return rows

        for api_key in ["virustotal", "abuseipdb", "shodan", "urlscan", "hybrid_analysis"]:
            api_meta = api_status.get(api_key)
            if not api_meta:
                continue
            rows.append(
                [
                    str(api_meta.get("name", api_key)),
                    str(api_meta.get("status", "unknown")).replace("_", " ").title(),
                    "Yes" if api_meta.get("configured") else "No",
                    "Yes" if api_meta.get("applicable") else "No",
                ]
            )

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

        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            textColor=colors.HexColor("#1a1a1a"),
            spaceAfter=6,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        )

        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading2"],
            fontSize=14,
            textColor=colors.HexColor("#0066cc"),
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
        )

        emphasis_style = ParagraphStyle(
            "Emphasis",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#2f3b52"),
            backColor=colors.HexColor("#f4f7fb"),
            borderPadding=8,
        )

        # Build document elements
        elements = []

        report_type = self._normalize_report_type(threat_analysis.get("report_type", "executive_summary"))

        # Header
        header_title = {
            "executive_summary": "SENTINEL-AI EXECUTIVE RISK REPORT",
            "technical_analysis": "SENTINEL-AI TECHNICAL ANALYSIS REPORT",
            "forensic_investigation": "SENTINEL-AI FORENSIC INVESTIGATION REPORT",
        }.get(report_type, "SENTINEL-AI THREAT ANALYSIS REPORT")
        elements.append(Paragraph(header_title, title_style))
        elements.append(Spacer(1, 0.2 * inch))

        # Report Info
        timestamp = threat_analysis.get("timestamp", datetime.now(timezone.utc).isoformat())
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
            ["Report Generated:", timestamp],
            ["Target:", input_val],
            ["Target Type:", input_type.upper()],
            ["Report Profile:", report_type.replace("_", " ").title()],
            ["Verdict:", verdict.upper()],
            ["Confidence:", f"{confidence * 100:.1f}%"],
            ["Sources Corroborating:", str(corroboration_count)],
            ["Forensic Threshold Met:", forensic_threshold_text],
        ]

        info_table = Table(info_data, colWidths=[2 * inch, 4 * inch])
        info_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e6e6e6")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ("BACKGROUND", (1, 4), (1, 4), verdict_style["bg"]),
                    ("TEXTCOLOR", (1, 4), (1, 4), verdict_style["fg"]),
                    ("FONTNAME", (1, 4), (1, 4), "Helvetica-Bold"),
                    ("BACKGROUND", (1, 7), (1, 7), forensic_cell_bg),
                    ("TEXTCOLOR", (1, 7), (1, 7), forensic_cell_fg),
                    ("FONTNAME", (1, 7), (1, 7), "Helvetica-Bold"),
                ]
            )
        )

        elements.append(info_table)
        elements.append(Spacer(1, 0.3 * inch))

        threats = threat_analysis.get("threat_indicators", [])
        action_plan = self._get_report_action_plan(threat_analysis)
        file_analysis = self._normalize_file_analysis(threat_analysis)
        risk_contract = file_analysis.get("risk_contract", {}) if isinstance(file_analysis.get("risk_contract"), dict) else {}
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
            report_focus_rows = [
                ["Static / PE", "Present" if file_analysis else "Not available"],
                ["Signature / YARA", ", ".join(file_analysis.get("signatures", [])[:5]) or "No signature hits"],
                ["Entropy", f"{float(file_analysis.get('entropy', 0.0) or 0.0):.3f}"],
                ["IOC extraction", str(sum(len(v) for v in (file_analysis.get('iocs', {}) or {}).values()))],
                ["Behavioral events", str(len(threat_analysis.get('behavioral_sequence', []) or threat_analysis.get('forensic_metadata', {}).get('behavioral_sequence', []) or []))],
                ["Threat intel APIs", str(len(threat_analysis.get('api_results', {}).get('apis_called', []) or []))],
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
            focus_table = Table([["Focus Area", "Value"]] + report_focus_rows, colWidths=[2.2 * inch, 3.8 * inch])
            focus_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elements.append(focus_table)
            elements.append(Spacer(1, 0.18 * inch))

        if report_type == "executive_summary":
            elements.append(Paragraph("BUSINESS IMPACT & DECISIONS", heading_style))
            summary_lines = [
                f"Decision urgency: {'Immediate' if verdict_key in {'malicious', 'suspicious'} else 'Routine'}",
                f"Operational posture: {'Containment recommended' if verdict_key in {'malicious', 'suspicious'} else 'Monitoring recommended'}",
                f"Top action: {action_plan[0] if action_plan else 'Continue monitoring'}",
            ]
            for line in summary_lines:
                elements.append(Paragraph(f"• {line}", normal_style))
            elements.append(Spacer(1, 0.15 * inch))

        if report_type == "technical_analysis":
            elements.append(Paragraph("DETECTION PIPELINE DETAILS", heading_style))
            pipeline_rows = [["Layer", "Evidence"]]
            pipeline_rows.append(["Static / PE", "Present" if file_analysis else "Not available"])
            pipeline_rows.append(["Signature / YARA", ", ".join(file_analysis.get("signatures", [])[:6]) or "No signature hits"])
            pipeline_rows.append(["IOC Extraction", ", ".join(sum((file_analysis.get("iocs", {}) or {}).values(), [])[:8]) or "None"])
            pipeline_rows.append(["Behavior / Network", f"{len(threat_analysis.get('behavioral_sequence', []) or threat_analysis.get('forensic_metadata', {}).get('behavioral_sequence', []) or [])} ordered events"])
            pipeline_rows.append(["Threat Intel", f"{len(threat_analysis.get('api_results', {}).get('apis_called', []) or [])} API source(s)"])
            pipeline_rows.append(["ML / Heuristic", f"Score {risk_contract.get('numeric_score', 'n/a')} | Confidence {risk_contract.get('confidence', 'n/a')}"])
            pipeline_table = Table(pipeline_rows, colWidths=[1.6 * inch, 4.4 * inch])
            pipeline_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elements.append(pipeline_table)
            elements.append(Spacer(1, 0.15 * inch))

        if report_type == "forensic_investigation":
            elements.append(Paragraph("EVIDENCE INVENTORY & TIMELINE", heading_style))
            evidence_rows = [["Evidence", "Type", "Value"]]
            if reason_codes:
                for reason in reason_codes[:6]:
                    if isinstance(reason, dict):
                        evidence_rows.append([reason.get("code", "UNKNOWN"), "Detector", reason.get("explanation", "")])
            for idx, threat in enumerate(threats[:4], start=1):
                evidence_rows.append([f"Threat {idx}", str(threat.get("source", "unknown")), str(threat.get("indicator", ""))[:120]])
            if forensic_metadata.get("source_details"):
                for detail in forensic_metadata.get("source_details", [])[:4]:
                    evidence_rows.append([str(detail.get("source", "unknown")), str(detail.get("severity", "unknown")), str(detail.get("indicator", ""))[:120]])
            if len(evidence_rows) == 1:
                evidence_rows.append(["N/A", "N/A", "No evidence inventory available"])
            evidence_table = Table(evidence_rows, colWidths=[1.35 * inch, 0.95 * inch, 4.05 * inch])
            evidence_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f766e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0fdfa")]),
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
                        str(event.get("timestamp", "unknown"))[:19],
                        str(event.get("stage", "telemetry")),
                        str(event.get("source", "unknown")),
                        str(event.get("details", ""))[:110],
                    ])
                if len(sequence_rows) > 1:
                    sequence_table = Table(sequence_rows, colWidths=[1.25 * inch, 1.1 * inch, 1.25 * inch, 3.75 * inch])
                    sequence_table.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#134e4a")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0fdfa")]),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]))
                    elements.append(sequence_table)
                    elements.append(Spacer(1, 0.15 * inch))
        
        # Activity Monitoring Section (if available)
        try:
            from .activity_database import activity_db
            activity_summary = activity_db.get_activity_summary(hours=24)
            
            if activity_summary and activity_summary.get('threat_scans', 0) > 0:
                elements.append(Paragraph("ACTIVITY MONITORING SUMMARY (Last 24h)", heading_style))
                
                activity_data = [
                    ["Metric", "Count"],
                    ["Threat Scans Performed", str(activity_summary.get('threat_scans', 0))],
                    ["Threats Detected", str(activity_summary.get('threats_detected', 0))],
                    ["Websites Monitored", str(activity_summary.get('websites_visited', 0))],
                    ["Applications Monitored", str(activity_summary.get('applications_launched', 0))],
                    ["Network Connections", str(activity_summary.get('network_connections', 0))],
                ]
                
                activity_table = Table(activity_data, colWidths=[3 * inch, 2 * inch])
                activity_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0066cc")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 11),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f0f0")]),
                        ("WORDWRAP", (0, 0), (-1, -1), True),  # Enable word wrapping
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),  # Align text to top
                    ])
                )
                
                elements.append(activity_table)
                elements.append(Spacer(1, 0.2 * inch))

                # Endpoint vulnerability scan summary (short/simple table)
                vuln_summary = self._get_endpoint_vuln_summary(hours=24)
                if vuln_summary and vuln_summary.get("total", 0) > 0:
                    elements.append(Paragraph("ENDPOINT VULNERABILITY SUMMARY (Last 24h)", heading_style))

                    vuln_data = [
                        ["Severity", "Findings"],
                        ["Critical", str(vuln_summary.get("critical", 0))],
                        ["High", str(vuln_summary.get("high", 0))],
                        ["Medium", str(vuln_summary.get("medium", 0))],
                        ["Low", str(vuln_summary.get("low", 0))],
                        ["Info", str(vuln_summary.get("info", 0))],
                        ["Total", str(vuln_summary.get("total", 0))],
                    ]

                    vuln_table = Table(vuln_data, colWidths=[3 * inch, 2 * inch])
                    vuln_table.setStyle(
                        TableStyle([
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474f")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 10),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                            ("TOPPADDING", (0, 0), (-1, -1), 7),
                            ("GRID", (0, 0), (-1, -1), 1, colors.black),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
                            ("BACKGROUND", (0, 6), (-1, 6), colors.HexColor("#eceff1")),
                            ("FONTNAME", (0, 6), (-1, 6), "Helvetica-Bold"),
                            ("WORDWRAP", (0, 0), (-1, -1), True),  # Enable word wrapping
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),  # Align text to top
                        ])
                    )
                    elements.append(vuln_table)
                    elements.append(Spacer(1, 0.2 * inch))
                
                # Recent threats from activity monitoring
                recent_threats = activity_db.get_recent_threats(limit=5)
                if recent_threats:
                    elements.append(Paragraph("Recent Threats Detected", heading_style))
                    
                    for threat in recent_threats:
                        threat_text = f"• [{threat['time']}] {threat['type'].upper()}: {threat['value']} - {threat['verdict'].upper()} (Confidence: {threat['confidence']:.1%}, Sources: {threat['sources']})"
                        elements.append(Paragraph(threat_text, normal_style))
                    
                    elements.append(Spacer(1, 0.2 * inch))
        except Exception as e:
            logger.debug(f"Could not include activity monitoring in report: {e}")

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
            methods_data,
            colWidths=[2.2 * inch, 1.2 * inch, 3.6 * inch]
        )
        methods_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2e7d32")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f8e9")]),
                ("WORDWRAP", (0, 0), (-1, -1), True),  # Enable word wrapping for long text
                ("VALIGN", (0, 0), (-1, -1), "TOP"),  # Align text to top for better readability
            ])
        )
        elements.append(methods_table)
        elements.append(Spacer(1, 0.2 * inch))

        # Intelligence source coverage
        elements.append(Paragraph("INTELLIGENCE SOURCE COVERAGE", heading_style))
        coverage_table = Table(
            self._get_api_coverage_rows(threat_analysis),
            colWidths=[1.8 * inch, 1.5 * inch, 1.2 * inch, 1.2 * inch],
        )
        coverage_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("WORDWRAP", (0, 0), (-1, -1), True),  # Enable word wrapping
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),  # Align text to top
                ]
            )
        )
        elements.append(coverage_table)
        elements.append(Spacer(1, 0.2 * inch))

        interval_summaries = threat_analysis.get("interval_summaries") or self._build_interval_summaries(threat_analysis)
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
                interval_rows,
                colWidths=[0.85 * inch, 0.9 * inch, 0.75 * inch, 0.85 * inch, 0.75 * inch, 0.8 * inch, 0.7 * inch],
            )
            interval_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                ])
            )
            elements.append(interval_table)
            elements.append(Spacer(1, 0.2 * inch))

        # Prioritized action plan
        elements.append(Paragraph("PRIORITIZED ACTION PLAN", heading_style))
        for index, action in enumerate(action_plan, start=1):
            elements.append(Paragraph(f"{index}. {action}", normal_style))
        elements.append(Spacer(1, 0.2 * inch))

        if report_type == "forensic_investigation":
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
        if forensic_metadata and forensic_metadata.get("source_details"):
            elements.append(Paragraph("FORENSIC EVIDENCE TRACKING", heading_style))
            
            source_details = forensic_metadata.get("source_details", [])
            if source_details:
                evidence_data = [["Source", "Severity", "Detection Details", "Timestamp"]]
                
                for detail in source_details:
                    evidence_data.append([
                        detail.get("source", "Unknown"),
                        detail.get("severity", "unknown").upper(),
                        detail.get("indicator", "")[:50],  # Truncate
                        detail.get("timestamp", "")[:19],  # Show only date/time
                    ])
                
                evidence_table = Table(
                    evidence_data, colWidths=[1.2 * inch, 0.9 * inch, 2.5 * inch, 1.4 * inch]
                )
                evidence_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#006633")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f8f0")]),
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
        if advanced_forensic:
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

            advanced_table = Table(advanced_rows, colWidths=[2.2 * inch, 3.8 * inch])
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

        # Threat Summary
        elements.append(Paragraph("THREAT SUMMARY", heading_style))

        if threats:
            threat_data = [["Source", "Severity", "Indicator"]]
            for threat in threats:
                threat_data.append(
                    [
                        threat.get("source", "Unknown"),
                        threat.get("severity", "unknown").upper(),
                        threat.get("indicator", "")[:80],  # Truncate long indicators
                    ]
                )

            threat_table = Table(
                threat_data, colWidths=[1.5 * inch, 1.2 * inch, 3.3 * inch]
            )
            threat_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0066cc")),
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
                            [colors.white, colors.HexColor("#f9f9f9")],
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

    def _get_analysis_methods_used(self, threat_analysis: Dict[str, Any]) -> list:
        """Get list of analysis methods used in the scan"""
        methods = []
        
        # Get file analysis data if available
        file_data = self._normalize_file_analysis(threat_analysis)
        scanner_methods = file_data.get("analysis_methods_used", []) if isinstance(file_data, dict) else []
        if isinstance(scanner_methods, list) and scanner_methods:
            methods.extend(scanner_methods)
        input_type = str(threat_analysis.get("input_type") or "").strip().lower()
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
        if behavioral:
            methods.append({
                "name": "Behavioral Analysis",
                "status": "COMPLETED",
                "details": f"Analyzed {len(behavioral.get('indicators', []))} behavioral indicators and {len(behavioral.get('anomalies', []))} anomalies."
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
