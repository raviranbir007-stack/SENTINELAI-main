"""
Advanced Reports API endpoints
"""
import io
import logging
import time
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import desc, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ....database import get_db
from ....models import AttackEvent, ScanHistory

router = APIRouter()
logger = logging.getLogger(__name__)

GENERATED_REPORTS_DIR = Path(__file__).resolve().parents[4] / "generated_reports"

# Known benign infrastructure IPs to filter from reports/incidents
BENIGN_INFRASTRUCTURE_IPS = {
    # Google DNS & services
    '8.8.8.8', '8.8.4.4', '142.250.192.195', '142.251.41.14', '172.217.27.170',
    '2001:4860:4860::8888', '2001:4860:4860::8844', '2607:f8b0:4004:814::200e',
    # Cloudflare DNS & services
    '1.1.1.1', '1.0.0.1', '151.101.209.91', '2606:4700:4700::1111', '2606:4700:4700::1001',
    '2620:1ec:46::68',
    # AWS
    '52.168.117.174', '54.239.28.30', '2600:1901:0:38d7::',
    # Microsoft Azure
    '20.189.173.1', '40.74.30.199',
    # Quad9
    '9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9',
    # OpenDNS
    '208.67.222.222', '208.67.220.220',
    # Verisign
    '64.6.64.6', '64.6.65.6',
    # Adguard
    '94.140.14.14', '94.140.15.15',
}


def _is_benign_infrastructure_indicator(indicator_value: str, indicator_type: str | None = None) -> bool:
    """Check if an indicator is known benign infrastructure (should not appear in threat reports)."""
    value = str(indicator_value or "").strip()
    if not value:
        return False
    
    # Check exact IP matches
    if value in BENIGN_INFRASTRUCTURE_IPS:
        return True
    
    # Check domain/URL matches for known CDNs (if applicable)
    lower_val = value.lower()
    cdn_keywords = {"google.com", "cloudflare.com", "aws.amazon.com", "azure.microsoft.com", 
                    "gstatic.com", "doubleclick.net"}
    if any(cdn in lower_val for cdn in cdn_keywords):
        return True
    
    return False


def _is_clean_verdict_only(indicator: dict) -> bool:
    """Check if indicator only has clean/safe verdicts (noise, no threat)."""
    verdict = str(indicator.get("verdict") or "").lower().strip()
    severity = str(indicator.get("severity") or "").lower().strip()
    status = str(indicator.get("status") or "").lower().strip()
    
    # Filter out CLEAN/SAFE verdicts
    if verdict in {"clean", "safe", "ok", "benign", "whitelisted", "not_detected"}:
        return True
    if severity in {"safe", "benign", "low_risk"}:
        return True
    if status in {"clean", "safe"}:
        return True
    
    return False


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _infer_indicator_type(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "unknown"
    try:
        ipaddress.ip_address(text)
        return "ip"
    except Exception:
        pass
    lower = text.lower()
    if lower.startswith(("http://", "https://", "hxxp://", "hxxps://")):
        return "url"
    if "." in text and "/" not in text and " " not in text:
        return "domain"
    if len(text) in {32, 40, 64} and all(ch in "0123456789abcdefABCDEF" for ch in text):
        return "file_hash"
    return "unknown"


def _build_api_status(threat_indicators: list[dict] | None) -> dict:
    # Import locally to avoid heavy imports at module import time
    from ....config import settings

    indicators = threat_indicators or []
    observed_types = {
        _infer_indicator_type(item.get("indicator") or item.get("value"))
        for item in indicators
        if isinstance(item, dict)
    }
    if not observed_types:
        observed_types = {"ip", "domain", "url", "file_hash"}

    key_presence = {
        "virustotal": bool(getattr(settings, "VIRUSTOTAL_API_KEY", "")),
        "abuseipdb": bool(getattr(settings, "ABUSEIPDB_API_KEY", "")),
        "shodan": bool(getattr(settings, "SHODAN_API_KEY", "")),
        "urlscan": bool(getattr(settings, "URLSCAN_API_KEY", "")),
        "hybrid_analysis": bool(getattr(settings, "HYBRIDANALYSIS_API_KEY", "")),
    }

    supported = {
        "virustotal": {"ip", "domain", "url", "file_hash"},
        "abuseipdb": {"ip", "domain", "url"},
        "shodan": {"ip", "domain", "url"},
        "urlscan": {"domain", "url"},
        "hybrid_analysis": {"file_hash"},
    }

    names = {
        "virustotal": "VirusTotal",
        "abuseipdb": "AbuseIPDB",
        "shodan": "Shodan",
        "urlscan": "URLScan.io",
        "hybrid_analysis": "Hybrid Analysis",
    }

    result = {}
    for provider in ("virustotal", "abuseipdb", "shodan", "urlscan", "hybrid_analysis"):
        applicable = bool(observed_types & supported[provider])
        configured = key_presence[provider]
        result[provider] = {
            "name": names[provider],
            "status": "not_executed",
            "configured": configured,
            "applicable": applicable,
        }
    return result


def _safe_report_name(raw_name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in str(raw_name or "report")).strip("._")
    return cleaned or "report"


def _store_generated_report(report_meta: dict, pdf_bytes: bytes) -> None:
    try:
        from ....api.compat import store_report_artifacts

        store_report_artifacts(report_meta, pdf_bytes)
    except Exception:
        GENERATED_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        report_id = str(report_meta.get("report_id") or _safe_report_name(report_meta.get("title") or "report"))
        (GENERATED_REPORTS_DIR / f"{report_id}.pdf").write_bytes(pdf_bytes)


class AdvancedReportRequest(BaseModel):
    target: str | None = None
    risk_score: float | None = None
    threats: list[str] | None = None
    scan_summary: str | None = None
    intervals: list[str] | None = None
    include_files: bool | None = None
    include_urls: bool | None = None
    include_ips: bool | None = None
    include_domains: bool | None = None
    include_hashes: bool | None = None
    include_attacks: bool | None = None
    include_defense_actions: bool | None = None
    format: str | None = "pdf"
    report_type: str | None = None
    report_timezone: str | None = None


def _normalize_intervals(intervals: list[str] | None) -> list[str]:
    """Normalize interval inputs and preserve caller order."""
    allowed = {"24h", "7d", "30d"}
    if not intervals:
        return ["24h"]

    normalized: list[str] = []
    for raw in intervals:
        value = str(raw or "").strip().lower()
        if value in allowed and value not in normalized:
            normalized.append(value)

    return normalized or ["24h"]


def _to_float_01(value: object) -> float:
    try:
        raw = float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
    if raw > 1.0:
        raw = raw / 100.0
    return max(0.0, min(raw, 1.0))


async def _collect_interval_security_metrics(db: AsyncSession, hours: int, scan_limit: int = 500, attack_limit: int = 500) -> dict:
    threshold = utcnow() - timedelta(hours=hours)

    attack_rows = (
        await db.execute(
            select(AttackEvent)
            .where(AttackEvent.detected_at >= threshold)
            .order_by(AttackEvent.detected_at.desc())
            .limit(attack_limit)
        )
    ).scalars().all()

    scan_rows = (
        await db.execute(
            select(ScanHistory)
            .where(ScanHistory.scan_timestamp >= threshold)
            .order_by(ScanHistory.scan_timestamp.desc())
            .limit(scan_limit)
        )
    ).scalars().all()

    attack_count = int((await db.execute(select(func.count(AttackEvent.id)).where(AttackEvent.detected_at >= threshold))).scalar() or 0)
    scan_count = int((await db.execute(select(func.count(ScanHistory.id)).where(ScanHistory.scan_timestamp >= threshold))).scalar() or 0)

    attacks = [
        {
            "event_id": attack.event_id,
            "type": attack.attack_type,
            "severity": str(getattr(attack.severity, "value", attack.severity) or "medium").lower(),
            "confidence": _to_float_01(attack.confidence),
            "source_ip": attack.source_ip,
            "source_domain": attack.source_domain,
            "description": attack.description,
            "status": attack.status,
            "detected_at": attack.detected_at.isoformat() if attack.detected_at else None,
        }
        for attack in attack_rows
    ]

    scans = [
        {
            "scan_id": scan.scan_id,
            "target": scan.target,
            "target_type": scan.target_type,
            "threat_level": str(scan.threat_level or "unknown").lower(),
            "confidence": _to_float_01(scan.confidence),
            "threats_detected": int(scan.threats_detected or 0),
            "scan_source": scan.scan_source or "manual",
            "scan_timestamp": scan.scan_timestamp.isoformat() if scan.scan_timestamp else None,
        }
        for scan in scan_rows
    ]

    return {
        "attack_count": attack_count,
        "scan_count": scan_count,
        "attacks": attacks,
        "scans": scans,
    }


@router.get("/interval/{interval}")
async def generate_interval_report(
    interval: str,
    report_type: str = "executive_summary",
    format: str = "pdf",
    report_timezone: str | None = None,
):
    """Generate a single-interval report for UIs that call interval path directly."""
    interval_key = str(interval or "").strip().lower()
    if interval_key not in {"24h", "7d", "30d"}:
        raise HTTPException(status_code=400, detail="Invalid interval. Use one of: 24h, 7d, 30d")

    request_payload = AdvancedReportRequest(
        intervals=[interval_key],
        report_type=report_type,
        format=format,
        report_timezone=report_timezone,
        include_files=True,
        include_urls=True,
        include_ips=True,
        include_domains=True,
        include_hashes=True,
        include_attacks=True,
        include_defense_actions=True,
    )
    return await generate_comprehensive_report(request_payload)


@router.post("/generate-comprehensive")
async def generate_comprehensive_report(req: AdvancedReportRequest, db: AsyncSession = Depends(get_db)):
    """Generate comprehensive threat analysis report with AI + local fallback."""
    try:
        # Import here to avoid heavy module initialization at startup.
        from ....core.report_generator import report_generator
        from ....core.activity_database import activity_db

        selected_intervals = _normalize_intervals(req.intervals)
        interval_label = ", ".join(selected_intervals)
        report_target = req.target or "Sentinel-AI Comprehensive Report"
        interval_hours_map = {"24h": 24, "7d": 24 * 7, "30d": 24 * 30}
        interval_summaries = []
        primary_hours = interval_hours_map.get(selected_intervals[0], 24)
        for interval in selected_intervals:
            hours = interval_hours_map.get(interval, 24)
            summary = activity_db.get_activity_summary(hours=hours)
            vuln_summary = report_generator._get_endpoint_vuln_summary(hours=hours)
            server_metrics = await _collect_interval_security_metrics(db, hours)
            interval_summaries.append({
                "interval": interval,
                "hours": hours,
                "activity": summary,
                "vulns": vuln_summary,
                "server_metrics": {
                    "attack_count": server_metrics["attack_count"],
                    "scan_count": server_metrics["scan_count"],
                    "recent_attacks": server_metrics["attacks"][:25],
                    "recent_scans": server_metrics["scans"][:25],
                },
            })

        primary_server_metrics = await _collect_interval_security_metrics(db, primary_hours)

        # Keep threat rows aligned to the selected time window so 24h/7d/30d reports
        # reflect only the clicked interval.
        # Fetch more threats for comprehensive reporting (increased from 200 to 1000)
        recent_threats = activity_db.get_recent_threats(limit=1000, hours=primary_hours)
        distribution = activity_db.get_threat_distribution(hours=primary_hours)

        def _normalize_conf(value: object) -> float:
            try:
                raw = float(value or 0.0)
            except (TypeError, ValueError):
                return 0.0
            if raw > 1.0:
                raw = raw / 100.0
            return max(0.0, min(raw, 1.0))

        threat_indicators = [
            {
                "indicator": str(item.get("value") or "unknown"),
                "severity": str(item.get("verdict") or "suspicious").lower(),
                "source": str(item.get("type") or "activity_monitor"),
                "confidence": _normalize_conf(item.get("confidence")),
                "timestamp": item.get("time"),
            }
            for item in recent_threats
            # FILTER: Exclude benign infrastructure IPs and CLEAN/SAFE verdicts
            if not _is_benign_infrastructure_indicator(item.get("value"), item.get("type"))
            and not _is_clean_verdict_only(item)
        ]
        threat_indicators.extend(
            {
                "indicator": str(item.get("source_ip") or item.get("source_domain") or item.get("type") or "attack_event"),
                "severity": str(item.get("severity") or "high").lower(),
                "source": "attack_event",
                "confidence": _to_float_01(item.get("confidence")),
                "timestamp": item.get("detected_at"),
            }
            for item in primary_server_metrics.get("attacks", [])
        )
        threat_indicators.extend(
            {
                "indicator": str(item.get("target") or item.get("scan_id") or "scan_event"),
                "severity": str(item.get("threat_level") or "suspicious").lower(),
                "source": "scan_history",
                "confidence": _to_float_01(item.get("confidence")),
                "timestamp": item.get("scan_timestamp"),
            }
            for item in primary_server_metrics.get("scans", [])
        )
        if req.threats:
            threat_indicators.extend(
                {
                    "indicator": str(t),
                    "severity": "medium",
                    "source": "dashboard",
                    "confidence": 0.5,
                }
                for t in req.threats
                if t
            )

        verdict_counts = distribution.get("by_verdict", {}) if isinstance(distribution, dict) else {}
        malicious_count = int(verdict_counts.get("malicious", 0) or 0) + int(verdict_counts.get("critical", 0) or 0)
        suspicious_count = int(verdict_counts.get("suspicious", 0) or 0)
        if malicious_count > 0:
            computed_verdict = "malicious"
        elif suspicious_count > 0:
            computed_verdict = "suspicious"
        elif threat_indicators:
            computed_verdict = "suspicious"
        else:
            computed_verdict = "safe"

        confidence_samples = [item.get("confidence", 0.0) for item in threat_indicators if isinstance(item, dict)]
        computed_confidence = sum(confidence_samples) / len(confidence_samples) if confidence_samples else 0.0
        if req.risk_score is not None:
            computed_confidence = _normalize_conf(req.risk_score)

        source_names = sorted({str(item.get("source", "unknown")) for item in threat_indicators if isinstance(item, dict)})
        forensic_metadata = {
            "corroboration_count": len(source_names),
            "corroboration_threshold_met": len(source_names) >= 2,
            "unique_sources": source_names,
            "total_indicators": len(threat_indicators),
            "critical_indicators": sum(1 for t in threat_indicators if str(t.get("severity", "")).lower() in {"critical", "malicious"}),
            "medium_indicators": sum(1 for t in threat_indicators if str(t.get("severity", "")).lower() in {"medium", "suspicious"}),
            "low_indicators": sum(1 for t in threat_indicators if str(t.get("severity", "")).lower() in {"low", "safe", "clean"}),
            "apis_checked": 0,
            "total_apis_available": 0,
            "source_details": [
                {
                    "source": str(item.get("type") or "activity_monitor"),
                    "severity": str(item.get("verdict") or "suspicious"),
                    "indicator": str(item.get("value") or "unknown"),
                    "timestamp": item.get("time"),
                    "score": _normalize_conf(item.get("confidence")),
                }
                for item in recent_threats[:12]
                # FILTER: Exclude benign infrastructure IPs and CLEAN verdicts
                if not _is_benign_infrastructure_indicator(item.get("value"), item.get("type"))
                and not _is_clean_verdict_only(item)
            ],
            "attack_events_covered": int(primary_server_metrics.get("attack_count", 0) or 0),
            "scan_history_covered": int(primary_server_metrics.get("scan_count", 0) or 0),
            "recent_attack_events": primary_server_metrics.get("attacks", [])[:20],
            "recent_scan_history": primary_server_metrics.get("scans", [])[:20],
        }

        raw_requested_type = str(req.report_type or "executive_summary").strip().lower()
        normalized_report_type = report_generator._normalize_report_type(req.report_type or "executive_summary")

        threat_analysis = {
            "input": report_target,
            "input_type": "advanced_report",
            "verdict": computed_verdict,
            "confidence": computed_confidence,
            "threat_indicators": threat_indicators,
            "api_results": {
                "apis_called": [],
                "apis_expected": ["virustotal", "abuseipdb", "shodan", "urlscan", "hybrid_analysis"],
                "api_status": _build_api_status(threat_indicators),
            },
            "summary": req.scan_summary or f"Generated for intervals: {interval_label}",
            "report_type": normalized_report_type,
            "report_timezone": req.report_timezone,
            "intervals": selected_intervals,
            "interval_summaries": interval_summaries,
            "forensic_metadata": forensic_metadata,
            "behavioral_sequence": [
                {
                    "timestamp": str(item.get("time") or "unknown"),
                    "stage": "threat_detection",
                    "source": str(item.get("type") or "activity_monitor"),
                    "details": f"{item.get('value', 'unknown')} detected as {str(item.get('verdict', 'suspicious')).upper()}",
                    "confidence": _normalize_conf(item.get("confidence")),
                }
                for item in recent_threats[:12]
            ],
            "timestamp": int(time.time()),
        }

        report_id = _safe_report_name(f"advanced_{int(time.time())}")
        threat_analysis["report_id"] = report_id

        requested_type = raw_requested_type
        if requested_type in {"all", "suite", "all_formats", "all_types"}:
            suite_reports = []
            suite_types = [
                "executive_summary",
                "technical_analysis",
                "forensic_investigation",
            ]
            suite_intervals = ["24h", "7d", "30d"]
            suite_counter = 0
            for interval in suite_intervals:
                hours = interval_hours_map.get(interval, 24)
                interval_activity = activity_db.get_activity_summary(hours=hours)
                interval_vulns = report_generator._get_endpoint_vuln_summary(hours=hours)
                interval_recent_threats = activity_db.get_recent_threats(limit=1000, hours=hours)
                interval_distribution = activity_db.get_threat_distribution(hours=hours)
                interval_server_metrics = await _collect_interval_security_metrics(db, hours)

                interval_indicators = [
                    {
                        "indicator": str(item.get("value") or "unknown"),
                        "severity": str(item.get("verdict") or "suspicious").lower(),
                        "source": str(item.get("type") or "activity_monitor"),
                        "confidence": _normalize_conf(item.get("confidence")),
                        "timestamp": item.get("time"),
                    }
                    for item in interval_recent_threats
                ]
                interval_indicators.extend(
                    {
                        "indicator": str(item.get("source_ip") or item.get("source_domain") or item.get("type") or "attack_event"),
                        "severity": str(item.get("severity") or "high").lower(),
                        "source": "attack_event",
                        "confidence": _to_float_01(item.get("confidence")),
                        "timestamp": item.get("detected_at"),
                    }
                    for item in interval_server_metrics.get("attacks", [])
                )
                interval_indicators.extend(
                    {
                        "indicator": str(item.get("target") or item.get("scan_id") or "scan_event"),
                        "severity": str(item.get("threat_level") or "suspicious").lower(),
                        "source": "scan_history",
                        "confidence": _to_float_01(item.get("confidence")),
                        "timestamp": item.get("scan_timestamp"),
                    }
                    for item in interval_server_metrics.get("scans", [])
                )

                interval_verdict_counts = interval_distribution.get("by_verdict", {}) if isinstance(interval_distribution, dict) else {}
                interval_malicious_count = int(interval_verdict_counts.get("malicious", 0) or 0) + int(interval_verdict_counts.get("critical", 0) or 0)
                interval_suspicious_count = int(interval_verdict_counts.get("suspicious", 0) or 0)
                if interval_malicious_count > 0:
                    interval_verdict = "malicious"
                elif interval_suspicious_count > 0:
                    interval_verdict = "suspicious"
                elif interval_indicators:
                    interval_verdict = "suspicious"
                else:
                    interval_verdict = "safe"

                interval_conf_samples = [item.get("confidence", 0.0) for item in interval_indicators if isinstance(item, dict)]
                interval_confidence = sum(interval_conf_samples) / len(interval_conf_samples) if interval_conf_samples else 0.0

                interval_source_names = sorted({str(item.get("source", "unknown")) for item in interval_indicators if isinstance(item, dict)})
                interval_forensic_metadata = {
                    "corroboration_count": len(interval_source_names),
                    "corroboration_threshold_met": len(interval_source_names) >= 2,
                    "unique_sources": interval_source_names,
                    "total_indicators": len(interval_indicators),
                    "critical_indicators": sum(1 for t in interval_indicators if str(t.get("severity", "")).lower() in {"critical", "malicious"}),
                    "medium_indicators": sum(1 for t in interval_indicators if str(t.get("severity", "")).lower() in {"medium", "suspicious"}),
                    "low_indicators": sum(1 for t in interval_indicators if str(t.get("severity", "")).lower() in {"low", "safe", "clean"}),
                    "apis_checked": 0,
                    "total_apis_available": sum(1 for meta in _build_api_status(interval_indicators).values() if meta.get("configured")),
                    "source_details": [
                        {
                            "source": str(item.get("type") or "activity_monitor"),
                            "severity": str(item.get("verdict") or "suspicious"),
                            "indicator": str(item.get("value") or "unknown"),
                            "timestamp": item.get("time"),
                            "score": _normalize_conf(item.get("confidence")),
                        }
                        for item in interval_recent_threats[:50]
                    ],
                    "attack_events_covered": int(interval_server_metrics.get("attack_count", 0) or 0),
                    "scan_history_covered": int(interval_server_metrics.get("scan_count", 0) or 0),
                    "recent_attack_events": interval_server_metrics.get("attacks", [])[:20],
                    "recent_scan_history": interval_server_metrics.get("scans", [])[:20],
                }

                interval_summaries_payload = [{
                    "interval": interval,
                    "hours": hours,
                    "activity": interval_activity,
                    "vulns": interval_vulns,
                    "server_metrics": {
                        "attack_count": interval_server_metrics["attack_count"],
                        "scan_count": interval_server_metrics["scan_count"],
                        "recent_attacks": interval_server_metrics["attacks"][:25],
                        "recent_scans": interval_server_metrics["scans"][:25],
                    },
                }]

                for report_type in suite_types:
                    suite_counter += 1
                    suite_id = _safe_report_name(f"advanced_{interval}_{report_type}_{int(time.time())}_{suite_counter}")
                    suite_payload = {
                        "input": report_target,
                        "input_type": "advanced_report",
                        "verdict": interval_verdict,
                        "confidence": interval_confidence,
                        "threat_indicators": interval_indicators,
                        "api_results": {
                            "apis_called": [],
                            "apis_expected": ["virustotal", "abuseipdb", "shodan", "urlscan", "hybrid_analysis"],
                            "api_status": _build_api_status(interval_indicators),
                        },
                        "summary": f"Generated for interval: {interval}",
                        "report_type": report_type,
                        "report_timezone": req.report_timezone,
                        "intervals": [interval],
                        "interval_summaries": interval_summaries_payload,
                        "forensic_metadata": interval_forensic_metadata,
                        "behavioral_sequence": [
                            {
                                "timestamp": str(item.get("time") or "unknown"),
                                "stage": "threat_detection",
                                "source": str(item.get("type") or "activity_monitor"),
                                "details": f"{item.get('value', 'unknown')} detected as {str(item.get('verdict', 'suspicious')).upper()}",
                                "confidence": _normalize_conf(item.get("confidence")),
                            }
                            for item in interval_recent_threats[:50]
                        ],
                        "timestamp": int(time.time()),
                        "report_id": suite_id,
                    }

                    logger.debug("Generating suite report | interval=%s | type=%s", interval, report_type)
                    suite_bytes = await report_generator.generate_analysis_report(suite_payload)
                    if not suite_bytes:
                        raise HTTPException(status_code=500, detail=f"Report generation failed for {interval}:{report_type}")

                    suite_meta = {
                        "report_id": suite_id,
                        "title": f"{report_target} - {interval.upper()} - {report_type.replace('_', ' ').title()}",
                        "target": report_target,
                        "interval": interval,
                        "type": report_type,
                        "threats_detected": len(interval_indicators),
                        "verdict": interval_verdict,
                        "confidence": interval_confidence,
                        "created": utcnow().isoformat(),
                        "download_url": f"/api/v1/reports/download/{suite_id}",
                    }
                    _store_generated_report(suite_meta, suite_bytes)
                    suite_reports.append(suite_meta)

            return JSONResponse(
                {
                    "status": "success",
                    "message": "Generated report suite for executive, technical, and forensic formats across 24h, 7d, and 30d",
                    "intervals": suite_intervals,
                    "count": len(suite_reports),
                    "reports": suite_reports,
                }
            )

        logger.debug("Generating comprehensive report | type=%s | intervals=%s", normalized_report_type, interval_label)
        report_bytes = await report_generator.generate_analysis_report(threat_analysis)
        if not report_bytes:
            raise HTTPException(status_code=500, detail="Report generation failed")

        is_pdf = bool(report_bytes.startswith(b"%PDF"))
        preferred_pdf = str(req.format or "pdf").lower() == "pdf"

        if is_pdf and preferred_pdf:
            content_type = "application/pdf"
            filename = f"sentinelai_report_{int(time.time())}.pdf"
        elif is_pdf:
            content_type = "application/pdf"
            filename = f"sentinelai_report_{int(time.time())}.pdf"
        else:
            content_type = "text/plain; charset=utf-8"
            filename = f"sentinelai_report_{int(time.time())}.txt"

        report_meta = {
            "report_id": report_id,
            "title": req.target or "Sentinel-AI Comprehensive Report",
            "target": report_target,
            "type": normalized_report_type,
            "threats_detected": len(threat_indicators),
            "verdict": computed_verdict,
            "confidence": computed_confidence,
            "report_timezone": req.report_timezone,
            "created": utcnow().isoformat(),
            "download_url": f"/api/v1/reports/download/{report_id}",
        }
        _store_generated_report(report_meta, report_bytes)

        return StreamingResponse(
            io.BytesIO(report_bytes),
            media_type=content_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Advanced report failed: {type(e).__name__}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Report generation failed")


@router.post("/generate-interval-analysis")
async def generate_interval_analysis_report(req: AdvancedReportRequest, db: AsyncSession = Depends(get_db)):
    """Generate comprehensive multi-interval report (24h | 7d | 30d) with distinct per-interval analysis sections."""
    try:
        from ....core.report_generator import report_generator
        from ....core.activity_database import activity_db

        interval_label = "24h, 7d, 30d"
        report_target = req.target or "Sentinel-AI Multi-Interval Analysis"
        interval_hours_map = {"24h": 24, "7d": 24 * 7, "30d": 24 * 30}
        selected_intervals = ["24h", "7d", "30d"]  # Always generate all 3
        interval_summaries = []
        
        for interval in selected_intervals:
            hours = interval_hours_map.get(interval, 24)
            summary = activity_db.get_activity_summary(hours=hours)
            vuln_summary = report_generator._get_endpoint_vuln_summary(hours=hours)
            interval_summaries.append({
                "interval": interval,
                "hours": hours,
                "activity": summary,
                "vulns": vuln_summary,
            })

        recent_threats = activity_db.get_recent_threats(limit=200)
        primary_hours = interval_hours_map["24h"]
        distribution = activity_db.get_threat_distribution(hours=primary_hours)

        def _normalize_conf(value: object) -> float:
            try:
                raw = float(value or 0.0)
            except (TypeError, ValueError):
                return 0.0
            if raw > 1.0:
                raw = raw / 100.0
            return max(0.0, min(raw, 1.0))

        threat_indicators = [
            {
                "indicator": str(item.get("value") or "unknown"),
                "severity": str(item.get("verdict") or "suspicious").lower(),
                "source": str(item.get("type") or "activity_monitor"),
                "confidence": _normalize_conf(item.get("confidence")),
                "timestamp": item.get("time"),
            }
            for item in recent_threats
        ]
        if req.threats:
            threat_indicators.extend(
                {
                    "indicator": str(t),
                    "severity": "medium",
                    "source": "dashboard",
                    "confidence": 0.5,
                }
                for t in req.threats
                if t
            )

        verdict_counts = distribution.get("by_verdict", {}) if isinstance(distribution, dict) else {}
        malicious_count = int(verdict_counts.get("malicious", 0) or 0) + int(verdict_counts.get("critical", 0) or 0)
        suspicious_count = int(verdict_counts.get("suspicious", 0) or 0)
        if malicious_count > 0:
            computed_verdict = "malicious"
        elif suspicious_count > 0:
            computed_verdict = "suspicious"
        elif threat_indicators:
            computed_verdict = "suspicious"
        else:
            computed_verdict = "safe"

        confidence_samples = [item.get("confidence", 0.0) for item in threat_indicators if isinstance(item, dict)]
        computed_confidence = sum(confidence_samples) / len(confidence_samples) if confidence_samples else 0.0
        if req.risk_score is not None:
            computed_confidence = _normalize_conf(req.risk_score)

        source_names = sorted({str(item.get("source", "unknown")) for item in threat_indicators if isinstance(item, dict)})
        forensic_metadata = {
            "corroboration_count": len(source_names),
            "corroboration_threshold_met": len(source_names) >= 2,
            "unique_sources": source_names,
            "total_indicators": len(threat_indicators),
            "critical_indicators": sum(1 for t in threat_indicators if str(t.get("severity", "")).lower() in {"critical", "malicious"}),
            "medium_indicators": sum(1 for t in threat_indicators if str(t.get("severity", "")).lower() in {"medium", "suspicious"}),
            "low_indicators": sum(1 for t in threat_indicators if str(t.get("severity", "")).lower() in {"low", "safe", "clean"}),
            "apis_checked": 0,
            "total_apis_available": sum(1 for meta in _build_api_status(threat_indicators).values() if meta.get("configured")),
            "source_details": [
                {
                    "source": str(item.get("type") or "activity_monitor"),
                    "severity": str(item.get("verdict") or "suspicious"),
                    "indicator": str(item.get("value") or "unknown"),
                    "timestamp": item.get("time"),
                    "score": _normalize_conf(item.get("confidence")),
                }
                for item in recent_threats[:12]
            ],
        }

        normalized_report_type = report_generator._normalize_report_type(req.report_type or "executive_summary")

        threat_analysis = {
            "input": report_target,
            "input_type": "interval_analysis",
            "verdict": computed_verdict,
            "confidence": computed_confidence,
            "threat_indicators": threat_indicators,
            "api_results": {
                "apis_called": [],
                "apis_expected": ["virustotal", "abuseipdb", "shodan", "urlscan", "hybrid_analysis"],
                "api_status": _build_api_status(threat_indicators),
            },
            "summary": f"Multi-interval analysis comparing immediate (24h), trending (7d), and strategic (30d) threat postures.",
            "report_type": normalized_report_type,
            "report_timezone": req.report_timezone,
            "intervals": selected_intervals,
            "interval_summaries": interval_summaries,
            "forensic_metadata": forensic_metadata,
            "behavioral_sequence": [
                {
                    "timestamp": str(item.get("time") or "unknown"),
                    "stage": "threat_detection",
                    "source": str(item.get("type") or "activity_monitor"),
                    "details": f"{item.get('value', 'unknown')} detected as {str(item.get('verdict', 'suspicious')).upper()}",
                    "confidence": _normalize_conf(item.get("confidence")),
                }
                for item in recent_threats[:12]
            ],
            "timestamp": int(time.time()),
        }

        report_id = _safe_report_name(f"interval_analysis_{int(time.time())}")
        threat_analysis["report_id"] = report_id

        logger.debug("Generating comprehensive interval analysis report | type=%s | intervals=%s", normalized_report_type, interval_label)
        report_bytes = await report_generator.generate_comprehensive_interval_report(threat_analysis)
        if not report_bytes:
            raise HTTPException(status_code=500, detail="Interval analysis report generation failed")

        is_pdf = bool(report_bytes.startswith(b"%PDF"))
        content_type = "application/pdf" if is_pdf else "text/plain; charset=utf-8"
        filename = f"sentinel_interval_analysis_{int(time.time())}.pdf"

        report_meta = {
            "report_id": report_id,
            "title": f"{report_target} - Multi-Interval Analysis",
            "target": report_target,
            "type": f"{normalized_report_type}_interval",
            "intervals": selected_intervals,
            "threats_detected": len(threat_indicators),
            "verdict": computed_verdict,
            "confidence": computed_confidence,
            "report_timezone": req.report_timezone,
            "created": utcnow().isoformat(),
            "download_url": f"/api/v1/reports/download/{report_id}",
        }
        _store_generated_report(report_meta, report_bytes)

        return StreamingResponse(
            io.BytesIO(report_bytes),
            media_type=content_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Interval analysis report failed: {type(e).__name__}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Report generation failed")