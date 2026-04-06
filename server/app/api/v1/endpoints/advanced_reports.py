"""
Advanced Reports API endpoints
"""
import io
import logging
import time
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel

router = APIRouter()
logger = logging.getLogger(__name__)

GENERATED_REPORTS_DIR = Path(__file__).resolve().parents[4] / "generated_reports"


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
async def generate_comprehensive_report(req: AdvancedReportRequest):
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
            interval_summaries.append({
                "interval": interval,
                "hours": hours,
                "activity": summary,
                "vulns": vuln_summary,
            })

        # Keep threat rows aligned to the selected time window so 24h/7d/30d reports
        # reflect only the clicked interval.
        recent_threats = activity_db.get_recent_threats(limit=200, hours=primary_hours)
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
            ],
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
                "apis_expected": ["abuseipdb", "virustotal", "urlvoid", "otx", "shodan"],
                "api_status": {},
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
            for idx, report_type in enumerate(suite_types, start=1):
                suite_id = _safe_report_name(f"advanced_{report_type}_{int(time.time())}_{idx}")
                suite_payload = dict(threat_analysis)
                suite_payload["report_type"] = report_type
                suite_payload["report_id"] = suite_id

                logger.debug("Generating suite report | type=%s | intervals=%s", report_type, interval_label)
                suite_bytes = await report_generator.generate_analysis_report(suite_payload)
                if not suite_bytes:
                    raise HTTPException(status_code=500, detail=f"Report generation failed for {report_type}")

                suite_meta = {
                    "report_id": suite_id,
                    "title": f"{report_target} - {report_type.replace('_', ' ').title()}",
                    "target": report_target,
                    "type": report_type,
                    "threats_detected": len(threat_indicators),
                    "verdict": computed_verdict,
                    "confidence": computed_confidence,
                    "created": datetime.utcnow().isoformat(),
                    "download_url": f"/api/v1/reports/download/{suite_id}",
                }
                _store_generated_report(suite_meta, suite_bytes)
                suite_reports.append(suite_meta)

            return JSONResponse(
                {
                    "status": "success",
                    "message": "Generated report suite for executive, technical, and forensic formats",
                    "intervals": selected_intervals,
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
            "created": datetime.utcnow().isoformat(),
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
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)[:100]}")


@router.post("/generate-interval-analysis")
async def generate_interval_analysis_report(req: AdvancedReportRequest):
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

        recent_threats = activity_db.get_recent_threats(limit=20)
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
                "apis_expected": ["abuseipdb", "virustotal", "urlvoid", "otx", "shodan"],
                "api_status": {},
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
            "created": datetime.utcnow().isoformat(),
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
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)[:100]}")