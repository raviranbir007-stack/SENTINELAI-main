"""
Advanced Reports API endpoints
"""
import io
import logging
import time
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
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


@router.post("/generate-comprehensive")
async def generate_comprehensive_report(req: AdvancedReportRequest):
    """Generate comprehensive threat analysis report with AI + local fallback."""
    try:
        # Import here to avoid heavy module initialization at startup.
        from ....core.report_generator import report_generator
        from ....core.activity_database import activity_db

        interval_label = ", ".join(req.intervals or ["24h"])
        report_target = req.target or "Sentinel-AI Comprehensive Report"
        interval_hours_map = {"24h": 24, "7d": 24 * 7, "30d": 24 * 30}
        selected_intervals = req.intervals or ["24h", "7d", "30d"]
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

        threat_analysis = {
            "input": report_target,
            "input_type": "advanced_report",
            "verdict": "unknown",
            "confidence": float(req.risk_score or 0.0),
            "threat_indicators": [
                {"indicator": t, "severity": "medium", "source": "dashboard"}
                for t in (req.threats or [])
            ],
            "api_results": {"apis_called": []},
            "summary": req.scan_summary or f"Generated for intervals: {interval_label}",
            "report_type": req.report_type or "executive_summary",
            "intervals": selected_intervals,
            "interval_summaries": interval_summaries,
            "timestamp": int(time.time()),
        }

        report_id = _safe_report_name(f"advanced_{int(time.time())}")
        threat_analysis["report_id"] = report_id

        logger.debug("Generating comprehensive report | type=%s | intervals=%s", req.report_type, interval_label)
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
            "type": req.report_type or "executive_summary",
            "threats_detected": len(req.threats or []),
            "verdict": "unknown",
            "confidence": float(req.risk_score or 0.0),
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