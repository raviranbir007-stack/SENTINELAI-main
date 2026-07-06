from pathlib import Path
import io
import asyncio
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ....core.report_generator import report_generator
from ....database import get_db
from ....models import ScanHistory

# ---------- ReportLab Import Handling ----------
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

# ---------- Gemini AI Optional Support ----------
try:
    import os

    try:
        # Prefer newer google-genai package
        import google.genai as genai
        GEMINI_READY = True
    except ImportError:
        # Fallback to deprecated package
        import google.generativeai as genai
        GEMINI_KEY = os.getenv("GEMINI_API_KEY")
        if GEMINI_KEY:
            genai.configure(api_key=GEMINI_KEY)
        GEMINI_READY = True
except Exception:
    GEMINI_READY = False

router = APIRouter()
logger = logging.getLogger(__name__)

GENERATED_REPORTS_DIR = Path(__file__).resolve().parents[4] / "generated_reports"
LEGACY_REPORT_DIRS = [
    GENERATED_REPORTS_DIR,
    Path(__file__).resolve().parents[5] / "generated_reports",
    Path(__file__).resolve().parents[5] / "server" / "generated_reports",
    Path(__file__).resolve().parents[4] / "app" / "generated_reports",
]


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


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
        is_pdf = isinstance(pdf_bytes, (bytes, bytearray)) and bytes(pdf_bytes).startswith(b"%PDF")
        extension = "pdf" if is_pdf else "txt"
        report_path = GENERATED_REPORTS_DIR / f"{report_id}.{extension}"
        report_path.write_bytes(pdf_bytes)


# ---------- Request Schema ----------
class ReportRequest(BaseModel):
    target: str | None = None
    scan_id: str | None = None
    risk_score: float | None = None
    threats: list[str] | None = None
    scan_summary: str | None = None
    report_type: str | None = None
    intervals: list[str] | None = None


# ---------- AI Text Generation ----------
def generate_ai_report(data: ReportRequest) -> str:
    base_text = f"""
Security Report for Target: {data.target}

Risk Score: {data.risk_score if data.risk_score is not None else "Not Available"}

Threat Summary:
{", ".join(data.threats) if data.threats else "No threats found or data missing."}

Scan Summary:
{data.scan_summary if data.scan_summary else "Scan summary not available."}
"""

    if not GEMINI_READY:
        return (
            base_text
            + "\n\nNote: AI enhancement unavailable. Install Gemini / set API key."
        )

    try:
        if hasattr(genai, "GenerativeModel"):
            model = genai.GenerativeModel("gemini-pro")
            response = model.generate_content(
                f"Create a professional cybersecurity vulnerability report:\n{base_text}"
            )
            return response.text
        logger.debug("Gemini client does not expose GenerativeModel; using fallback report text")
        return base_text + "\n\nNote: AI enhancement unavailable with current Gemini client."
    except Exception as e:
        logger.warning(f"Gemini AI unavailable, using fallback text: {e}")
        return base_text + "\n\nNote: AI enhancement failed."


# ---------- PDF Generator ----------
def create_pdf(text: str, data: ReportRequest) -> io.BytesIO:
    if not REPORTLAB_AVAILABLE:
        # If ReportLab is not installed, raise to be handled by endpoint
        raise HTTPException(
            status_code=500,
            detail="ReportLab not installed. Run: pip install reportlab",
        )

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setTitle(f"{data.target} Security Report")

    y = 750
    for line in text.split("\n"):
        if y < 40:
            pdf.showPage()
            y = 750
        safe_line = str(line or "").encode("latin-1", "replace").decode("latin-1")
        pdf.drawString(50, y, safe_line)
        y -= 18

    pdf.save()
    buffer.seek(0)
    return buffer


async def _generate_report_bytes_with_timeout(threat_analysis: dict, data: ReportRequest) -> bytes:
    """Generate report bytes with a bounded AI timeout and deterministic PDF fallback."""
    timeout_seconds = float(getattr(report_generator, "gemini_request_timeout_seconds", 20.0))
    # Keep endpoint timeout aligned with report generator limits.
    timeout_seconds = max(10.0, min(timeout_seconds, 120.0))
    try:
        logger.info(
            "REPORT_GENERATION_START | target=%s | report_type=%s | timeout=%ss",
            threat_analysis.get("input", "unknown"),
            threat_analysis.get("report_type", "unknown"),
            timeout_seconds
        )
        result = await asyncio.wait_for(
            report_generator.generate_analysis_report(threat_analysis),
            timeout=timeout_seconds,
        )
        logger.info(
            "REPORT_GENERATION_SUCCESS | target=%s | report_type=%s | reason=%s",
            threat_analysis.get("input", "unknown"),
            threat_analysis.get("report_type", "unknown"),
            report_generator._last_gemini_failure_reason or "Gemini success"
        )
        return result
    except asyncio.TimeoutError:
        logger.warning(
            "REPORT_GENERATION_TIMEOUT | target=%s | report_type=%s | timeout=%ss | using fallback",
            threat_analysis.get("input", "unknown"),
            threat_analysis.get("report_type", "unknown"),
            timeout_seconds,
        )
        fallback_text = report_generator._get_fallback_analysis(threat_analysis)
        scan_results = report_generator._format_scan_results_section(threat_analysis)
        forensic_summary = report_generator._format_forensic_summary(threat_analysis)
        fallback_blob = f"{fallback_text}\n\n---\n\nSCAN RESULTS\n\n{scan_results}\n\nFORENSIC SUMMARY\n\n{forensic_summary}"
        return create_pdf(fallback_blob, data).getvalue()
    except Exception as e:
        logger.error(
            "REPORT_GENERATION_ERROR | target=%s | report_type=%s | error=%s | reason=%s",
            threat_analysis.get("input", "unknown"),
            threat_analysis.get("report_type", "unknown"),
            str(e)[:200],
            report_generator._last_gemini_failure_reason or "unknown",
            exc_info=True
        )
        raise


# ---------- API Endpoint ----------
@router.post("/generate")
async def generate_report(data: ReportRequest, db: AsyncSession = Depends(get_db)):
    try:
        now = utcnow()
        report_id = _safe_report_name(data.scan_id or data.target or f"report_{int(now.timestamp())}")
        if data.scan_id:
            result = await db.execute(select(ScanHistory).where(ScanHistory.scan_id == data.scan_id))
            scan = result.scalar_one_or_none()
            if scan:
                data.target = scan.target or scan.target_type or scan.scan_id
                analysis_data = scan.analysis_data or {}
                data.scan_summary = data.scan_summary or analysis_data.get("summary")
                if not data.threats and isinstance(analysis_data.get("threat_indicators"), list):
                    data.threats = [
                        str(item.get("indicator") or item.get("description") or item)
                        for item in analysis_data.get("threat_indicators")
                        if item
                    ]

                threat_analysis = {
                    "input": data.target,
                    "input_type": scan.target_type or "unknown",
                    "verdict": scan.threat_level or analysis_data.get("verdict", "unknown"),
                    "confidence": scan.confidence if scan.confidence is not None else analysis_data.get("confidence", 0.0),
                    "threat_indicators": analysis_data.get("threat_indicators", data.threats or []),
                    "api_results": analysis_data.get("api_results", {}),
                    "summary": data.scan_summary or analysis_data.get("summary", ""),
                    "threats_detected": scan.threats_detected or len(analysis_data.get("threat_indicators", [])),
                    "analysis_data": analysis_data,
                    "file_analysis": analysis_data.get("file_analysis") if isinstance(analysis_data.get("file_analysis"), dict) else (analysis_data.get("local_analysis") if isinstance(analysis_data.get("local_analysis"), dict) else {}),
                    "forensic_metadata": analysis_data.get("forensic_metadata", {}),
                    "scan_id": scan.scan_id,
                    "threat_level": scan.threat_level or analysis_data.get("threat_level", "unknown"),
                    "status": "complete",
                    "report_type": data.report_type or "executive_summary",
                    "intervals": data.intervals or ["24h", "7d", "30d"],
                    "timestamp": scan.scan_timestamp.isoformat() if scan.scan_timestamp else utcnow().isoformat(),
                }

                report_bytes = await _generate_report_bytes_with_timeout(threat_analysis, data)
                if not report_bytes:
                    fallback_text = report_generator._get_fallback_analysis(threat_analysis)
                    scan_results = report_generator._format_scan_results_section(threat_analysis)
                    forensic_summary = report_generator._format_forensic_summary(threat_analysis)
                    report_bytes = (
                        f"{fallback_text}\n\n---\n\nSCAN RESULTS\n\n{scan_results}\n\nFORENSIC SUMMARY\n\n{forensic_summary}"
                    ).encode("utf-8", "replace")

                content_type = "application/pdf" if report_bytes.startswith(b"%PDF") else "text/plain; charset=utf-8"
                filename = f"{data.target}_security_report.pdf" if content_type == "application/pdf" else f"{data.target}_security_report.txt"
                report_meta = {
                    "report_id": report_id,
                    "title": f"Threat Analysis - {data.target}",
                    "target": data.target,
                    "type": threat_analysis.get("report_type", "executive_summary"),
                    "threats_detected": threat_analysis.get("threats_detected", len(threat_analysis.get("threat_indicators", []))),
                    "verdict": threat_analysis.get("verdict", "unknown"),
                    "confidence": threat_analysis.get("confidence", 0.0),
                    "created": now.isoformat(),
                    "download_url": f"/api/v1/reports/download/{report_id}",
                }
                _store_generated_report(report_meta, report_bytes)
                return StreamingResponse(
                    io.BytesIO(report_bytes),
                    media_type=content_type,
                    headers={"Content-Disposition": f"attachment; filename={filename}"},
                )

        if not data.target:
            raise HTTPException(status_code=400, detail="Report target or scan_id required")

        logger.debug(f"REPORT started | target={data.target} | scan_id={data.scan_id}")

        report_type = report_generator._normalize_report_type(data.report_type or "executive_summary")
        threat_analysis = {
            "input": data.target,
            "input_type": "manual_report",
            "verdict": "unknown",
            "confidence": float(data.risk_score or 0.0),
            "threat_indicators": [{"source": "manual_input", "severity": "unknown", "indicator": t} for t in (data.threats or [])],
            "api_results": {},
            "summary": data.scan_summary or "Manual report generation",
            "threats_detected": len(data.threats or []),
            "analysis_data": {},
            "file_analysis": {},
            "forensic_metadata": {},
            "scan_id": data.scan_id,
            "threat_level": "unknown",
            "status": "complete",
            "report_type": report_type,
            "intervals": data.intervals or ["24h", "7d", "30d"],
            "timestamp": utcnow().isoformat(),
        }
        report_bytes = await _generate_report_bytes_with_timeout(threat_analysis, data)
        if not report_bytes:
            report_text = generate_ai_report(data)
            report_bytes = report_text.encode("utf-8", "replace")

        content_type = "application/pdf" if report_bytes.startswith(b"%PDF") else "text/plain; charset=utf-8"
        report_meta = {
            "report_id": report_id,
            "title": f"Threat Analysis - {data.target}",
            "target": data.target,
            "type": report_type,
            "threats_detected": len(data.threats or []),
            "verdict": "unknown",
            "confidence": float(data.risk_score or 0.0),
            "created": now.isoformat(),
            "download_url": f"/api/v1/reports/download/{report_id}",
        }
        _store_generated_report(report_meta, report_bytes)

        filename = (
            f"{data.target}_security_report.pdf"
            if content_type == "application/pdf"
            else f"{data.target}_security_report.txt"
        )

        logger.debug(f"REPORT ok | target={data.target} | media={content_type}")
        return StreamingResponse(
            io.BytesIO(report_bytes),
            media_type=content_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        try:
            fallback_text = generate_ai_report(data)
            fallback_pdf = create_pdf(fallback_text, data)
            safe_target = _safe_report_name(data.target or "report")
            return StreamingResponse(
                fallback_pdf,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f"attachment; filename={safe_target}_security_report_fallback.pdf"
                },
            )
        except Exception:
            raise HTTPException(status_code=500, detail="Report generation failed")


@router.get("/")
async def list_reports():
    try:
        reports = []
        seen_ids = set()

        # 1) API compatibility store
        try:
            from ....api.compat import REPORTS_STORE

            if REPORTS_STORE:
                for report in reversed(REPORTS_STORE):
                    report_id = str(report.get("report_id") or "").strip()
                    if report_id and report_id not in seen_ids:
                        reports.append(report)
                        seen_ids.add(report_id)
        except Exception:
            pass

        # 2) In-memory generated report cache from report generator
        try:
            cache = getattr(report_generator, "_reports_cache", {}) or {}
            for report_id, payload in cache.items():
                rid = str(report_id or "").strip()
                if not rid or rid in seen_ids:
                    continue
                size_bytes = len(payload) if isinstance(payload, (bytes, bytearray)) else 0
                reports.append({
                    "report_id": rid,
                    "filename": f"{rid}.pdf",
                    "title": rid,
                    "created_at": utcnow().isoformat(),
                    "size_bytes": size_bytes,
                    "download_url": f"/api/v1/reports/download/{rid}",
                })
                seen_ids.add(rid)
        except Exception:
            pass

        # 3) Filesystem stores (current + legacy locations)
        for reports_dir in LEGACY_REPORT_DIRS:
            reports_dir.mkdir(parents=True, exist_ok=True)
            files = list(reports_dir.glob("*.pdf")) + list(reports_dir.glob("*.txt"))
            for f in sorted(files, key=lambda x: x.stat().st_mtime, reverse=True):
                rid = str(f.stem or "").strip()
                if not rid or rid in seen_ids:
                    continue
                reports.append({
                    "report_id": rid,
                    "filename": f.name,
                    "title": f.stem,
                    "created_at": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                    "size_bytes": f.stat().st_size,
                    "download_url": f"/api/v1/reports/download/{f.stem}"
                })
                seen_ids.add(rid)

        response = JSONResponse(
            {"reports": reports, "count": len(reports)},
            headers={
                "Cache-Control": "public, max-age=5",
                "ETag": f'"{len(reports)}-{utcnow().timestamp():.0f}"'
            }
        )
        return response

    except Exception as e:
        logger.error(f"List reports failed: {e}")
        response = JSONResponse(
            {"reports": [], "count": 0},
            headers={"Cache-Control": "public, max-age=5"}
        )
        return response


@router.get("/download/{report_id}")
async def download_report(report_id: str, db: AsyncSession = Depends(get_db)):
    """Generate and return a PDF report for the given report_id.

    First checks if report exists in cache, otherwise generates on-demand.
    """
    try:
        from ....core.report_generator import report_generator

        def _build_download_response(report_bytes: bytes, requested_id: str) -> StreamingResponse:
            is_pdf = isinstance(report_bytes, (bytes, bytearray)) and bytes(report_bytes).startswith(b"%PDF")
            ext = "pdf" if is_pdf else "txt"
            media = "application/pdf" if is_pdf else "text/plain; charset=utf-8"
            from io import BytesIO
            buf = BytesIO(report_bytes)
            buf.seek(0)
            return StreamingResponse(
                buf,
                media_type=media,
                headers={"Content-Disposition": f"attachment; filename={requested_id}.{ext}"},
            )

        report_path = GENERATED_REPORTS_DIR / f"{report_id}.pdf"
        if report_path.exists():
            return _build_download_response(report_path.read_bytes(), report_id)

        text_report_path = GENERATED_REPORTS_DIR / f"{report_id}.txt"
        if text_report_path.exists():
            return _build_download_response(text_report_path.read_bytes(), report_id)
        
        # Check cache first
        if hasattr(report_generator, '_reports_cache') and report_id in report_generator._reports_cache:
            logger.debug(f"REPORT dl | target={report_id} | src=cache")
            pdf_bytes = report_generator._reports_cache[report_id]
        else:
            logger.debug(f"REPORT dl | target={report_id} | src=rebuild")
            scan = None
            try:
                result = await db.execute(select(ScanHistory).where(ScanHistory.scan_id == report_id))
                scan = result.scalar_one_or_none()
            except Exception:
                scan = None

            if not scan:
                raise HTTPException(status_code=404, detail="Report not found")

            analysis_data = scan.analysis_data if isinstance(scan.analysis_data, dict) else {}
            threat_analysis = {
                "input": scan.target or scan.target_type or scan.scan_id,
                "input_type": scan.target_type or analysis_data.get("input_type") or "unknown",
                "verdict": scan.threat_level or analysis_data.get("verdict", "unknown"),
                "confidence": scan.confidence if scan.confidence is not None else analysis_data.get("confidence", 0.0),
                "threat_indicators": analysis_data.get("threat_indicators", []),
                "api_results": analysis_data.get("api_results", {}),
                "summary": analysis_data.get("summary", ""),
                "threats_detected": scan.threats_detected or len(analysis_data.get("threat_indicators", [])),
                "analysis_data": analysis_data,
                "file_analysis": analysis_data.get("file_analysis") if isinstance(analysis_data.get("file_analysis"), dict) else (analysis_data.get("local_analysis") if isinstance(analysis_data.get("local_analysis"), dict) else {}),
                "forensic_metadata": analysis_data.get("forensic_metadata", {}),
                "scan_id": scan.scan_id,
                "threat_level": scan.threat_level or analysis_data.get("threat_level", "unknown"),
                "status": "complete",
                "report_type": analysis_data.get("report_type", "executive_summary"),
                "intervals": analysis_data.get("intervals", ["24h", "7d", "30d"]),
                "timestamp": scan.scan_timestamp.isoformat() if scan.scan_timestamp else utcnow().isoformat(),
            }
            pdf_bytes = await report_generator.generate_analysis_report(threat_analysis)
            if not pdf_bytes:
                raise HTTPException(status_code=404, detail="Report not found")

        return _build_download_response(pdf_bytes, report_id)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Download report failed: {e}")
        raise HTTPException(status_code=500, detail="Report download failed")


@router.get("/diagnostics/gemini-status")
async def get_gemini_status():
    """Get detailed diagnostics about Gemini API availability and configuration.
    
    Returns information about:
    - API key configuration and validity
    - Circuit breaker state
    - Quota/rate limit status
    - Daily report usage
    - Recent failure reasons
    """
    try:
        diagnosis = await report_generator.diagnose_gemini_status()
        return JSONResponse(diagnosis)
    except Exception as e:
        logger.error(f"Gemini diagnostics failed: {e}")
        return JSONResponse(
            {
                "error": str(e),
                "gemini_available": GEMINI_READY,
                "timestamp": utcnow().isoformat()
            },
            status_code=500
        )
