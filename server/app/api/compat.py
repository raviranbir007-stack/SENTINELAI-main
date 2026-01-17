import random
import hashlib
from datetime import datetime, timedelta
from io import BytesIO

from fastapi import APIRouter, File, HTTPException, UploadFile, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..core.report_generator import report_generator
from ..core.threat_analyzer import threat_analyzer
from ..database import get_db
from ..models import ScanHistory

router = APIRouter()

# In-memory scan store for compatibility (ephemeral)
SCANS_STORE: list[dict] = []
MAX_STORE = 100

# In-memory reports store
REPORTS_STORE: list[dict] = []
# Report PDF cache (report_id -> pdf_bytes)
REPORTS_PDF_CACHE: dict[str, bytes] = {}


async def _save_scan_to_db(scan_data: dict, db: AsyncSession):
    """Save scan result to database for historical reporting"""
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        # Extract forensic metadata
        forensic = scan_data.get("forensic_metadata", {})
        evidence_sources = forensic.get("evidence_sources", [])
        corroboration_count = forensic.get("corroboration_count", 0)
        
        logger.info(f"Saving scan {scan_data.get('scan_id')} - Forensic: count={corroboration_count}, sources={evidence_sources}")
        logger.info(f"Scan type: {scan_data.get('type')}, confidence: {scan_data.get('confidence')}, threats: {scan_data.get('threats_detected')}")
        
        # Create database record
        scan_record = ScanHistory(
            scan_id=scan_data.get("scan_id"),
            target=scan_data.get("target"),
            target_type=scan_data.get("type", "unknown"),
            target_name=scan_data.get("target", ""),
            threat_level=scan_data.get("threat_level"),
            confidence=scan_data.get("confidence", 0.0),
            threats_detected=scan_data.get("threats_detected", 0),
            analysis_data={
                "verdict": scan_data.get("verdict"),
                "summary": scan_data.get("summary"),
                "api_results": scan_data.get("api_results", {}),
                "threat_indicators": scan_data.get("threat_indicators", []),
                "forensic_metadata": forensic,
            },
            evidence_sources=evidence_sources,
            corroboration_count=corroboration_count,
        )
        
        db.add(scan_record)
        await db.commit()
        await db.refresh(scan_record)
        
        logger.info(f"Scan {scan_data.get('scan_id')} saved to database successfully")
        
    except Exception as e:
        logger.error(f"Failed to save scan to database: {e}")
        logger.exception(e)  # Full traceback
        await db.rollback()


class GenericScanRequest(BaseModel):
    type: str
    target: str


# Add OPTIONS handlers for CORS preflight requests
@router.options("/scan")
async def options_scan():
    """Handle CORS preflight for /scan endpoint."""
    return {}


@router.options("/scan/file")
async def options_scan_file():
    """Handle CORS preflight for /scan/file endpoint."""
    return {}


@router.options("/scans")
async def options_scans():
    """Handle CORS preflight for /scans endpoint."""
    return {}


@router.options("/dashboard/stats")
async def options_dashboard_stats():
    """Handle CORS preflight for /dashboard/stats endpoint."""
    return {}


@router.options("/dashboard/summary")
async def options_dashboard_summary():
    """Handle CORS preflight for /dashboard/summary endpoint."""
    return {}


@router.options("/threats")
async def options_threats():
    """Handle CORS preflight for /threats endpoint."""
    return {}


@router.options("/reports")
async def options_reports():
    """Handle CORS preflight for /reports endpoint."""
    return {}


@router.options("/reports/generate")
async def options_reports_generate():
    """Handle CORS preflight for /reports/generate endpoint."""
    return {}

@router.options("/scans/{scan_id}")
async def options_scan_detail():
    """Handle CORS preflight for /scans/{scan_id} endpoint."""
    return {}


@router.options("/reports/{report_id}")
async def options_report_detail():
    """Handle CORS preflight for /reports/{report_id} endpoint."""
    return {}


@router.options("/reports/{report_id}/download")
async def options_report_download():
    """Handle CORS preflight for /reports/{report_id}/download endpoint."""
    return {}

@router.post("/scan")
async def generic_scan(req: GenericScanRequest, db: AsyncSession = Depends(get_db)):
    """Compatibility endpoint: accepts {type, target} and returns a scan result.

    Uses real threat analyzer with VirusTotal, Shodan, URLScan, AbuseIPDB, 
    and Hybrid Analysis to provide actual threat detection.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    scan_id = f"GEN_{int(datetime.utcnow().timestamp())}_{random.randint(1000, 9999)}"
    logger.info(f"Starting scan: {scan_id} - type: {req.type}, target: {req.target}")
    
    try:
        # Perform real threat analysis using all 5 APIs
        analysis_result = await threat_analyzer.analyze(req.target)
        logger.info(f"Analysis complete for {scan_id}: verdict={analysis_result.get('verdict')}")
        
        # Map analyzer verdict to threat_level
        verdict = analysis_result.get("verdict", "unknown")
        threat_level_map = {
            "clean": "safe",
            "suspicious": "suspicious",
            "malicious": "malicious"
        }
        threat_level = threat_level_map.get(verdict, "unknown")
        
        # Count detected threats
        threats_detected = len(analysis_result.get("threat_indicators", []))
        
        # Build scan result with real data
        result = {
            "scan_id": scan_id,
            "target": req.target,
            "type": analysis_result.get("input_type", req.type),
            "status": "complete",
            "threat_level": threat_level,
            "threats_detected": threats_detected,
            "verdict": verdict,
            "confidence": analysis_result.get("confidence", 0.0),
            "summary": analysis_result.get("summary", "Analysis complete"),
            "timestamp": datetime.utcnow().isoformat(),
            # Include API results for detailed view
            "api_results": analysis_result.get("api_results", {}),
            "threat_indicators": analysis_result.get("threat_indicators", []),
            # Include forensic reliability metadata
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
            # Include AI-enhanced analysis
            "ai_analysis": analysis_result.get("ai_analysis", {}),
            "ai_verdict_adjustment": analysis_result.get("ai_verdict_adjustment"),
        }
        logger.info(f"Scan result created: {scan_id} - {threat_level}")
    except Exception as e:
        # Fallback if analysis fails
        logger.error(f"Scan {scan_id} failed: {str(e)}")
        result = {
            "scan_id": scan_id,
            "target": req.target,
            "type": req.type,
            "status": "error",
            "threat_level": "unknown",
            "threats_detected": 0,
            "verdict": "error",
            "confidence": 0.0,
            "summary": f"Analysis failed: {str(e)}",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e),
        }

    # prepend to store (most recent first)
    SCANS_STORE.insert(0, result)
    logger.info(f"Scan {scan_id} stored. Total scans in store: {len(SCANS_STORE)}")
    # trim store
    if len(SCANS_STORE) > MAX_STORE:
        SCANS_STORE.pop()
    
    # Save to database for time-range reports
    await _save_scan_to_db(result, db)

    return result


@router.post("/scan/file")
async def scan_file(file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    """File upload scan endpoint. Computes hash and analyzes with real threat APIs."""
    scan_id = f"GEN_{int(datetime.utcnow().timestamp())}_{random.randint(1000, 9999)}"
    filename = file.filename or "unknown"

    try:
        # Read file content and compute hash
        content = await file.read()
        file_size = len(content)
        
        # Compute SHA256 hash
        file_hash = hashlib.sha256(content).hexdigest()
        
        # Perform real threat analysis on file hash
        analysis_result = await threat_analyzer.analyze(file_hash)
        
        # Map analyzer verdict to threat_level
        verdict = analysis_result.get("verdict", "unknown")
        threat_level_map = {
            "clean": "safe",
            "suspicious": "suspicious",
            "malicious": "malicious"
        }
        threat_level = threat_level_map.get(verdict, "unknown")
        
        # Count detected threats
        threats_detected = len(analysis_result.get("threat_indicators", []))
        
        result = {
            "scan_id": scan_id,
            "target": filename,
            "type": "file",
            "file_size": file_size,
            "file_hash": file_hash,
            "status": "complete",
            "threat_level": threat_level,
            "threats_detected": threats_detected,
            "verdict": verdict,
            "confidence": analysis_result.get("confidence", 0.0),
            "summary": analysis_result.get("summary", "File analysis complete"),
            "timestamp": datetime.utcnow().isoformat(),
            # Include API results
            "api_results": analysis_result.get("api_results", {}),
            "threat_indicators": analysis_result.get("threat_indicators", []),
            # Include forensic reliability metadata
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
        }
    except Exception as e:
        result = {
            "scan_id": scan_id,
            "target": filename,
            "type": "file",
            "file_size": 0,
            "status": "error",
            "threat_level": "unknown",
            "threats_detected": 0,
            "verdict": "error",
            "summary": f"File analysis failed: {str(e)}",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e),
        }

    # prepend to store (most recent first)
    SCANS_STORE.insert(0, result)
    # trim store
    if len(SCANS_STORE) > MAX_STORE:
        SCANS_STORE.pop()
    
    # Save to database for time-range reports
    await _save_scan_to_db(result, db)

    return result


@router.get("/scans")
async def list_scans():
    """Return recent scans from in-memory store."""
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"GET /scans - returning {len(SCANS_STORE)} scans")
    return SCANS_STORE


@router.get("/scans/{scan_id}")
async def get_scan_detail(scan_id: str):
    """Get detailed information about a specific scan."""
    for scan in SCANS_STORE:
        if scan.get("scan_id") == scan_id:
            return scan
    raise HTTPException(status_code=404, detail="Scan not found")


@router.get("/dashboard/stats")
async def get_dashboard_stats():
    """Get dashboard statistics (compatibility endpoint)."""
    return {
        "critical_threats": 2,
        "medium_threats": 5,
        "low_threats": 1,
        "files_scanned": 156,
        "urls_scanned": 23,
        "ips_scanned": 12,
    }


@router.get("/dashboard/summary")
async def get_dashboard_summary():
    """Get dashboard summary with recent activity."""
    return {
        "total_scans": 156,
        "threats_detected": 8,
        "last_scan": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
        "system_status": "healthy",
    }


@router.get("/threats")
async def get_threats():
    """Get all detected threats (compatibility endpoint)."""
    return [
        {
            "id": 1,
            "name": "Suspicious Process Activity",
            "details": "Process_monitor.exe attempting network connection",
            "severity": "critical",
            "timestamp": (datetime.utcnow() - timedelta(hours=1)).isoformat(),
            "status": "active",
        },
        {
            "id": 2,
            "name": "Malware Signature Detected",
            "details": "file_download.exe matches known malware pattern",
            "severity": "critical",
            "timestamp": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
            "status": "active",
        },
        {
            "id": 3,
            "name": "Suspicious URL Access",
            "details": "Attempted access to known phishing domain",
            "severity": "medium",
            "timestamp": (datetime.utcnow() - timedelta(hours=3)).isoformat(),
            "status": "resolved",
        },
    ]


@router.get("/reports")
async def list_reports():
    """Return all generated reports from store."""
    # Return reports in reverse chronological order (newest first)
    return list(reversed(REPORTS_STORE)) if REPORTS_STORE else []


class ReportRequest(BaseModel):
    target: str | None = None
    type: str | None = None
    timeRange: str | None = None


@router.post("/reports/generate")
async def generate_report(req: ReportRequest):
    """Generate an AI report (PDF) for a target using the Gemini-backed report generator.

    If the Gemini API key is not configured, return a clear 400 error so the frontend
    can display a helpful message.
    """
    # Check Gemini key
    if not getattr(settings, "GEMINI_API_KEY", None):
        raise HTTPException(
            status_code=400,
            detail="Unable to generate report: gemini api key is not given",
        )

    # Generate unique report ID
    now = datetime.utcnow()
    report_id = f"RPT_{int(now.timestamp())}_{random.randint(1000, 9999)}"
    
    target = req.target or "unknown"
    scan_type = req.type or "unknown"
    time_range = req.timeRange or "24h"
    
    # Get the most recent scan for this target from SCANS_STORE to use its full analysis
    target_scans = [s for s in SCANS_STORE if target in s.get("target", "")]
    
    # If we have a recent scan with full analysis data, use it
    if target_scans:
        # Use the most recent scan with complete data
        latest_scan = target_scans[-1]
        
        # If scan has api_results and threat_indicators, use them directly
        if "api_results" in latest_scan and "threat_indicators" in latest_scan:
            threat_analysis = {
                "input": target,
                "input_type": latest_scan.get("type", scan_type),
                "verdict": latest_scan.get("verdict", "unknown"),
                "confidence": latest_scan.get("confidence", 0.5),
                "threat_indicators": latest_scan.get("threat_indicators", []),
                "api_results": latest_scan.get("api_results", {}),
                "timestamp": now.isoformat(),
                "report_id": report_id,
                "summary": latest_scan.get("summary", ""),
                "threats_detected": latest_scan.get("threats_detected", 0),
                "forensic_metadata": latest_scan.get("forensic_metadata", {}),
                "scan_id": latest_scan.get("scan_id", ""),
                "threat_level": latest_scan.get("threat_level", "unknown"),
                "status": latest_scan.get("status", "complete"),
            }
        else:
            # Fallback: perform fresh analysis
            threat_analysis = await threat_analyzer.analyze(target)
            threat_analysis["report_id"] = report_id
    else:
        # No recent scans - perform fresh analysis
        threat_analysis = await threat_analyzer.analyze(target)
        threat_analysis["report_id"] = report_id

    # Generate PDF bytes with full analysis data
    pdf_bytes = await report_generator.generate_analysis_report(threat_analysis)

    if not pdf_bytes:
        raise HTTPException(status_code=500, detail="Report generation failed")

    # Store report metadata using actual analysis data
    report_meta = {
        "report_id": report_id,
        "title": f"Threat Analysis - {target}",
        "target": target,
        "type": threat_analysis.get("input_type", scan_type),
        "time_range": time_range,
        "threats_detected": threat_analysis.get("threats_detected", len(threat_analysis.get("threat_indicators", []))),
        "verdict": threat_analysis.get("verdict", "unknown"),
        "confidence": threat_analysis.get("confidence", 0.5),
        "created": now.isoformat(),
    }
    REPORTS_STORE.append(report_meta)
    
    # Cache PDF for later retrieval
    REPORTS_PDF_CACHE[report_id] = pdf_bytes
    
    # Trim old cache (keep last 50 reports)
    if len(REPORTS_PDF_CACHE) > 50:
        # Remove oldest entries
        sorted_ids = sorted(REPORTS_PDF_CACHE.keys())
        for old_id in sorted_ids[:-50]:
            del REPORTS_PDF_CACHE[old_id]

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={target}_report_{report_id}.pdf"},
    )

@router.get("/reports/{report_id}")
async def get_report(report_id: str):
    """Get report metadata by ID."""
    for report in REPORTS_STORE:
        if report.get("report_id") == report_id:
            return report
    raise HTTPException(status_code=404, detail="Report not found")


@router.get("/reports/{report_id}/download")
async def download_report(report_id: str):
    """Download a specific report PDF by ID."""
    # Check if report exists in cache
    if report_id not in REPORTS_PDF_CACHE:
        raise HTTPException(status_code=404, detail="Report not found or expired")
    
    pdf_bytes = REPORTS_PDF_CACHE[report_id]
    
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={report_id}.pdf"},
    )