import random
from datetime import datetime, timedelta
from io import BytesIO

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from ..config import settings
from ..core.report_generator import report_generator

router = APIRouter()

# In-memory scan store for compatibility (ephemeral)
SCANS_STORE: list[dict] = []
MAX_STORE = 100


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


@router.post("/scan")
async def generic_scan(req: GenericScanRequest):
    """Compatibility endpoint: accepts {type, target} and returns a scan result.

    Also persists the result in an in-memory list so the `/scans` endpoint
    returns recent scans for the frontend Scans page.
    """
    scan_id = f"GEN_{int(datetime.utcnow().timestamp())}_{random.randint(1000, 9999)}"
    # Simple heuristic response mimicking existing scan endpoints
    if req.type.lower() in ("url", "domain"):
        status = "complete"
        threat_level = "safe"
        threats_detected = 0
    else:
        status = "queued"
        threat_level = "unknown"
        threats_detected = 0

    result = {
        "scan_id": scan_id,
        "target": req.target,
        "type": req.type,
        "status": status,
        "threat_level": threat_level,
        "threats_detected": threats_detected,
        "timestamp": datetime.utcnow().isoformat(),
    }

    # prepend to store (most recent first)
    SCANS_STORE.insert(0, result)
    # trim store
    if len(SCANS_STORE) > MAX_STORE:
        SCANS_STORE.pop()

    return result


@router.post("/scan/file")
async def scan_file(file: UploadFile = File(...)):
    """File upload scan endpoint. Accepts a file and returns a scan result."""
    scan_id = f"GEN_{int(datetime.utcnow().timestamp())}_{random.randint(1000, 9999)}"
    filename = file.filename or "unknown"

    # Read file content (for demo, just read filename; real implementation would analyze)
    file_size = 0
    try:
        content = await file.read()
        file_size = len(content)
    except Exception:
        pass

    # Mock analysis: check file extension for threat simulation
    threat_level = "safe"
    threats_detected = 0
    if any(
        ext in filename.lower()
        for ext in [".exe", ".dll", ".bat", ".cmd", ".scr", ".vbs"]
    ):
        threat_level = "suspicious"
        threats_detected = 1

    result = {
        "scan_id": scan_id,
        "target": filename,
        "type": "file",
        "file_size": file_size,
        "status": "complete",
        "threat_level": threat_level,
        "threats_detected": threats_detected,
        "timestamp": datetime.utcnow().isoformat(),
    }

    # prepend to store (most recent first)
    SCANS_STORE.insert(0, result)
    # trim store
    if len(SCANS_STORE) > MAX_STORE:
        SCANS_STORE.pop()

    return result


@router.get("/scans")
async def list_scans():
    """Return recent scans from in-memory store."""
    return SCANS_STORE


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
    """Return mock reports list."""
    now = datetime.utcnow()
    return [
        {
            "report_id": f"RPT_{int(now.timestamp()) - i}",
            "title": "Threat Analysis",
            "created": (now.isoformat()),
        }
        for i in range(3)
    ]


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

    # Build a minimal threat_analysis payload for the report generator
    target = req.target or "unknown"
    threat_analysis = {
        "input": target,
        "input_type": req.type or "unknown",
        "verdict": "unknown",
        "confidence": 0.0,
        "threat_indicators": [],
        "api_results": {"apis_called": []},
        "timestamp": datetime.utcnow().isoformat(),
    }

    # Generate PDF bytes
    pdf_bytes = await report_generator.generate_analysis_report(threat_analysis)

    if not pdf_bytes:
        raise HTTPException(status_code=500, detail="Report generation failed")

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=sentinel_report.pdf"},
    )
