import random
import hashlib
import os
import json
import logging
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, HTTPException, UploadFile, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from ..config import settings
from ..core.report_generator import report_generator
from ..core.threat_analyzer import threat_analyzer
from ..database import get_db
from ..models import AttackEvent, ScanHistory, SystemLog

router = APIRouter()
logger = logging.getLogger(__name__)

GENERATED_REPORTS_DIR = Path(__file__).resolve().parents[2] / "generated_reports"
REPORTS_INDEX_FILE = GENERATED_REPORTS_DIR / "reports_index.json"


def _load_persistent_reports() -> list[dict]:
    try:
        if not REPORTS_INDEX_FILE.exists():
            return []
        with REPORTS_INDEX_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        return []
    except Exception as e:
        logger.warning(f"Failed to load reports index: {e}")
        return []


def _save_persistent_reports() -> None:
    try:
        GENERATED_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        with REPORTS_INDEX_FILE.open("w", encoding="utf-8") as f:
            json.dump(REPORTS_STORE, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.warning(f"Failed to save reports index: {e}")


def store_report_artifacts(report_meta: dict, pdf_bytes: bytes) -> None:
    """Persist report metadata + PDF to memory and disk."""
    report_id = report_meta.get("report_id")
    if not report_id:
        return

    GENERATED_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_file = GENERATED_REPORTS_DIR / f"{report_id}.pdf"
    report_file.write_bytes(pdf_bytes)

    report_meta = {**report_meta, "report_path": str(report_file)}

    # upsert by report_id
    existing_idx = next((i for i, r in enumerate(REPORTS_STORE) if r.get("report_id") == report_id), None)
    if existing_idx is None:
        REPORTS_STORE.append(report_meta)
    else:
        REPORTS_STORE[existing_idx] = report_meta

    REPORTS_PDF_CACHE[report_id] = pdf_bytes

    # keep only latest N report metadata
    if len(REPORTS_STORE) > 500:
        del REPORTS_STORE[:-500]

    # keep only latest N in-memory PDFs
    if len(REPORTS_PDF_CACHE) > 100:
        oldest_ids = sorted(REPORTS_PDF_CACHE.keys())[:-100]
        for old_id in oldest_ids:
            REPORTS_PDF_CACHE.pop(old_id, None)

    _save_persistent_reports()

# In-memory scan store for compatibility (ephemeral)
SCANS_STORE: list[dict] = []
MAX_STORE = 100

# In-memory reports store
REPORTS_STORE: list[dict] = _load_persistent_reports()
# Report PDF cache (report_id -> pdf_bytes)
REPORTS_PDF_CACHE: dict[str, bytes] = {}


def _is_low_signal_suspicious_ip_scan(scan: ScanHistory) -> bool:
    """Return True for low-confidence single-source suspicious IP scans."""
    level = str(scan.threat_level or "unknown").lower()
    target_type = str(scan.target_type or "unknown").lower()
    if level != "suspicious" or target_type != "ip":
        return False

    try:
        confidence = float(scan.confidence or 0.0)
    except Exception:
        confidence = 0.0

    analysis = scan.analysis_data or {}
    indicators = analysis.get("threat_indicators") or []
    warnings = analysis.get("warnings") or []
    corroboration_count = int(scan.corroboration_count or 0)
    summary_blob = " ".join([
        str(analysis.get("summary", "") or ""),
        " ".join(str(w) for w in warnings),
        " ".join(str(r) for r in (analysis.get("recommendations") or [])),
    ]).lower()

    return (
        confidence < 0.5
        and len(indicators) <= 1
        and len(warnings) <= 1
        and corroboration_count <= 1
        and (
            "single source" in summary_blob
            or "limited corroboration" in summary_blob
            or "minor threat indicators" in summary_blob
        )
    )


async def _save_scan_to_db(scan_data: dict, db: AsyncSession):
    """Save scan result to database for historical reporting"""
    import logging
    logger = logging.getLogger(__name__)

    if os.getenv("PYTEST_CURRENT_TEST"):
        logger.debug("Skipping database persistence for pytest-generated compatibility scan")
        return
    
    try:
        # Extract forensic metadata
        forensic = scan_data.get("forensic_metadata", {})
        evidence_sources = forensic.get("evidence_sources", [])
        corroboration_count = forensic.get("corroboration_count", 0)
        
        logger.debug(f"Saving scan {scan_data.get('scan_id')} - Forensic: count={corroboration_count}, sources={evidence_sources}")
        logger.debug(f"Scan type: {scan_data.get('type')}, confidence: {scan_data.get('confidence')}, threats: {scan_data.get('threats_detected')}")
        
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
        
        # Log to system logs
        log_entry = SystemLog(
            log_level="INFO",
            component="scanner",
            message=f"Scan completed: {scan_data.get('scan_id')} - {scan_data.get('target')}",
            details={
                "scan_id": scan_data.get("scan_id"),
                "target": scan_data.get("target"),
                "threat_level": scan_data.get("threat_level"),
                "target_type": scan_data.get("type"),
                "threats_detected": scan_data.get("threats_detected", 0),
                "confidence": scan_data.get("confidence", 0.0),
            },
        )
        db.add(log_entry)
        await db.commit()

        logger.debug(f"Scan {scan_data.get('scan_id')} saved to database successfully")
        
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
    import time
    logger = logging.getLogger(__name__)
    
    scan_id = f"GEN_{int(datetime.utcnow().timestamp())}_{random.randint(1000, 9999)}"
    logger.debug(f"SCAN {scan_id} started | type={req.type} | target={req.target}")
    
    # Track scan duration
    scan_start_time = time.time()
    
    try:
        # Perform real threat analysis using all 5 APIs
        analysis_result = await threat_analyzer.analyze(req.target)
        scan_duration_ms = int((time.time() - scan_start_time) * 1000)
        
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
        if threat_level in {"malicious", "critical"} or threats_detected > 1:
            logger.info(f"SCAN {scan_id} | lvl={threat_level} | ind={threats_detected}")
        else:
            logger.debug(f"SCAN {scan_id} | lvl={threat_level} | ind={threats_detected}")
    except Exception as e:
        # Fallback if analysis fails
        logger.error(f"SCAN {scan_id} failed | {str(e)}")
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

    if not os.getenv("PYTEST_CURRENT_TEST"):
        # prepend to store (most recent first)
        SCANS_STORE.insert(0, result)
        logger.debug(f"Scan {scan_id} stored. Total scans in store: {len(SCANS_STORE)}")
        # trim store
        if len(SCANS_STORE) > MAX_STORE:
            SCANS_STORE.pop()
        
        # Save to database for time-range reports
        await _save_scan_to_db(result, db)
    else:
        logger.debug(f"Skipping in-memory/database storage for pytest-generated scan {scan_id}")
    
    # Log to enhanced activity database with full details
    try:
        from app.core.activity_database import activity_db
        from app.core.terminal_monitor import terminal_monitor
        
        artifact_type = analysis_result.get('input_type', req.type) if 'analysis_result' in locals() else req.type
        corroboration = analysis_result.get('corroboration_analysis', {}) if 'analysis_result' in locals() else {}
        
        # Log comprehensive scan details to activity database
        activity_db.log_threat_scan({
            'artifact_type': artifact_type,
            'artifact_value': req.target,
            'scan_duration_ms': scan_duration_ms if 'scan_duration_ms' in locals() else 0,
            'verdict': verdict,
            'confidence': result.get('confidence', 0.0),
            'threat_level': threat_level,
            'corroboration_level': corroboration.get('corroboration', {}).get('level'),
            'source_count': corroboration.get('corroboration', {}).get('source_count', 0),
            'sources': corroboration.get('corroboration', {}).get('sources', []),
            'api_results': result.get('api_results'),
            'threat_indicators': result.get('threat_indicators', []),
            'recommendations': analysis_result.get('recommendations', []) if 'analysis_result' in locals() else [],
            'flags': analysis_result.get('flags', {}) if 'analysis_result' in locals() else {},
            'is_automated': req.metadata.get('automated', False) if hasattr(req, 'metadata') and req.metadata else False,
            'metadata': req.metadata if hasattr(req, 'metadata') else {}
        })

        try:
            confidence_value = float(result.get('confidence', 0.0) or 0.0)
        except Exception:
            confidence_value = 0.0
        warnings_list = result.get('warnings') or []
        indicators_list = result.get('threat_indicators') or []
        summary_blob = " ".join([
            str(result.get('summary', '') or ''),
            " ".join(str(w) for w in warnings_list),
            " ".join(str(r) for r in (result.get('recommendations') or [])),
        ]).lower()
        low_signal_suspicious_ip = (
            artifact_type == 'ip'
            and str(verdict).lower() == 'suspicious'
            and confidence_value < 0.5
            and len(indicators_list) <= 1
            and len(warnings_list) <= 1
            and 'single source' in summary_blob
        )
        
        # Update terminal monitor for real-time display
        if not low_signal_suspicious_ip:
            terminal_monitor.log_scan_activity(artifact_type, req.target, verdict)
        
        # Log additional activity based on type
        if artifact_type == 'url' or artifact_type == 'domain':
            terminal_monitor.log_website_activity(req.target, threat_level.upper())
        
    except Exception as e:
        logger.error(f"Failed to log to enhanced monitoring: {e}")

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
async def list_scans(source: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    """Return recent scans from database (fallback to memory).

    Defaults to operator-triggered manual scans only so automated client-side
    protection hash checks do not flood the dashboard history.
    Pass source=all to include every scan source.
    """
    query = select(ScanHistory).order_by(desc(ScanHistory.scan_timestamp)).limit(100)
    if source != "all":
        query = query.where(ScanHistory.scan_source == "manual")

    result = await db.execute(query)
    scans = result.scalars().all()
    if scans:
        return [
            {
                "scan_id": s.scan_id,
                "target": s.target,
                "type": s.target_type,
                "source": s.scan_source or "manual",
                "status": "complete",
                "threat_level": s.threat_level or "unknown",
                "verdict": (s.analysis_data or {}).get("verdict"),
                "timestamp": s.scan_timestamp.isoformat() if s.scan_timestamp else None,
            }
            for s in scans
        ]

    if source != "all":
        return [s for s in SCANS_STORE if s.get("scan_source", "manual") == "manual"]
    return SCANS_STORE


@router.get("/scans/{scan_id}")
async def get_scan_detail(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get detailed information about a specific scan."""
    result = await db.execute(select(ScanHistory).where(ScanHistory.scan_id == scan_id))
    scan = result.scalar_one_or_none()
    if scan:
        analysis = scan.analysis_data or {}
        return {
            "scan_id": scan.scan_id,
            "target": scan.target,
            "type": scan.target_type,
            "status": "complete",
            "threat_level": scan.threat_level,
            "verdict": analysis.get("verdict"),
            "confidence": scan.confidence,
            "threats_detected": scan.threats_detected,
            "timestamp": scan.scan_timestamp.isoformat() if scan.scan_timestamp else None,
            "api_results": analysis.get("api_results", {}),
            "threat_indicators": analysis.get("threat_indicators", []),
            "summary": analysis.get("summary"),
            "forensic_metadata": analysis.get("forensic_metadata", {}),
        }
    for scan in SCANS_STORE:
        if scan.get("scan_id") == scan_id:
            return scan
    raise HTTPException(status_code=404, detail="Scan not found")


@router.get("/dashboard/stats")
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    """Get dashboard statistics (compatibility endpoint)."""
    result = await db.execute(select(ScanHistory).order_by(desc(ScanHistory.scan_timestamp)).limit(1000))
    scans = result.scalars().all()

    stats = {
        "critical_threats": 0,
        "high_threats": 0,
        "medium_threats": 0,
        "low_threats": 0,
        "files_scanned": 0,
        "urls_scanned": 0,
        "ips_scanned": 0,
        "total_scans": len(scans),
        "active_threats": 0,
    }

    for scan in scans:
        level = (scan.threat_level or "unknown").lower()
        if level in ["malicious", "critical"]:
            stats["critical_threats"] += 1
        elif level in ["suspicious", "high"]:
            stats["high_threats"] += 1
        elif level in ["safe", "clean", "low"]:
            stats["low_threats"] += 1
        else:
            stats["medium_threats"] += 1

        t = (scan.target_type or "").lower()
        if t in ["file", "hash"]:
            stats["files_scanned"] += 1
        elif t in ["url", "domain"]:
            stats["urls_scanned"] += 1
        elif t == "ip":
            stats["ips_scanned"] += 1

        if level in ["malicious", "critical", "suspicious", "high"]:
            stats["active_threats"] += 1

    return stats


@router.get("/dashboard/summary")
async def get_dashboard_summary(db: AsyncSession = Depends(get_db)):
    """Get dashboard summary with recent activity."""
    result = await db.execute(select(ScanHistory).order_by(desc(ScanHistory.scan_timestamp)).limit(1))
    last_scan = result.scalar_one_or_none()

    result_all = await db.execute(select(ScanHistory))
    scans = result_all.scalars().all()
    threats = [s for s in scans if (s.threat_level or "").lower() in ["malicious", "critical", "suspicious", "high"]]

    return {
        "total_scans": len(scans),
        "threats_detected": len(threats),
        "last_scan": last_scan.scan_timestamp.isoformat() if last_scan else None,
        "system_status": "healthy",
    }


@router.get("/threats")
async def get_threats(db: AsyncSession = Depends(get_db)):
    """Get all detected threats (compatibility endpoint).

    Combines scan-based findings and IDS attack events so the dashboard can
    show intrusion attempts (nmap/brute-force/metasploit-like patterns) with
    concise description and mitigation hints.
    """
    scan_result = await db.execute(select(ScanHistory).order_by(desc(ScanHistory.scan_timestamp)).limit(100))
    scans = scan_result.scalars().all()

    attack_result = await db.execute(select(AttackEvent).order_by(desc(AttackEvent.detected_at)).limit(100))
    attacks = attack_result.scalars().all()

    def _icon_for(threat_type: str) -> str:
        lowered = str(threat_type or "").lower()
        if "brute" in lowered:
            return "🔐"
        if "metasploit" in lowered or "exploit" in lowered:
            return "💥"
        if "scan" in lowered or "nmap" in lowered or "recon" in lowered:
            return "🛰️"
        if "flood" in lowered or "ddos" in lowered:
            return "🌊"
        return "🚨"

    threats = []

    # Scan-history threats
    for scan in scans:
        level = (scan.threat_level or "unknown").lower()
        if level in ["safe", "clean", "unknown"]:
            continue
        if _is_low_signal_suspicious_ip_scan(scan):
            continue

        severity = "critical" if level in ["malicious", "critical"] else "high" if level in ["suspicious", "high"] else "medium"
        analysis = scan.analysis_data or {}
        summary = analysis.get("summary") or "Threat detected"
        target = scan.target or scan.target_name or "unknown"
        type_label = f"{(scan.target_type or 'scan').lower()}_threat"

        threats.append({
            "id": scan.scan_id,
            "scan_id": scan.scan_id,
            "name": f"{(scan.target_type or 'unknown').upper()} Threat",
            "type": type_label,
            "icon": _icon_for(type_label),
            "target": target,
            "details": summary,
            "description": summary,
            "short_description": summary[:140],
            "severity": severity,
            "confidence": scan.confidence,
            "corroboration_count": scan.corroboration_count or 0,
            "target_type": scan.target_type,
            "source": "Multi-API Scan",
            "location": "Endpoint Scan Pipeline",
            "timestamp": scan.scan_timestamp.isoformat() if scan.scan_timestamp else None,
            "status": "active",
        })

    # IDS/defense attack events
    for attack in attacks:
        indicators = attack.indicators if isinstance(attack.indicators, dict) else {}
        short_desc = indicators.get("short_description") or attack.description or "Intrusion attempt detected"
        mitigation_commands = indicators.get("mitigation_commands")
        if not isinstance(mitigation_commands, list):
            mitigation_commands = []

        severity = (attack.severity.value if attack.severity else "medium").lower()
        target = attack.source_ip or attack.source_domain or attack.destination_ip or "unknown"
        source_hostname = indicators.get("source_hostname") or attack.source_domain
        target_display = f"{attack.source_ip} ({source_hostname})" if attack.source_ip and source_hostname else target
        type_label = str(attack.attack_type or "intrusion").lower()

        threats.append({
            "id": attack.event_id,
            "event_id": attack.event_id,
            "name": f"Attack Event: {attack.attack_type}",
            "type": type_label,
            "icon": _icon_for(type_label),
            "target": target,
            "target_display": target_display,
            "source_hostname": source_hostname,
            "details": attack.description or short_desc,
            "description": attack.description or short_desc,
            "short_description": short_desc,
            "severity": severity,
            "source": indicators.get("tool_signature") or "Intrusion Detector",
            "location": "Network Intrusion Monitoring",
            "timestamp": attack.detected_at.isoformat() if attack.detected_at else None,
            "status": attack.status or "active",
            "mitigation_commands": mitigation_commands,
            "recommended_action": indicators.get("recommended_action"),
            "attack_family": indicators.get("attack_family"),
            "tool_signature": indicators.get("tool_signature"),
            "prediction_summary": indicators.get("prediction_summary"),
            "predicted_next_step": indicators.get("predicted_next_step"),
            "prediction_confidence": indicators.get("prediction_confidence"),
        })

    threats.sort(key=lambda t: t.get("timestamp") or "", reverse=True)
    return threats[:200]


@router.get("/logs")
async def get_logs(db: AsyncSession = Depends(get_db)):
    """Return recent system logs for dashboard."""
    result = await db.execute(select(SystemLog).order_by(desc(SystemLog.timestamp)).limit(50))
    logs = result.scalars().all()
    return [
        {
            "level": log.log_level,
            "component": log.component,
            "message": log.message,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
        }
        for log in logs
    ]


@router.get("/dashboard/api-status")
async def get_api_status():
    """Return API configuration status for dashboard (compat)."""
    return [
        {
            "name": "VirusTotal",
            "key_configured": bool(settings.VIRUSTOTAL_API_KEY),
            "enabled": bool(settings.VIRUSTOTAL_API_KEY),
            "status": "ready" if settings.VIRUSTOTAL_API_KEY else "missing_key",
            "supported_inputs": ["url", "domain", "file_hash"],
        },
        {
            "name": "AbuseIPDB",
            "key_configured": bool(settings.ABUSEIPDB_API_KEY),
            "enabled": bool(settings.ABUSEIPDB_API_KEY),
            "status": "ready" if settings.ABUSEIPDB_API_KEY else "missing_key",
            "supported_inputs": ["ip"],
        },
        {
            "name": "Shodan",
            "key_configured": bool(settings.SHODAN_API_KEY),
            "enabled": bool(settings.SHODAN_API_KEY),
            "status": "ready" if settings.SHODAN_API_KEY else "missing_key",
            "supported_inputs": ["ip"],
        },
        {
            "name": "URLScan.io",
            "key_configured": bool(settings.URLSCAN_API_KEY),
            "enabled": bool(settings.URLSCAN_API_KEY),
            "status": "ready" if settings.URLSCAN_API_KEY else "missing_key",
            "supported_inputs": ["url", "domain"],
        },
        {
            "name": "Hybrid Analysis",
            "key_configured": bool(settings.HYBRIDANALYSIS_API_KEY),
            "enabled": bool(settings.HYBRIDANALYSIS_API_KEY),
            "status": "ready" if settings.HYBRIDANALYSIS_API_KEY else "missing_key",
            "supported_inputs": ["file_hash"],
        },
    ]


@router.get("/reports")
async def list_reports():
    """Return all generated reports from store."""
    # refresh from disk if in-memory store is empty (e.g., process started fresh)
    if not REPORTS_STORE:
        REPORTS_STORE.extend(_load_persistent_reports())
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
    store_report_artifacts(report_meta, pdf_bytes)

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
    if report_id in REPORTS_PDF_CACHE:
        pdf_bytes = REPORTS_PDF_CACHE[report_id]
    else:
        # fallback to persisted file path
        report_meta = next((r for r in REPORTS_STORE if r.get("report_id") == report_id), None)
        report_path = report_meta.get("report_path") if report_meta else None
        if not report_path or not Path(report_path).exists():
            raise HTTPException(status_code=404, detail="Report not found or expired")
        pdf_bytes = Path(report_path).read_bytes()
        REPORTS_PDF_CACHE[report_id] = pdf_bytes
    
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={report_id}.pdf"},
    )