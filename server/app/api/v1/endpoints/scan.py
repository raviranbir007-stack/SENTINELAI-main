"""
Threat Scanning Endpoints
Handles threat analysis for IPs, URLs, domains, and file hashes
"""

import hashlib
import logging
import os
import re
from datetime import datetime
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ....core.input_detector import InputDetector
from ....core.report_generator import report_generator
from ....core.threat_analyzer import threat_analyzer
from ....database import get_db
from ....models import ClientInstallation, ScanHistory, SystemLog

logger = logging.getLogger(__name__)
router = APIRouter()

# In-memory scan history (in production, use database)
_scan_history = []

# Compiled regex patterns for input validation
_RE_HASH   = re.compile(r'^[a-fA-F0-9]{32,64}$')
_RE_IP     = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})$'
)
_RE_DOMAIN = re.compile(r'^[a-zA-Z0-9\-\.]{1,253}$')
_ALLOWED_SCAN_SOURCES = {"manual", "client_protection", "background", "scheduled"}


def _generate_scan_id(prefix: str) -> str:
    """Generate a collision-resistant scan ID suitable for DB unique constraints."""
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    return f"{prefix}_{ts}_{uuid4().hex[:8]}"


def _validate_target(target: str, max_len: int = 2048) -> str:
    """Sanitise and basic-validate a scan target string."""
    target = target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target must not be empty")
    if len(target) > max_len:
        raise HTTPException(status_code=400, detail=f"Target exceeds maximum length ({max_len})")
    # Reject obvious shell-injection attempts
    for bad in (";", "&&", "||", "`", "$(",):
        if bad in target:
            raise HTTPException(status_code=400, detail="Invalid characters in target")
    return target


def _normalize_scan_source(scan_source: Optional[str]) -> str:
    """Normalize request scan source to a supported value."""
    if not scan_source:
        return "manual"
    value = scan_source.strip().lower()
    if value not in _ALLOWED_SCAN_SOURCES:
        return "manual"
    return value


def _log_scan_completion(scan_id: str, scan_type: str, result: dict) -> None:
    """Emit concise scan completion logs and suppress benign INFO noise."""
    level = str(result.get("threat_level", "unknown")).lower()
    indicators = int(result.get("threats_detected", 0) or 0)
    message = f"SCAN {scan_id} | type={scan_type} | lvl={level} | ind={indicators}"
    if level in {"suspicious", "malicious", "critical"} or indicators > 0:
        logger.info(message)
    else:
        logger.debug(message)


class ThreatScanRequest(BaseModel):
    """Request model for threat scanning"""

    target: str
    include_report: bool = False
    include_external_apis: Optional[bool] = None  # None -> settings.EXTERNAL_APIS_ENABLED
    client_id: Optional[str] = None  # Optional client ID for tracking
    scan_source: Optional[str] = None  # manual | client_protection | background | scheduled

    @field_validator("target")
    @classmethod
    def target_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target must not be empty")
        if len(v) > 2048:
            raise ValueError("target exceeds maximum length of 2048 characters")
        return v

    @field_validator("scan_source")
    @classmethod
    def validate_scan_source(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        value = v.strip().lower()
        if value not in _ALLOWED_SCAN_SOURCES:
            raise ValueError("scan_source must be one of: manual, client_protection, background, scheduled")
        return value


class ScanResponse(BaseModel):
    """Response model for scan results"""

    scan_id: str
    target: str
    threat_level: str
    confidence: float
    threats_detected: int
    api_results: dict
    timestamp: str


# CORS preflight handlers
@router.options("/file")
async def options_scan_file():
    """Handle CORS preflight for /file endpoint."""
    return {}


@router.options("/url")
async def options_scan_url():
    """Handle CORS preflight for /url endpoint."""
    return {}


@router.options("/ip")
async def options_scan_ip():
    """Handle CORS preflight for /ip endpoint."""
    return {}


@router.options("/hash")
async def options_scan_hash():
    """Handle CORS preflight for /hash endpoint."""
    return {}


@router.options("/scan")
async def options_universal_scan():
    """Handle CORS preflight for /scan endpoint."""
    return {}


async def _store_scan_result(scan_data: dict, db: AsyncSession):
    """Store scan result in history and database"""
    global _scan_history

    if os.getenv("PYTEST_CURRENT_TEST"):
        logger.debug(f"Skipping scan persistence for pytest-generated scan {scan_data.get('scan_id')}")
        return

    _scan_history.insert(0, scan_data)  # Add to front
    # Keep only last 100 scans
    if len(_scan_history) > 100:
        _scan_history = _scan_history[:100]
    
    # Store in database (retry once if scan_id collides)
    try:
        client_id_fk = None
        if scan_data.get("client_id"):
            query = select(ClientInstallation).where(ClientInstallation.client_id == scan_data["client_id"])
            result = await db.execute(query)
            client = result.scalar_one_or_none()
            if client:
                client_id_fk = client.id

        current_scan_id = scan_data["scan_id"]
        id_prefix = current_scan_id.split("_", 1)[0] if "_" in current_scan_id else "SCAN"

        for attempt in range(2):
            try:
                scan_record = ScanHistory(
                    scan_id=current_scan_id,
                    target=scan_data.get("target", scan_data.get("filename", "")),
                    target_type=scan_data.get("target_type", "unknown"),
                    threat_level=scan_data.get("threat_level", "unknown"),
                    confidence=scan_data.get("confidence", 0.0),
                    threats_detected=scan_data.get("threats_detected", 0),
                    analysis_data=scan_data.get("analysis", {}),
                    client_id=client_id_fk,
                    report_generated=scan_data.get("report_url") is not None,
                    # Scan origin: 'manual' = user/API, 'background' = auto-monitor
                    scan_source=scan_data.get("scan_source", "manual"),
                    # Forensic Reliability Fields
                    evidence_sources=scan_data.get("forensic_metadata", {}).get("evidence_sources", []),
                    corroboration_count=scan_data.get("forensic_metadata", {}).get("corroboration_count", 0),
                )

                db.add(scan_record)
                db.add(SystemLog(
                    log_level="INFO",
                    component="scanner",
                    message=f"Scan completed: {current_scan_id} - {scan_data.get('target', '')}",
                    details={
                        "scan_id": current_scan_id,
                        "target": scan_data.get("target", scan_data.get("filename", "")),
                        "threat_level": scan_data.get("threat_level"),
                        "target_type": scan_data.get("target_type"),
                        "threats_detected": scan_data.get("threats_detected", 0),
                        "confidence": scan_data.get("confidence", 0.0),
                    },
                ))
                await db.commit()
                scan_data["scan_id"] = current_scan_id
                logger.debug(f"Scan {current_scan_id} stored in database")
                return
            except IntegrityError as ie:
                await db.rollback()
                if attempt == 0 and "scan_history.scan_id" in str(ie):
                    current_scan_id = _generate_scan_id(id_prefix)
                    logger.warning(
                        "scan_id collision detected; retrying with regenerated id %s",
                        current_scan_id,
                    )
                    continue
                raise
    except Exception as e:
        logger.error(f"Failed to store scan in database: {str(e)}")
        await db.rollback()


@router.get("/history")
async def get_scan_history(
    source: Optional[str] = None,
    limit: int = 100,
):
    """
    Get recent scan history from in-memory cache.
    source=manual (default) | all
    Background auto-monitor scans are NOT stored here — they live in activity_monitoring.db.
    Use GET /api/v1/monitoring/activity for background scan records.
    """
    items = _scan_history
    if source != "all":
        items = [s for s in items if s.get("scan_source", "manual") == "manual"]
    return {
        "total": len(items),
        "source_filter": source or "manual",
        "note": "Background scans are tracked at /api/v1/monitoring/activity",
        "scans": items[:limit],
    }


@router.post("/file")
async def scan_file(
    file: UploadFile = File(...),
    include_report: bool = False,
    include_external_apis: Optional[bool] = None,
    client_id: Optional[str] = None,
    scan_source: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Scan an uploaded file for threats using VirusTotal and Hybrid Analysis

    Args:
        file: File to scan
        include_report: Include PDF report in response
        client_id: Optional client ID for tracking

    Returns:
        Threat analysis results with optional PDF report
    """
    try:
        # Read file content and compute hash
        file_content = await file.read()
        file_size = len(file_content)

        # Check file size limit (10MB)
        if file_size > 10 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File too large (max 10MB)")

        # Compute SHA256 hash
        file_hash = hashlib.sha256(file_content).hexdigest()

        logger.debug(f"SCAN FILE started | target={file.filename}")

        # Run threat analysis on file hash
        analysis_result = await threat_analyzer.analyze(
            file_hash,
            use_external_apis=include_external_apis,
        )

        # Add file metadata
        analysis_result["file_info"] = {
            "filename": file.filename,
            "size": file_size,
            "content_type": file.content_type,
            "sha256": file_hash,
        }

        scan_id = _generate_scan_id("FILE")
        
        # Generate PDF report if requested
        report_url = None
        try:
            if include_report:
                pdf_bytes = await report_generator.generate_analysis_report(analysis_result)
                if pdf_bytes:
                    report_url = f"/api/v1/reports/download/{scan_id}"
                    # Store report for later retrieval (in-memory for now)
                    if not hasattr(report_generator, '_reports_cache'):
                        report_generator._reports_cache = {}
                    report_generator._reports_cache[scan_id] = pdf_bytes
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
        
        result = {
            "scan_id": scan_id,
            "filename": file.filename,
            "file_hash": file_hash,
            "status": "complete",
            "threat_level": analysis_result.get("verdict", "unknown"),
            "confidence": analysis_result.get("confidence", 0.0),
            "threats_detected": len(analysis_result.get("threat_indicators", [])),
            "analysis": analysis_result,
            "timestamp": datetime.utcnow().isoformat(),
            "report_url": report_url,
            "target_type": "file",
            "target_name": file.filename,
            "client_id": client_id,
            "scan_source": _normalize_scan_source(scan_source),
            # Include forensic metadata
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
        }
        
        # Store in scan history and database
        await _store_scan_result(result, db)
        
        _log_scan_completion(scan_id, "file", result)
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/url")
async def scan_url(request: ThreatScanRequest, db: AsyncSession = Depends(get_db)):
    """
    Scan a URL for threats using VirusTotal and URLScan

    Args:
        request: Scan request with target URL

    Returns:
        Threat analysis results
    """
    try:
        url = _validate_target(request.target)
        include_report = request.include_report

        # Ensure URL scheme is present
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        logger.debug(f"SCAN URL started | target={url}")

        # Run threat analysis
        analysis_result = await threat_analyzer.analyze(
            url,
            use_external_apis=request.include_external_apis,
        )

        scan_id = _generate_scan_id("URL")
        
        # Generate PDF report if requested
        report_url = None
        try:
            if include_report:
                pdf_bytes = await report_generator.generate_analysis_report(analysis_result)
                if pdf_bytes:
                    report_url = f"/api/v1/reports/download/{scan_id}"
                    # Store report for later retrieval
                    if not hasattr(report_generator, '_reports_cache'):
                        report_generator._reports_cache = {}
                    report_generator._reports_cache[scan_id] = pdf_bytes
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
        
        result = {
            "scan_id": scan_id,
            "url": url,
            "status": "complete",
            "threat_level": analysis_result.get("verdict", "unknown"),
            "confidence": analysis_result.get("confidence", 0.0),
            "threats_detected": len(analysis_result.get("threat_indicators", [])),
            "analysis": analysis_result,
            "timestamp": datetime.utcnow().isoformat(),
            "report_url": report_url,
            "target_type": "url",
            "target_name": url,
            "client_id": request.client_id,
            "scan_source": _normalize_scan_source(request.scan_source),
            # Include forensic metadata
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
        }
        
        # Store in scan history and database
        await _store_scan_result(result, db)
        
        _log_scan_completion(scan_id, "url", result)
        return result

    except Exception as e:
        logger.error(f"URL scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/ip")
async def scan_ip(request: ThreatScanRequest, db: AsyncSession = Depends(get_db)):
    """
    Scan an IP address for threats using AbuseIPDB and Shodan

    Args:
        request: Scan request with target IP

    Returns:
        Threat analysis results
    """
    try:
        ip = _validate_target(request.target, max_len=45)
        # Basic IP format check
        if not _RE_IP.match(ip):
            raise HTTPException(status_code=400, detail="Invalid IP address format")
        include_report = request.include_report

        logger.debug(f"SCAN IP started | target={ip}")

        # Run threat analysis
        analysis_result = await threat_analyzer.analyze(
            ip,
            use_external_apis=request.include_external_apis,
        )

        scan_id = _generate_scan_id("IP")
        
        # Generate PDF report if requested
        report_url = None
        try:
            if include_report:
                pdf_bytes = await report_generator.generate_analysis_report(analysis_result)
                if pdf_bytes:
                    report_url = f"/api/v1/reports/download/{scan_id}"
                    # Store report for later retrieval
                    if not hasattr(report_generator, '_reports_cache'):
                        report_generator._reports_cache = {}
                    report_generator._reports_cache[scan_id] = pdf_bytes
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
        
        result = {
            "scan_id": scan_id,
            "ip": ip,
            "status": "complete",
            "threat_level": analysis_result.get("verdict", "unknown"),
            "confidence": analysis_result.get("confidence", 0.0),
            "threats_detected": len(analysis_result.get("threat_indicators", [])),
            "analysis": analysis_result,
            "timestamp": datetime.utcnow().isoformat(),
            "report_url": report_url,
            "target_type": "ip",
            "target_name": ip,
            "client_id": request.client_id,
            "scan_source": _normalize_scan_source(request.scan_source),
            # Include forensic metadata
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
        }
        
        # Store in scan history and database
        await _store_scan_result(result, db)
        
        _log_scan_completion(scan_id, "ip", result)
        return result

    except Exception as e:
        logger.error(f"IP scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/hash")
async def scan_hash(request: ThreatScanRequest, db: AsyncSession = Depends(get_db)):
    """
    Scan a file hash for threats using VirusTotal and Hybrid Analysis

    Args:
        request: Scan request with target hash (MD5, SHA1, or SHA256)

    Returns:
        Threat analysis results
    """
    try:
        file_hash = _validate_target(request.target, max_len=128)
        # Accept MD5 (32), SHA1 (40), SHA256 (64) hex strings
        if not _RE_HASH.match(file_hash):
            raise HTTPException(status_code=400, detail="Invalid hash format — expected MD5 (32), SHA1 (40), or SHA256 (64) hex string")
        include_report = request.include_report

        logger.debug(f"SCAN HASH started | target={file_hash[:16]}...")

        # Run threat analysis
        analysis_result = await threat_analyzer.analyze(
            file_hash,
            use_external_apis=request.include_external_apis,
        )

        scan_id = _generate_scan_id("HASH")
        
        # Generate PDF report if requested
        report_url = None
        try:
            if include_report:
                pdf_bytes = await report_generator.generate_analysis_report(analysis_result)
                if pdf_bytes:
                    report_url = f"/api/v1/reports/download/{scan_id}"
                    if not hasattr(report_generator, '_reports_cache'):
                        report_generator._reports_cache = {}
                    report_generator._reports_cache[scan_id] = pdf_bytes
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")

        result = {
            "scan_id": scan_id,
            "hash": file_hash,
            "status": "complete",
            "threat_level": analysis_result.get("verdict", "unknown"),
            "confidence": analysis_result.get("confidence", 0.0),
            "threats_detected": len(analysis_result.get("threat_indicators", [])),
            "analysis": analysis_result,
            "timestamp": datetime.utcnow().isoformat(),
            "report_url": report_url,
            "target_type": "hash",
            "target_name": file_hash,
            "client_id": request.client_id,
            "scan_source": _normalize_scan_source(request.scan_source),
            # Include forensic metadata
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
        }
        
        # Store in scan history and database
        await _store_scan_result(result, db)
        
        _log_scan_completion(scan_id, "hash", result)
        return result

    except Exception as e:
        logger.error(f"Hash scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/scan")
async def universal_scan(request: ThreatScanRequest, db: AsyncSession = Depends(get_db)):
    """
    Universal scan endpoint - auto-detects input type and routes to appropriate analyzer

    Args:
        request: Scan request with target (IP, URL, domain, or hash)

    Returns:
        Threat analysis results
    """
    try:
        target = request.target.strip()
        include_report = request.include_report

        # Detect input type
        input_type, metadata = InputDetector.detect(target)

        logger.debug(f"SCAN started | detected_type={input_type.value} | target={target}")

        # Run threat analysis
        analysis_result = await threat_analyzer.analyze(
            target,
            use_external_apis=request.include_external_apis,
        )

        scan_id = _generate_scan_id("SCAN")
        
        # Generate PDF report if requested
        report_url = None
        try:
            if include_report:
                pdf_bytes = await report_generator.generate_analysis_report(analysis_result)
                if pdf_bytes:
                    report_url = f"/api/v1/reports/download/{scan_id}"
                    if not hasattr(report_generator, '_reports_cache'):
                        report_generator._reports_cache = {}
                    report_generator._reports_cache[scan_id] = pdf_bytes
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")

        result = {
            "scan_id": scan_id,
            "target": target,
            "detected_type": input_type.value,
            "status": "complete",
            "threat_level": analysis_result.get("verdict", "unknown"),
            "confidence": analysis_result.get("confidence", 0.0),
            "threats_detected": len(analysis_result.get("threat_indicators", [])),
            "analysis": analysis_result,
            "timestamp": datetime.utcnow().isoformat(),
            "report_url": report_url,
            "target_type": input_type.value,
            "target_name": target,
            "client_id": request.client_id,
            "scan_source": _normalize_scan_source(request.scan_source),
            # Include forensic metadata
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
            # Include AI analysis if available
            "ai_analysis": analysis_result.get("ai_analysis", {}),
            "ai_verdict_adjustment": analysis_result.get("ai_verdict_adjustment"),
        }
        
        # Store in scan history and database
        await _store_scan_result(result, db)
        
        _log_scan_completion(scan_id, input_type.value, result)
        return result

    except Exception as e:
        logger.error(f"Universal scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("")
@router.post("/")
async def universal_scan_root(request: ThreatScanRequest, db: AsyncSession = Depends(get_db)):
    """Compatibility alias for cleaner route usage: /api/v1/scan"""
    return await universal_scan(request, db)


@router.get("/results/{scan_id}")
async def get_scan_results(scan_id: str):
    """
    Get results of a specific scan

    Note: In production, scan results would be stored in a database
    """
    return {
        "scan_id": scan_id,
        "status": "complete",
        "timestamp": datetime.utcnow().isoformat(),
        "message": "For real-time results, use the /scan endpoint directly",
        "note": "Database integration recommended for production use",
    }
