"""
Threat Scanning Endpoints
Handles threat analysis for IPs, URLs, domains, and file hashes
"""

import hashlib
import logging
import os
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel
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


class ThreatScanRequest(BaseModel):
    """Request model for threat scanning"""

    target: str
    include_report: bool = False
    client_id: Optional[str] = None  # Optional client ID for tracking


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
    
    # Store in database
    try:
        client_id_fk = None
        if scan_data.get("client_id"):
            query = select(ClientInstallation).where(ClientInstallation.client_id == scan_data["client_id"])
            result = await db.execute(query)
            client = result.scalar_one_or_none()
            if client:
                client_id_fk = client.id
        
        scan_record = ScanHistory(
            scan_id=scan_data["scan_id"],
            target=scan_data.get("target", scan_data.get("filename", "")),
            target_type=scan_data.get("target_type", "unknown"),
            threat_level=scan_data.get("threat_level", "unknown"),
            confidence=scan_data.get("confidence", 0.0),
            threats_detected=scan_data.get("threats_detected", 0),
            analysis_data=scan_data.get("analysis", {}),
            client_id=client_id_fk,
            report_generated=scan_data.get("report_url") is not None,
            # Forensic Reliability Fields
            evidence_sources=scan_data.get("forensic_metadata", {}).get("evidence_sources", []),
            corroboration_count=scan_data.get("forensic_metadata", {}).get("corroboration_count", 0),
        )
        
        db.add(scan_record)
        db.add(SystemLog(
            log_level="INFO",
            component="scanner",
            message=f"Scan completed: {scan_data['scan_id']} - {scan_data.get('target', '')}",
            details={
                "threat_level": scan_data.get("threat_level"),
                "target_type": scan_data.get("target_type"),
                "threats_detected": scan_data.get("threats_detected", 0),
            },
        ))
        await db.commit()
        logger.debug(f"Scan {scan_data['scan_id']} stored in database")
    except Exception as e:
        logger.error(f"Failed to store scan in database: {str(e)}")
        await db.rollback()


@router.get("/history")
async def get_scan_history():
    """Get recent scan history"""
    return {
        "total": len(_scan_history),
        "scans": _scan_history
    }


@router.post("/file")
async def scan_file(
    file: UploadFile = File(...),
    include_report: bool = False,
    client_id: Optional[str] = None,
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
        analysis_result = await threat_analyzer.analyze(file_hash)

        # Add file metadata
        analysis_result["file_info"] = {
            "filename": file.filename,
            "size": file_size,
            "content_type": file.content_type,
            "sha256": file_hash,
        }

        scan_id = f"FILE_{int(datetime.now().timestamp())}"
        
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
            # Include forensic metadata
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
        }
        
        # Store in scan history and database
        await _store_scan_result(result, db)
        
        logger.info(f"SCAN {scan_id} complete | type=file | level={result['threat_level']} | indicators={result['threats_detected']}")
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
        url = request.target.strip()
        include_report = request.include_report

        # Validate URL
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        logger.debug(f"SCAN URL started | target={url}")

        # Run threat analysis
        analysis_result = await threat_analyzer.analyze(url)

        scan_id = f"URL_{int(datetime.now().timestamp())}"
        
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
            # Include forensic metadata
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
        }
        
        # Store in scan history and database
        await _store_scan_result(result, db)
        
        logger.info(f"SCAN {scan_id} complete | type=url | level={result['threat_level']} | indicators={result['threats_detected']}")
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
        ip = request.target.strip()
        include_report = request.include_report

        logger.debug(f"SCAN IP started | target={ip}")

        # Run threat analysis
        analysis_result = await threat_analyzer.analyze(ip)

        scan_id = f"IP_{int(datetime.now().timestamp())}"
        
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
            # Include forensic metadata
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
        }
        
        # Store in scan history and database
        await _store_scan_result(result, db)
        
        logger.info(f"SCAN {scan_id} complete | type=ip | level={result['threat_level']} | indicators={result['threats_detected']}")
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
        file_hash = request.target.strip()
        include_report = request.include_report

        logger.debug(f"SCAN HASH started | target={file_hash[:16]}...")

        # Run threat analysis
        analysis_result = await threat_analyzer.analyze(file_hash)

        scan_id = f"HASH_{int(datetime.now().timestamp())}"
        
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
            # Include forensic metadata
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
        }
        
        # Store in scan history and database
        await _store_scan_result(result, db)
        
        logger.info(f"SCAN {scan_id} complete | type=hash | level={result['threat_level']} | indicators={result['threats_detected']}")
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
        analysis_result = await threat_analyzer.analyze(target)

        scan_id = f"SCAN_{int(datetime.now().timestamp())}"
        
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
            # Include forensic metadata
            "forensic_metadata": analysis_result.get("forensic_metadata", {}),
            # Include AI analysis if available
            "ai_analysis": analysis_result.get("ai_analysis", {}),
            "ai_verdict_adjustment": analysis_result.get("ai_verdict_adjustment"),
        }
        
        # Store in scan history and database
        await _store_scan_result(result, db)
        
        logger.info(f"SCAN {scan_id} complete | type={input_type.value} | level={result['threat_level']} | indicators={result['threats_detected']}")
        return result

    except Exception as e:
        logger.error(f"Universal scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


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
