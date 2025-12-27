"""
Threat Scanning Endpoints
Handles threat analysis for IPs, URLs, domains, and file hashes
"""

import hashlib
import logging
from datetime import datetime

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

from ....core.input_detector import InputDetector
from ....core.report_generator import report_generator
from ....core.threat_analyzer import threat_analyzer

logger = logging.getLogger(__name__)
router = APIRouter()


class ThreatScanRequest(BaseModel):
    """Request model for threat scanning"""

    target: str
    include_report: bool = False


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


@router.post("/file")
async def scan_file(file: UploadFile = File(...), include_report: bool = False):
    """
    Scan an uploaded file for threats using VirusTotal and Hybrid Analysis

    Args:
        file: File to scan
        include_report: Include PDF report in response

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

        logger.info(f"Scanning file: {file.filename} (SHA256: {file_hash})")

        # Run threat analysis on file hash
        analysis_result = await threat_analyzer.analyze(file_hash)

        # Add file metadata
        analysis_result["file_info"] = {
            "filename": file.filename,
            "size": file_size,
            "content_type": file.content_type,
            "sha256": file_hash,
        }

        # Generate PDF report if requested
        if include_report:
            pdf_bytes = await report_generator.generate_analysis_report(analysis_result)
            if pdf_bytes:
                analysis_result["report"] = {
                    "format": "pdf",
                    "size": len(pdf_bytes),
                    "data": pdf_bytes.hex(),  # Convert bytes to hex string for JSON
                }

        return {
            "scan_id": f"FILE_{datetime.now().timestamp()}",
            "filename": file.filename,
            "file_hash": file_hash,
            "status": "complete",
            "threat_level": analysis_result.get("verdict", "unknown"),
            "confidence": analysis_result.get("confidence", 0.0),
            "threats_detected": len(analysis_result.get("threat_indicators", [])),
            "analysis": analysis_result,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/url")
async def scan_url(request: ThreatScanRequest):
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

        logger.info(f"Scanning URL: {url}")

        # Run threat analysis
        analysis_result = await threat_analyzer.analyze(url)

        # Generate PDF report if requested
        if include_report:
            pdf_bytes = await report_generator.generate_analysis_report(analysis_result)
            if pdf_bytes:
                analysis_result["report"] = {
                    "format": "pdf",
                    "size": len(pdf_bytes),
                    "data": pdf_bytes.hex(),
                }

        return {
            "scan_id": f"URL_{datetime.now().timestamp()}",
            "url": url,
            "status": "complete",
            "threat_level": analysis_result.get("verdict", "unknown"),
            "confidence": analysis_result.get("confidence", 0.0),
            "threats_detected": len(analysis_result.get("threat_indicators", [])),
            "analysis": analysis_result,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"URL scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/ip")
async def scan_ip(request: ThreatScanRequest):
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

        logger.info(f"Scanning IP: {ip}")

        # Run threat analysis
        analysis_result = await threat_analyzer.analyze(ip)

        # Generate PDF report if requested
        if include_report:
            pdf_bytes = await report_generator.generate_analysis_report(analysis_result)
            if pdf_bytes:
                analysis_result["report"] = {
                    "format": "pdf",
                    "size": len(pdf_bytes),
                    "data": pdf_bytes.hex(),
                }

        return {
            "scan_id": f"IP_{datetime.now().timestamp()}",
            "ip": ip,
            "status": "complete",
            "threat_level": analysis_result.get("verdict", "unknown"),
            "confidence": analysis_result.get("confidence", 0.0),
            "threats_detected": len(analysis_result.get("threat_indicators", [])),
            "analysis": analysis_result,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"IP scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/hash")
async def scan_hash(request: ThreatScanRequest):
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

        logger.info(f"Scanning hash: {file_hash}")

        # Run threat analysis
        analysis_result = await threat_analyzer.analyze(file_hash)

        # Generate PDF report if requested
        if include_report:
            pdf_bytes = await report_generator.generate_analysis_report(analysis_result)
            if pdf_bytes:
                analysis_result["report"] = {
                    "format": "pdf",
                    "size": len(pdf_bytes),
                    "data": pdf_bytes.hex(),
                }

        return {
            "scan_id": f"HASH_{datetime.now().timestamp()}",
            "hash": file_hash,
            "status": "complete",
            "threat_level": analysis_result.get("verdict", "unknown"),
            "confidence": analysis_result.get("confidence", 0.0),
            "threats_detected": len(analysis_result.get("threat_indicators", [])),
            "analysis": analysis_result,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Hash scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/scan")
async def universal_scan(request: ThreatScanRequest):
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

        logger.info(
            f"Universal scan - Detected type: {input_type} for target: {target}"
        )

        # Run threat analysis
        analysis_result = await threat_analyzer.analyze(target)

        # Generate PDF report if requested
        if include_report:
            pdf_bytes = await report_generator.generate_analysis_report(analysis_result)
            if pdf_bytes:
                analysis_result["report"] = {
                    "format": "pdf",
                    "size": len(pdf_bytes),
                    "data": pdf_bytes.hex(),
                }

        return {
            "scan_id": f"SCAN_{datetime.now().timestamp()}",
            "target": target,
            "detected_type": input_type.value,
            "status": "complete",
            "threat_level": analysis_result.get("verdict", "unknown"),
            "confidence": analysis_result.get("confidence", 0.0),
            "threats_detected": len(analysis_result.get("threat_indicators", [])),
            "analysis": analysis_result,
            "timestamp": datetime.utcnow().isoformat(),
        }

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
