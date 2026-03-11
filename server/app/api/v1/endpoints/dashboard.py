import asyncio
import json
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Query, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ....database import get_db
from ....config import settings
from ....models import ScanHistory, SystemLog

router = APIRouter()


def _get_time_threshold(time_range: str) -> datetime:
    now = datetime.utcnow()
    if time_range == "7d":
        return now - timedelta(days=7)
    if time_range == "30d":
        return now - timedelta(days=30)
    return now - timedelta(hours=24)


def _map_severity(threat_level: str) -> str:
    level = (threat_level or "unknown").lower()
    if level in ["malicious", "critical"]:
        return "critical"
    if level in ["suspicious", "high"]:
        return "high"
    if level in ["safe", "clean", "low"]:
        return "low"
    return "medium"


# Add OPTIONS handlers for CORS preflight
@router.options("/summary")
async def options_summary():
    """Handle CORS preflight for /summary endpoint."""
    return {}


@router.options("/threats")
async def options_dashboard_threats():
    """Handle CORS preflight for /threats endpoint."""
    return {}


@router.options("/stats")
async def options_stats():
    """Handle CORS preflight for /stats endpoint."""
    return {}


@router.get("/summary")
async def get_dashboard_summary(
    time_range: Optional[str] = Query("24h", description="Time range: 24h, 7d, 30d"),
    db: AsyncSession = Depends(get_db),
):
    """Get dashboard summary with recent activity"""

    time_range_label = {
        "24h": "Last 24 Hours",
        "7d": "Last 7 Days",
        "30d": "Last 30 Days",
    }.get(time_range, "Last 24 Hours")

    threshold = _get_time_threshold(time_range)
    result = await db.execute(
        select(ScanHistory).where(ScanHistory.scan_timestamp >= threshold).order_by(desc(ScanHistory.scan_timestamp))
    )
    scans = result.scalars().all()

    total_scans = len(scans)
    threats_detected = len([s for s in scans if (s.threat_level or "").lower() in ["malicious", "suspicious", "critical", "high"]])
    critical_threats = len([s for s in scans if (s.threat_level or "").lower() in ["malicious", "critical"]])
    last_scan = scans[0].scan_timestamp.isoformat() if scans else None

    return {
        "time_range": time_range_label,
        "total_scans": total_scans,
        "threats_detected": threats_detected,
        "critical_threats": critical_threats,
        "last_scan": last_scan,
        "system_status": "active",
    }


@router.get("/threats")
async def get_dashboard_threats(
    time_range: Optional[str] = Query("24h", description="Time range: 24h, 7d, 30d"),
    severity: Optional[str] = Query(
        None, description="Filter by severity: critical, high, medium, low"
    ),
    db: AsyncSession = Depends(get_db),
):
    """Get recent threats detected with filtering"""

    threshold = _get_time_threshold(time_range)
    result = await db.execute(
        select(ScanHistory)
        .where(ScanHistory.scan_timestamp >= threshold)
        .order_by(desc(ScanHistory.scan_timestamp))
    )
    scans = result.scalars().all()

    threats = []
    for scan in scans:
        level = (scan.threat_level or "").lower()
        if level in ["safe", "clean", "unknown"]:
            continue
        sev = _map_severity(level)
        if severity and sev != severity:
            continue

        analysis = scan.analysis_data or {}
        summary = analysis.get("summary") or "Threat detected"

        threats.append({
            "threat_id": scan.scan_id,
            "name": f"{scan.target_type.upper()} Threat",
            "type": scan.target_type,
            "details": summary,
            "severity": sev,
            "timestamp": scan.scan_timestamp.isoformat(),
            "source": scan.target,
            "location": "Unknown",
        })

    return threats


@router.get("/stats")
async def get_dashboard_stats(
    time_range: Optional[str] = Query("24h", description="Time range: 24h, 7d, 30d"),
    db: AsyncSession = Depends(get_db),
):
    """Get dashboard statistics with breakdown by severity"""

    threshold = _get_time_threshold(time_range)
    result = await db.execute(
        select(ScanHistory).where(ScanHistory.scan_timestamp >= threshold)
    )
    scans = result.scalars().all()

    stats = {
        "critical_threats": 0,
        "high_threats": 0,
        "medium_threats": 0,
        "low_threats": 0,
        "files_scanned": 0,
        "urls_scanned": 0,
        "ips_scanned": 0,
    }

    for scan in scans:
        sev = _map_severity(scan.threat_level or "unknown")
        if sev == "critical":
            stats["critical_threats"] += 1
        elif sev == "high":
            stats["high_threats"] += 1
        elif sev == "medium":
            stats["medium_threats"] += 1
        else:
            stats["low_threats"] += 1

        t = (scan.target_type or "").lower()
        if t in ["file", "hash"]:
            stats["files_scanned"] += 1
        elif t in ["url", "domain"]:
            stats["urls_scanned"] += 1
        elif t in ["ip"]:
            stats["ips_scanned"] += 1

    return stats


@router.get("/logs")
async def get_dashboard_logs(
    limit: int = Query(50, description="Max log entries"),
    db: AsyncSession = Depends(get_db),
):
    """Get recent system logs for dashboard"""
    result = await db.execute(
        select(SystemLog).order_by(desc(SystemLog.timestamp)).limit(limit)
    )
    logs = result.scalars().all()
    return [
        {
            "level": log.log_level,
            "component": log.component,
            "message": log.message,
            "details": log.details,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
        }
        for log in logs
    ]


@router.get("/api-status")
async def get_api_status():
    """Return API configuration status for dashboard."""
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


@router.get("/logs/stream")
async def stream_logs(db: AsyncSession = Depends(get_db)):
    """Stream recent logs using Server-Sent Events (SSE)."""

    async def event_generator():
        last_ts = datetime.utcnow() - timedelta(minutes=5)
        while True:
            result = await db.execute(
                select(SystemLog)
                .where(SystemLog.timestamp > last_ts)
                .order_by(SystemLog.timestamp)
                .limit(100)
            )
            logs = result.scalars().all()

            for log in logs:
                last_ts = log.timestamp or last_ts
                payload = {
                    "level": log.log_level,
                    "component": log.component,
                    "message": log.message,
                    "details": log.details,
                    "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                }
                yield f"data: {json.dumps(payload)}\n\n"

            await asyncio.sleep(2)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
