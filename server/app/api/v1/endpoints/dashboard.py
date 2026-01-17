from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Query

router = APIRouter()


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
    time_range: Optional[str] = Query("24h", description="Time range: 24h, 7d, 30d")
):
    """Get dashboard summary with recent activity"""

    # Calculate stats based on time range
    time_range_label = {
        "24h": "Last 24 Hours",
        "7d": "Last 7 Days",
        "30d": "Last 30 Days",
    }.get(time_range, "Last 24 Hours")

    return {
        "time_range": time_range_label,
        "total_scans": 156,
        "threats_detected": 8,
        "critical_threats": 3,
        "last_scan": (datetime.now() - timedelta(hours=2)).isoformat(),
        "system_status": "active",
    }


@router.get("/threats")
async def get_dashboard_threats(
    time_range: Optional[str] = Query("24h", description="Time range: 24h, 7d, 30d"),
    severity: Optional[str] = Query(
        None, description="Filter by severity: critical, high, medium, low"
    ),
):
    """Get recent threats detected with filtering"""

    all_threats = [
        {
            "threat_id": "THR001",
            "name": "Suspicious Process Activity",
            "type": "Process Injection",
            "details": "Process_monitor.exe attempting network connection",
            "severity": "critical",
            "timestamp": (datetime.now() - timedelta(hours=1)).isoformat(),
            "source": "192.168.1.50",
            "location": "Bangalore, India",
        },
        {
            "threat_id": "THR002",
            "name": "Malware Signature Detected",
            "type": "Malware",
            "details": "file_download.exe matches known malware pattern",
            "severity": "critical",
            "timestamp": (datetime.now() - timedelta(hours=2)).isoformat(),
            "source": "192.168.1.75",
            "location": "Mumbai, India",
        },
        {
            "threat_id": "THR003",
            "name": "Suspicious URL Access",
            "type": "Phishing",
            "details": "Attempted access to known phishing domain",
            "severity": "medium",
            "timestamp": (datetime.now() - timedelta(hours=3)).isoformat(),
            "source": "192.168.1.100",
            "location": "Delhi, India",
        },
        {
            "threat_id": "THR004",
            "name": "Port Scan Detected",
            "type": "Reconnaissance",
            "details": "Multiple open ports detected via Shodan scan",
            "severity": "high",
            "timestamp": (datetime.now() - timedelta(days=1)).isoformat(),
            "source": "10.0.0.1",
            "location": "Hyderabad, India",
        },
    ]

    # Filter by severity if specified
    if severity:
        all_threats = [t for t in all_threats if t["severity"] == severity]

    return all_threats


@router.get("/stats")
async def get_dashboard_stats(
    time_range: Optional[str] = Query("24h", description="Time range: 24h, 7d, 30d")
):
    """Get dashboard statistics with breakdown by severity"""

    # Stats vary by time range
    stats_map = {
        "24h": {
            "critical_threats": 2,
            "high_threats": 2,
            "medium_threats": 3,
            "low_threats": 1,
            "files_scanned": 156,
            "urls_scanned": 23,
            "ips_scanned": 12,
        },
        "7d": {
            "critical_threats": 5,
            "high_threats": 8,
            "medium_threats": 12,
            "low_threats": 4,
            "files_scanned": 412,
            "urls_scanned": 67,
            "ips_scanned": 34,
        },
        "30d": {
            "critical_threats": 12,
            "high_threats": 18,
            "medium_threats": 28,
            "low_threats": 9,
            "files_scanned": 1023,
            "urls_scanned": 156,
            "ips_scanned": 78,
        },
    }

    return stats_map.get(time_range, stats_map["24h"])
