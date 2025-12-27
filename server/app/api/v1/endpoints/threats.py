from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel

router = APIRouter()


class IPScanRequest(BaseModel):
    ip_address: str


# Add OPTIONS handlers for CORS preflight
@router.options("")
async def options_threats():
    """Handle CORS preflight for / endpoint."""
    return {}


@router.options("/{threat_id}")
async def options_threat_detail(threat_id: str):
    """Handle CORS preflight for detail endpoint."""
    return {}


@router.options("/{threat_id}/respond")
async def options_threat_respond(threat_id: str):
    """Handle CORS preflight for respond endpoint."""
    return {}


@router.options("/scan-ip")
async def options_scan_ip():
    """Handle CORS preflight for scan-ip endpoint."""
    return {}


@router.get("")
async def get_threats(
    time_range: Optional[str] = Query(
        "24h", description="Time range: 24h, 7d, 30d, or custom date YYYY-MM-DD"
    ),
    start_date: Optional[str] = Query(
        None, description="Start date in YYYY-MM-DD format"
    ),
    end_date: Optional[str] = Query(None, description="End date in YYYY-MM-DD format"),
):
    """Get all detected threats filtered by time range"""

    # Calculate date range
    now = datetime.now()

    if time_range == "24h":
        start = now - timedelta(hours=24)
    elif time_range == "7d":
        start = now - timedelta(days=7)
    elif time_range == "30d":
        start = now - timedelta(days=30)
    elif time_range == "custom" and start_date and end_date:
        try:
            start = datetime.strptime(start_date, "%Y-%m-%d")
            end = datetime.strptime(end_date, "%Y-%m-%d")
            end = end.replace(hour=23, minute=59, second=59)
        except ValueError:
            return {"error": "Invalid date format. Use YYYY-MM-DD"}
    else:
        start = now - timedelta(hours=24)

    # Mock data with proper threat information including location
    mock_threats = [
        {
            "threat_id": "THR001",
            "name": "Suspicious Process Activity",
            "type": "Process Injection",
            "details": "Process_monitor.exe attempting network connection",
            "severity": "critical",
            "timestamp": (datetime.now() - timedelta(hours=1)).isoformat(),
            "status": "active",
            "source": "192.168.1.50",
            "location": "Bangalore, India",
            "source_country": "IN",
            "detected_by": "Network Scanner",
        },
        {
            "threat_id": "THR002",
            "name": "Malware Signature Detected",
            "type": "Malware",
            "details": "file_download.exe matches Trojan.Generic pattern",
            "severity": "critical",
            "timestamp": (datetime.now() - timedelta(hours=2)).isoformat(),
            "status": "active",
            "source": "192.168.1.75",
            "location": "Mumbai, India",
            "source_country": "IN",
            "detected_by": "File Scanner",
        },
        {
            "threat_id": "THR003",
            "name": "Suspicious URL Access",
            "type": "Phishing",
            "details": "Attempted access to malicious domain: fake-bank.com",
            "severity": "medium",
            "timestamp": (datetime.now() - timedelta(hours=3)).isoformat(),
            "status": "resolved",
            "source": "192.168.1.100",
            "location": "Delhi, India",
            "source_country": "IN",
            "detected_by": "URL Scanner",
        },
        {
            "threat_id": "THR004",
            "name": "Port Scan Detected",
            "type": "Reconnaissance",
            "details": "Multiple open ports detected via Shodan scan",
            "severity": "high",
            "timestamp": (datetime.now() - timedelta(days=1, hours=5)).isoformat(),
            "status": "mitigated",
            "source": "10.0.0.1",
            "location": "Hyderabad, India",
            "source_country": "IN",
            "detected_by": "Shodan API",
        },
        {
            "threat_id": "THR005",
            "name": "Abusive IP Detected",
            "type": "Abuse/Spam",
            "details": "IP flagged for spamming activity on AbuseIPDB",
            "severity": "medium",
            "timestamp": (datetime.now() - timedelta(days=2)).isoformat(),
            "status": "active",
            "source": "203.100.50.75",
            "location": "Chennai, India",
            "source_country": "IN",
            "detected_by": "AbuseIPDB",
        },
        {
            "threat_id": "THR006",
            "name": "VirusTotal Detection",
            "type": "File Hash Malicious",
            "details": "File hash detected as malicious by multiple vendors",
            "severity": "critical",
            "timestamp": (datetime.now() - timedelta(days=5)).isoformat(),
            "status": "quarantined",
            "source": "192.168.1.120",
            "location": "Pune, India",
            "source_country": "IN",
            "detected_by": "VirusTotal",
        },
    ]

    # Filter by date range
    filtered_threats = [
        t for t in mock_threats if datetime.fromisoformat(t["timestamp"]) >= start
    ]

    return {
        "time_range": time_range,
        "start_date": start.isoformat(),
        "end_date": (
            (datetime.strptime(end_date, "%Y-%m-%d") if end_date else now).isoformat()
            if time_range == "custom"
            else now.isoformat()
        ),
        "total_threats": len(filtered_threats),
        "threats": filtered_threats,
    }


@router.get("/{threat_id}")
async def get_threat_details(threat_id: str):
    """Get comprehensive details of a specific threat"""
    threat_details_map = {
        "THR001": {
            "threat_id": "THR001",
            "name": "Suspicious Process Activity",
            "type": "Process Injection",
            "description": "Unauthorized process attempting network connection from victim system",
            "severity": "critical",
            "timestamp": (datetime.now() - timedelta(hours=1)).isoformat(),
            "source": "192.168.1.50",
            "location": "Bangalore, India",
            "source_country": "IN",
            "status": "active",
            "detected_by": "Network Scanner",
            "api_sources": ["Shodan", "AbuseIPDB"],
            "confidence_score": 95,
            "affected_systems": ["VICTIM-PC-01", "VICTIM-PC-02"],
            "recommended_action": "Isolate affected systems immediately",
            "details": {
                "process_name": "Process_monitor.exe",
                "target_ports": [80, 443, 8080],
                "connection_attempts": 45,
                "failed_auth_attempts": 12,
            },
        },
        "THR002": {
            "threat_id": "THR002",
            "name": "Malware Signature Detected",
            "type": "Malware",
            "description": "File matched known malware pattern via VirusTotal",
            "severity": "critical",
            "timestamp": (datetime.now() - timedelta(hours=2)).isoformat(),
            "source": "192.168.1.75",
            "location": "Mumbai, India",
            "source_country": "IN",
            "status": "active",
            "detected_by": "File Scanner",
            "api_sources": ["VirusTotal", "Hybrid Analysis"],
            "confidence_score": 98,
            "file_hash": "d131dd02c5e6eec1...",
            "file_name": "file_download.exe",
            "malware_family": "Trojan.Generic",
            "recommended_action": "Quarantine file immediately",
            "details": {
                "detection_ratio": "42/67",
                "vendors": ["Norton", "McAfee", "Kaspersky"],
                "file_size": "2.3 MB",
                "first_seen": (datetime.now() - timedelta(days=30)).isoformat(),
            },
        },
    }

    threat = threat_details_map.get(threat_id)
    if not threat:
        return {
            "threat_id": threat_id,
            "name": "Unknown Threat",
            "error": "Threat not found",
        }
    return threat


@router.post("/{threat_id}/respond")
async def respond_to_threat(threat_id: str):
    """Respond to a specific threat with mitigation action"""
    return {
        "threat_id": threat_id,
        "status": "responded",
        "action": "threat_quarantined",
        "timestamp": datetime.now().isoformat(),
        "message": "Threat has been quarantined and isolated successfully",
        "details": {
            "action_taken": "Isolated system from network",
            "files_quarantined": 1,
            "processes_killed": 1,
            "logs_generated": True,
        },
    }


@router.post("/scan-ip")
async def scan_ip(request: IPScanRequest):
    """Scan an IP address for threats using multiple APIs"""
    return {
        "ip_address": request.ip_address,
        "scan_status": "complete",
        "threat_level": "suspicious",
        "reputation_score": 45,
        "location": "Unknown",
        "api_results": {
            "abuseipdb": {"abuse_score": 65, "reports": 23},
            "shodan": {"open_ports": 8, "vulnerabilities": 3},
        },
        "details": f"IP {request.ip_address} has suspicious reputation",
    }
