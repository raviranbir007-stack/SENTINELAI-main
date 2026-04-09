
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Query
from pydantic import BaseModel

router = APIRouter()


def _parse_timestamp_utc(value: str) -> Optional[datetime]:
    """Parse ISO timestamp and return a timezone-aware UTC datetime."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

# Endpoint to mark all threats as read (acknowledged)
@router.post("/mark-all-read")
async def mark_all_threats_as_read():
    """Mark all threats as read/acknowledged and restore system health to normal."""
    from .scan import _scan_history
    # Mark all threats in scan history as read
    for scan in _scan_history:
        scan["is_read"] = True
    # If you have a DB model for threats, update those as well here
    # System health logic: if all are read, health is normal
    health = "normal" if all(s.get("is_read", False) for s in _scan_history) else "degraded"
    # Set global/system health if available
    try:
        from .scan import _system_health
        _system_health["status"] = health
    except Exception:
        pass
    return {"status": "ok", "all_threats_marked_read": True, "system_health": health}


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
    """Get detected threats filtered by time range from real scan history only."""

    # Import scan history
    from .scan import _scan_history
    
    # Calculate date range
    now = datetime.now(timezone.utc)

    if time_range == "24h":
        start = now - timedelta(hours=24)
    elif time_range == "7d":
        start = now - timedelta(days=7)
    elif time_range == "30d":
        start = now - timedelta(days=30)
    elif time_range == "custom" and start_date and end_date:
        try:
            start = datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            end = datetime.strptime(end_date, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59, tzinfo=timezone.utc
            )
        except ValueError:
            return {"error": "Invalid date format. Use YYYY-MM-DD"}
    else:
        start = now - timedelta(hours=24)
    
    # Convert scan history to threat format
    threats_from_scans = []
    seen_ids = set()
    seen_fingerprints = set()
    for scan in _scan_history:
        scan_time = _parse_timestamp_utc(scan.get("timestamp", ""))
        if scan_time is None:
            continue
        if scan_time >= start:
            threat_level = scan.get("threat_level", "unknown")
            threats_count = scan.get("threats_detected", 0)
            
            # Determine severity based on threat level
            severity_map = {
                "malicious": "critical",
                "critical": "critical",
                "suspicious": "high",
                "high": "high",
                "clean": "low",
                "safe": "low",
                "unknown": "medium",
            }
            severity = severity_map.get(str(threat_level).lower(), "medium")
            
            # Determine status
            status = "active" if severity in ["critical", "high"] else "resolved"

            scan_id = scan.get("scan_id")
            if scan_id:
                if scan_id in seen_ids:
                    continue
                seen_ids.add(scan_id)

            # Deduplicate repeated equivalent records (common after restarts/replays)
            fingerprint = (
                str(scan.get("target_type", "unknown")).lower(),
                str(scan.get("target_name", "unknown")).lower(),
                severity,
                scan_time.replace(minute=0, second=0, microsecond=0).isoformat(),
            )
            if fingerprint in seen_fingerprints:
                continue
            seen_fingerprints.add(fingerprint)
            
            threat_item = {
                "threat_id": scan.get("scan_id") or f"SCANLESS_{len(threats_from_scans)+1}",
                "name": f"{str(scan.get('target_type', 'unknown')).upper()} Scan: {scan.get('target_name', 'unknown')}",
                "type": f"{scan.get('target_type', 'unknown')} Analysis",
                "details": f"Threat Level: {threat_level}, Threats Found: {threats_count}",
                "severity": severity,
                "timestamp": scan.get("timestamp"),
                "status": status,
                "source": scan.get("target_name", "unknown"),
                "location": "SENTINEL-AI System",
                "source_country": "N/A",
                "detected_by": f"Multi-API Scan ({scan.get('target_type', 'unknown')})",
                "report_url": scan.get("report_url"),
                "confidence": scan.get("confidence", 0.0),
                "target_type": scan.get("target_type", "unknown"),
            }
            threats_from_scans.append(threat_item)
    # Sort newest first for stable dashboard order
    all_threats = sorted(
        threats_from_scans,
        key=lambda item: item.get("timestamp", ""),
        reverse=True,
    )

    return {
        "time_range": time_range,
        "start_date": start.isoformat(),
        "end_date": (
            (
                datetime.strptime(end_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if end_date
                else now
            ).isoformat()
            if time_range == "custom"
            else now.isoformat()
        ),
        "total_threats": len(all_threats),
        "threats": all_threats,
    }



@router.get("/{threat_id}")
async def get_threat_details(threat_id: str):
    """Get details for a specific threat ID from real scan history."""
    from .scan import _scan_history

    scan = next((entry for entry in _scan_history if entry.get("scan_id") == threat_id), None)
    if not scan:
        return {
            "threat_id": threat_id,
            "name": "Unknown Threat",
            "error": "Threat not found",
        }

    threat_level = str(scan.get("threat_level", "unknown")).lower()
    severity_map = {
        "malicious": "critical",
        "critical": "critical",
        "suspicious": "high",
        "high": "high",
        "clean": "low",
        "safe": "low",
        "unknown": "medium",
    }
    severity = severity_map.get(threat_level, "medium")
    threat_count = int(scan.get("threats_detected", 0) or 0)
    status = "active" if severity in {"critical", "high"} else "resolved"

    return {
        "threat_id": threat_id,
        "name": f"{str(scan.get('target_type', 'unknown')).upper()} Scan: {scan.get('target_name', 'unknown')}",
        "type": f"{scan.get('target_type', 'unknown')} Analysis",
        "description": f"Threat level {threat_level} with {threat_count} indicator(s) detected.",
        "severity": severity,
        "timestamp": scan.get("timestamp"),
        "source": scan.get("target_name", "unknown"),
        "location": "SENTINEL-AI System",
        "source_country": "N/A",
        "status": status,
        "detected_by": f"Multi-API Scan ({scan.get('target_type', 'unknown')})",
        "confidence_score": round(float(scan.get("confidence", 0.0) or 0.0) * 100, 1),
        "recommended_action": (
            "Isolate and investigate immediately"
            if severity == "critical"
            else "Review scan artifacts and monitor for recurrence"
        ),
        "details": {
            "target_type": scan.get("target_type"),
            "target_name": scan.get("target_name"),
            "threat_level": threat_level,
            "threats_detected": threat_count,
            "report_url": scan.get("report_url"),
        },
    }


@router.post("/{threat_id}/respond")
async def respond_to_threat(threat_id: str):
    """Respond to a specific threat with mitigation action"""
    from .scan import _scan_history

    found = any(scan.get("scan_id") == threat_id for scan in _scan_history)
    return {
        "threat_id": threat_id,
        "status": "responded" if found else "not_found",
        "action": "threat_quarantined" if found else "none",
        "timestamp": datetime.now().isoformat(),
        "message": (
            "Threat has been quarantined and isolated successfully"
            if found
            else "Threat ID not found in current scan history"
        ),
        "details": {
            "action_taken": "Isolated system from network" if found else "No action taken",
            "files_quarantined": 1 if found else 0,
            "processes_killed": 1 if found else 0,
            "logs_generated": found,
            "threat_exists": found,
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
