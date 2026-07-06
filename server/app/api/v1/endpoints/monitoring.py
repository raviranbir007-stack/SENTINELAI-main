"""
Background Monitoring API — SENTINEL-AI v3

Exposes read-only access to the background activity-monitor database
(activity_monitoring.db) so the dashboard can display surveillance
telemetry separately from operator-triggered manual scans.

All data here comes from the AutomaticActivityMonitor which runs
with use_external_apis=False — zero external API quota is consumed.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Query, Depends
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from ....database import get_db
from ....models import ClientInstallation, SystemLog, User
from .auth import require_permission

logger = logging.getLogger(__name__)
router = APIRouter()


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hours(time_range: str) -> int:
    return {"24h": 24, "7d": 168, "30d": 720}.get(time_range, 24)


def _label(time_range: str) -> str:
    return {"24h": "Last 24 Hours", "7d": "Last 7 Days", "30d": "Last 30 Days"}.get(
        time_range, "Last 24 Hours"
    )


def _adb():
    try:
        from ....core.activity_database import activity_db
        return activity_db
    except Exception:
        return None


def _monitoring_scope(user: User, organization_id: Optional[int], department_id: Optional[int]) -> tuple[Optional[int], Optional[int]]:
    user_org_id = getattr(user, "organization_id", None)
    user_dept_id = getattr(user, "department_id", None)
    is_admin = bool(getattr(user, "is_admin", False))
    effective_org_id = organization_id if is_admin and organization_id is not None else user_org_id
    effective_dept_id = department_id if is_admin and department_id is not None else user_dept_id
    return effective_org_id, effective_dept_id


async def _tenant_client_scope(db: AsyncSession, organization_id: Optional[int], department_id: Optional[int]) -> tuple[set[str], set[int]]:
    if organization_id is None:
        return set(), set()

    query = select(ClientInstallation.client_id, ClientInstallation.ip_address).where(ClientInstallation.organization_id == organization_id)
    if department_id is not None:
        query = query.where(ClientInstallation.department_id == department_id)
    result = await db.execute(query)
    client_ids: set[str] = set()
    client_ips: set[int] = set()
    for client_id, ip_address in result.all():
        if client_id:
            client_ids.add(str(client_id))
        if ip_address:
            client_ips.add(str(ip_address))
    return client_ids, client_ips


def _details_match_tenant(details: dict, client_ids: set[str], client_ips: set[str]) -> bool:
    if not client_ids and not client_ips:
        return True
    details = details or {}
    candidate_values = [
        details.get("client_id"),
        details.get("host_ip"),
        details.get("source_ip"),
        details.get("destination_ip"),
        details.get("ip_address"),
    ]
    for value in candidate_values:
        if value is None:
            continue
        text = str(value)
        if text in client_ids or text in client_ips:
            return True
    return False


def _filter_websites_by_tenant(items: list[dict], client_ips: set[str]) -> list[dict]:
    if not client_ips:
        return items
    filtered = []
    for item in items:
        host_ip = str(item.get("host_ip") or "").strip()
        if host_ip and host_ip in client_ips:
            filtered.append(item)
    return filtered


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

@router.options("/{path:path}")
async def options_catch_all(path: str):
    return {}


# ---------------------------------------------------------------------------
# /stats  — primary background monitoring stats
# ---------------------------------------------------------------------------

@router.get("/stats")
async def get_monitoring_stats(
    time_range: Optional[str] = Query("24h", description="Time range: 24h, 7d, 30d"),
    organization_id: Optional[int] = Query(default=None),
    department_id: Optional[int] = Query(default=None),
    current_user = Depends(require_permission("reports.read")),
):
    """
    Summary of background surveillance activity for the chosen period.

    Includes:
    - Number of automated artifact scans performed
    - Threats detected by local heuristics/ML (no external API calls)
    - Breakdown by artifact type (url, ip, hash, domain)
    - Websites visited and network connections observed
    """
    adb = _adb()
    if not adb:
        return {"available": False, "reason": "Activity database not initialised"}

    hours = _hours(time_range)
    effective_org_id, effective_dept_id = _monitoring_scope(current_user, organization_id, department_id)
    try:
        stats = adb.get_background_stats(hours=hours)
        return {
            "available": True,
            "time_range": _label(time_range),
            "generated_at": utcnow().isoformat() + "Z",
            "note": "These scans run locally — no external API quota consumed.",
            "tenant_scope": {
                "organization_id": effective_org_id,
                "department_id": effective_dept_id,
                "applies_to_shared_activity_db": False,
            },
            **stats,
        }
    except Exception as exc:
        logger.error("monitoring /stats error: %s", exc)
        return {"available": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# /activity  — recent background activity feed
# ---------------------------------------------------------------------------

@router.get("/activity")
async def get_recent_activity(
    limit: int = Query(200, ge=1, le=2000, description="Max entries to return - increased to show more recent activity"),
    db: AsyncSession = Depends(get_db),
    organization_id: Optional[int] = Query(default=None),
    department_id: Optional[int] = Query(default=None),
    current_user = Depends(require_permission("reports.read")),
):
    """
    Most recent background activity entries across all monitored artifact types.
    Each entry is classified by the local heuristics & ML engine.
    """
    adb = _adb()
    if not adb:
        return {"available": False, "items": []}

    try:
        effective_org_id, effective_dept_id = _monitoring_scope(current_user, organization_id, department_id)
        tenant_client_ids, tenant_client_ips = await _tenant_client_scope(db, effective_org_id, effective_dept_id)
        items = adb.get_recent_activity(limit=limit)

        # Merge live defense/network action events so IDS/IPS/detection actions
        # appear in dashboard live activity.
        defense_result = await db.execute(
            select(SystemLog)
            .where(SystemLog.component.in_(["defense_event", "network_defense", "nids_ingestion"]))
            .order_by(desc(SystemLog.timestamp))
            .limit(max(limit, 100))
        )
        defense_logs = defense_result.scalars().all()

        defense_items = []
        for row in defense_logs:
            details = row.details if isinstance(row.details, dict) else {}
            if effective_org_id is not None and not _details_match_tenant(details, tenant_client_ids, tenant_client_ips):
                continue
            event_name = details.get("event") or (str(row.message).split(":", 1)[0] if row.message else "defense_event")
            severity = str(details.get("severity") or "medium").lower()
            verdict = "critical" if severity == "critical" else "malicious" if severity == "high" else "suspicious" if severity == "medium" else "safe"
            source_value = details.get("source_ip") or details.get("source_domain") or details.get("destination_ip") or details.get("client_id") or "endpoint"

            defense_items.append(
                {
                    "type": event_name,
                    "value": source_value,
                    "verdict": verdict,
                    "confidence": 0.95 if severity == "critical" else 0.8 if severity == "high" else 0.6,
                    "indicator_count": 1,
                    "automated": True,
                    "time": row.timestamp.isoformat() if row.timestamp else utcnow().isoformat(),
                    "source": row.component or "defense_event",
                    "description": row.message,
                    "details": details,
                }
            )

        merged = list(items) + defense_items
        merged.sort(key=lambda x: str(x.get("time") or ""), reverse=True)
        merged = merged[:limit]

        return {
            "available": True,
            "count": len(merged),
            "generated_at": utcnow().isoformat() + "Z",
            "tenant_scope": {
                "organization_id": effective_org_id,
                "department_id": effective_dept_id,
                "applies_to_shared_activity_db": False,
                "client_ids_known": len(tenant_client_ids),
                "client_ips_known": len(tenant_client_ips),
            },
            "items": merged,
        }
    except Exception as exc:
        logger.error("monitoring /activity error: %s", exc)
        return {"available": False, "items": [], "error": str(exc)}


# ---------------------------------------------------------------------------
# /websites  — visited browser sites with verdicts
# ---------------------------------------------------------------------------

@router.get("/websites")
async def get_visited_websites(
    limit: int = Query(200, ge=1, le=2000, description="Max entries - fetch more recent history"),
    hours: int = Query(24, ge=1, le=720, description="Lookback window hours"),
    organization_id: Optional[int] = Query(default=None),
    department_id: Optional[int] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_permission("reports.read")),
):
    """
    Recently visited websites captured by the browser history monitor.
    Each entry includes the domain, verdict (safe/suspicious/malicious), browser, and time.
    """
    adb = _adb()
    if not adb:
        return {"available": False, "items": []}

    try:
        items = adb.get_visited_websites(limit=limit, hours=hours)
        effective_org_id, effective_dept_id = _monitoring_scope(current_user, organization_id, department_id)
        tenant_client_ids, tenant_client_ips = await _tenant_client_scope(db, effective_org_id, effective_dept_id)
        items = _filter_websites_by_tenant(items, tenant_client_ips) if effective_org_id is not None else items
        return {
            "available": True,
            "count": len(items),
            "generated_at": utcnow().isoformat() + "Z",
            "tenant_scope": {
                "organization_id": effective_org_id,
                "department_id": effective_dept_id,
                "applies_to_shared_activity_db": False,
                "client_ips_known": len(tenant_client_ips),
            },
            "items": items,
        }
    except Exception as exc:
        logger.error("monitoring /websites error: %s", exc)
        return {"available": False, "items": [], "error": str(exc)}


# ---------------------------------------------------------------------------
# /threat-feed  — recent background threats only
# ---------------------------------------------------------------------------

@router.get("/threat-feed")
async def get_threat_feed(
    limit: int = Query(20, ge=1, le=100, description="Max threats to return"),
    organization_id: Optional[int] = Query(default=None),
    department_id: Optional[int] = Query(default=None),
    current_user = Depends(require_permission("alerts.read")),
):
    """
    Real-time feed of threats found by the background auto-monitor.
    Only includes verdicts: malicious, suspicious, critical.
    """
    adb = _adb()
    if not adb:
        return {"available": False, "threats": []}

    try:
        threats = adb.get_recent_threats(limit=limit)
        effective_org_id, effective_dept_id = _monitoring_scope(current_user, organization_id, department_id)
        return {
            "available": True,
            "count": len(threats),
            "generated_at": utcnow().isoformat() + "Z",
            "source": "background_auto_monitor",
            "tenant_scope": {
                "organization_id": effective_org_id,
                "department_id": effective_dept_id,
                "applies_to_shared_activity_db": False,
            },
            "threats": threats,
        }
    except Exception as exc:
        logger.error("monitoring /threat-feed error: %s", exc)
        return {"available": False, "threats": [], "error": str(exc)}


# ---------------------------------------------------------------------------
# /trends  — background scan time-series
# ---------------------------------------------------------------------------

@router.get("/trends")
async def get_monitoring_trends(
    time_range: Optional[str] = Query("24h", description="Time range: 24h, 7d, 30d"),
    interval: Optional[int] = Query(None, description="Bucket size in minutes (auto if omitted)"),
    organization_id: Optional[int] = Query(default=None),
    department_id: Optional[int] = Query(default=None),
    current_user = Depends(require_permission("reports.read")),
):
    """Time-bucketed background scan counts for trend charting."""
    adb = _adb()
    if not adb:
        return {"available": False, "series": []}

    hours = _hours(time_range)
    interval_min = interval or (60 if hours <= 48 else 360 if hours <= 168 else 1440)
    effective_org_id, effective_dept_id = _monitoring_scope(current_user, organization_id, department_id)

    try:
        series = adb.get_scan_trends(hours=hours, interval_minutes=interval_min)
        return {
            "available": True,
            "time_range": _label(time_range),
            "interval_minutes": interval_min,
            "data_points": len(series),
            "tenant_scope": {
                "organization_id": effective_org_id,
                "department_id": effective_dept_id,
                "applies_to_shared_activity_db": False,
            },
            "series": series,
        }
    except Exception as exc:
        logger.error("monitoring /trends error: %s", exc)
        return {"available": False, "series": [], "error": str(exc)}


# ---------------------------------------------------------------------------
# /distribution  — threat type & verdict breakdown
# ---------------------------------------------------------------------------

@router.get("/distribution")
async def get_threat_distribution(
    time_range: Optional[str] = Query("24h", description="Time range: 24h, 7d, 30d"),
    organization_id: Optional[int] = Query(default=None),
    department_id: Optional[int] = Query(default=None),
    current_user = Depends(require_permission("reports.read")),
):
    """Threat type and verdict distribution for background-monitored artifacts."""
    adb = _adb()
    if not adb:
        return {"available": False}

    hours = _hours(time_range)
    effective_org_id, effective_dept_id = _monitoring_scope(current_user, organization_id, department_id)
    try:
        dist = adb.get_threat_distribution(hours=hours)
        return {
            "available": True,
            "time_range": _label(time_range),
            "generated_at": utcnow().isoformat() + "Z",
            "tenant_scope": {
                "organization_id": effective_org_id,
                "department_id": effective_dept_id,
                "applies_to_shared_activity_db": False,
            },
            **dist,
        }
    except Exception as exc:
        logger.error("monitoring /distribution error: %s", exc)
        return {"available": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# /summary  — activity database overview
# ---------------------------------------------------------------------------

@router.get("/summary")
async def get_activity_summary(
    time_range: Optional[str] = Query("24h", description="Time range: 24h, 7d, 30d"),
    organization_id: Optional[int] = Query(default=None),
    department_id: Optional[int] = Query(default=None),
    current_user = Depends(require_permission("reports.read")),
):
    """Full activity summary from the background monitoring database."""
    adb = _adb()
    if not adb:
        return {"available": False}

    hours = _hours(time_range)
    effective_org_id, effective_dept_id = _monitoring_scope(current_user, organization_id, department_id)
    try:
        summary = adb.get_activity_summary(hours=hours)
        return {
            "available": True,
            "time_range": _label(time_range),
            "tenant_scope": {
                "organization_id": effective_org_id,
                "department_id": effective_dept_id,
                "applies_to_shared_activity_db": False,
            },
            **summary,
        }
    except Exception as exc:
        logger.error("monitoring /summary error: %s", exc)
        return {"available": False, "error": str(exc)}
