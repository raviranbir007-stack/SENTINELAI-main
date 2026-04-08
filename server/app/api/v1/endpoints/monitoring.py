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
from ....models import SystemLog

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
    try:
        stats = adb.get_background_stats(hours=hours)
        return {
            "available": True,
            "time_range": _label(time_range),
            "generated_at": utcnow().isoformat() + "Z",
            "note": "These scans run locally — no external API quota consumed.",
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
    limit: int = Query(50, ge=1, le=200, description="Max entries to return"),
    db: AsyncSession = Depends(get_db),
):
    """
    Most recent background activity entries across all monitored artifact types.
    Each entry is classified by the local heuristics & ML engine.
    """
    adb = _adb()
    if not adb:
        return {"available": False, "items": []}

    try:
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
    limit: int = Query(50, ge=1, le=200, description="Max entries"),
    hours: int = Query(24, ge=1, le=720, description="Lookback window hours"),
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
        return {
            "available": True,
            "count": len(items),
            "generated_at": utcnow().isoformat() + "Z",
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
        return {
            "available": True,
            "count": len(threats),
            "generated_at": utcnow().isoformat() + "Z",
            "source": "background_auto_monitor",
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
):
    """Time-bucketed background scan counts for trend charting."""
    adb = _adb()
    if not adb:
        return {"available": False, "series": []}

    hours = _hours(time_range)
    interval_min = interval or (60 if hours <= 48 else 360 if hours <= 168 else 1440)

    try:
        series = adb.get_scan_trends(hours=hours, interval_minutes=interval_min)
        return {
            "available": True,
            "time_range": _label(time_range),
            "interval_minutes": interval_min,
            "data_points": len(series),
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
):
    """Threat type and verdict distribution for background-monitored artifacts."""
    adb = _adb()
    if not adb:
        return {"available": False}

    hours = _hours(time_range)
    try:
        dist = adb.get_threat_distribution(hours=hours)
        return {
            "available": True,
            "time_range": _label(time_range),
            "generated_at": utcnow().isoformat() + "Z",
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
):
    """Full activity summary from the background monitoring database."""
    adb = _adb()
    if not adb:
        return {"available": False}

    hours = _hours(time_range)
    try:
        summary = adb.get_activity_summary(hours=hours)
        return {
            "available": True,
            "time_range": _label(time_range),
            **summary,
        }
    except Exception as exc:
        logger.error("monitoring /summary error: %s", exc)
        return {"available": False, "error": str(exc)}
