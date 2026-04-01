from .auth import admin_required
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi import Request, APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import smtplib
from email.mime.text import MIMEText
import logging

from ....config import settings
from ....database import get_db

# Dependency to enforce only approved clients can access features
async def approved_client_required(request: Request, db: AsyncSession = Depends(get_db)):
    client_id = request.headers.get("X-Client-ID")
    if not client_id:
        raise HTTPException(status_code=401, detail="Missing client ID header")
    query = select(ClientInstallation).where(ClientInstallation.client_id == client_id)
    result = await db.execute(query)
    client = result.scalar_one_or_none()
    if not client or not client.is_active:
        raise HTTPException(status_code=403, detail="Client not approved or inactive")
    return client

logger = logging.getLogger(__name__)
router = APIRouter()

class ClientRegistrationRequest(BaseModel):
    hostname: str
    ip_address: str
    os_type: str
    version: str
    master_password: str

@router.post("/client/register")
async def register_client(request: ClientRegistrationRequest, db: AsyncSession = Depends(get_db)):
    # Check master password
    if request.master_password != settings.MASTER_CLIENT_PASSWORD:
        return JSONResponse({"success": False, "message": "Invalid master password."}, status_code=403)

    # Mark client as pending approval
    new_client = ClientInstallation(
        client_id=str(uuid.uuid4()),
        hostname=request.hostname,
        ip_address=request.ip_address,
        os_type=request.os_type,
        version=request.version,
        is_active=False  # Not active until admin approves
    )
    db.add(new_client)
    await db.commit()
    await db.refresh(new_client)

    # Notify admin (dashboard notification + email)
    _notify_admin_new_client(new_client)

    return JSONResponse({"success": True, "message": "Registration pending admin approval."})

def _notify_admin_new_client(client):
    # Email notification
    try:
        msg = MIMEText(f"New client registration request:\n\nHostname: {client.hostname}\nIP: {client.ip_address}\nOS: {client.os_type}\nVersion: {client.version}\n\nApprove in the admin dashboard.")
        msg["Subject"] = "SentinelAI: New Client Registration Request"
        msg["From"] = settings.FROM_EMAIL
        msg["To"] = settings.ADMIN_EMAIL
        with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
            server.starttls()
            if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.sendmail(settings.FROM_EMAIL, [settings.ADMIN_EMAIL], msg.as_string())
    except Exception as e:
        logger.warning(f"Failed to send admin email: {e}")
    # TODO: Add dashboard notification logic (frontend integration required)

# Admin approval endpoint
class ClientApprovalRequest(BaseModel):
    client_id: str
    approve: bool

@router.post("/client/approve")
async def approve_client(request: ClientApprovalRequest, db: AsyncSession = Depends(get_db)):
    query = select(ClientInstallation).where(ClientInstallation.client_id == request.client_id)
    result = await db.execute(query)
    client = result.scalar_one_or_none()
    if not client:
        return JSONResponse({"success": False, "message": "Client not found."}, status_code=404)
    if request.approve:
        client.is_active = True
        await db.commit()
        await db.refresh(client)
        return JSONResponse({"success": True, "message": "Client approved and activated."})
    else:
        await db.delete(client)
        await db.commit()
        return JSONResponse({"success": True, "message": "Client registration denied and removed."})
# --- Block & Shutdown and Resume endpoints (move from client_admin.py for correct routing) ---
from fastapi.responses import JSONResponse
from ..endpoints.auth import admin_required
# --- Block & Shutdown and Resume endpoints (move from client_admin.py for correct routing) ---
"""
Network Monitoring and Defense System
Tracks attacks across all client installations and implements defense mechanisms
"""

import asyncio
import hmac
import ipaddress
import json
import logging
import os
import re
import socket
import uuid
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import and_, func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ....database import execute_sqlite_write, get_db
from ....config import settings
from ....core.nids_ingestor import NIDSIngestor
from ....core.notifier import NotificationEngine
from ....core.security_telemetry import security_telemetry
from ....core.terminal_monitor import terminal_monitor
from ....models import (
    AttackEvent,
    ClientInstallation,
    DefenseAction,
    NetworkAlert,
    ScanHistory,
    SystemLog,
    ThreatSeverity,
)

logger = logging.getLogger(__name__)
router = APIRouter()

# --- Block & Shutdown and Resume endpoints (must be after router is defined) ---
from fastapi.responses import JSONResponse


from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

@router.post("/clients/{client_id}/block_shutdown")
async def block_and_shutdown_client(
    client_id: str,
    db: AsyncSession = Depends(get_db),
    request: Request = None,
):
    if request is not None:
        await _admin_or_blocked_in_safe_mode(request)
    logger.info(f"[BLOCK] Attempting to block client {client_id}")
    query = select(ClientInstallation).where(ClientInstallation.client_id == client_id)
    result = await db.execute(query)
    client = result.scalar_one_or_none()
    if not client:
        logger.error(f"[BLOCK] Client not found: {client_id}")
        return JSONResponse({"success": False, "message": "Client not found."}, status_code=404)
    client.protection_enabled = False
    await db.commit()
    await db.refresh(client)
    logger.info(f"[BLOCK] Client {client_id} protection_enabled set to {client.protection_enabled}")
    return JSONResponse({"success": True, "message": f"Client has been blocked and shut down. protection_enabled={client.protection_enabled}. This action is reversible via the Resume button."})

@router.post("/clients/{client_id}/resume")
async def resume_client(
    client_id: str,
    db: AsyncSession = Depends(get_db),
    request: Request = None,
):
    if request is not None:
        await _admin_or_blocked_in_safe_mode(request)
    logger.info(f"[RESUME] Attempting to resume client {client_id}")
    query = select(ClientInstallation).where(ClientInstallation.client_id == client_id)
    result = await db.execute(query)
    client = result.scalar_one_or_none()
    if not client:
        logger.error(f"[RESUME] Client not found: {client_id}")
        return JSONResponse({"success": False, "message": "Client not found."}, status_code=404)
    client.protection_enabled = True
    await db.commit()
    await db.refresh(client)
    logger.info(f"[RESUME] Client {client_id} protection_enabled set to {client.protection_enabled}")
    return JSONResponse({"success": True, "message": f"Client has been resumed and all features re-enabled. protection_enabled={client.protection_enabled}"})


_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_CLIENT_RUNTIME_STATE: dict[str, dict] = {}
_RUNTIME_STATE_TTL_SECONDS = 15 * 60
_ROLLBACK_TASKS: dict[str, asyncio.Task] = {}


def _client_safe_mode_enabled() -> bool:
    return os.getenv("SENTINEL_CLIENT_SAFE_DASHBOARD_MODE", "true").strip().lower() in {"1", "true", "yes", "on"}


def _registration_alert_recipients() -> list[str]:
    recipients = []
    for candidate in [settings.ADMIN_EMAIL, settings.ALERT_EMAIL, settings.SMTP_USERNAME]:
        if candidate:
            recipients.append(str(candidate).strip())

    extra = str(getattr(settings, "CLIENT_REGISTRATION_ALERT_EMAILS", "") or "")
    if extra:
        recipients.extend([p.strip() for p in extra.replace(";", ",").split(",") if p.strip()])

    normalized: list[str] = []
    seen = set()
    for item in recipients:
        if "@" not in item:
            continue
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(item)
    return normalized


def _request_origin_host_or_ip(request: Request) -> str:
    forwarded = str(request.headers.get("X-Forwarded-For", "") or "").strip()
    if forwarded:
        # trust first hop in standard X-Forwarded-For list
        return forwarded.split(",", 1)[0].strip()
    if request.client and request.client.host:
        return str(request.client.host).strip()
    return ""


def _request_is_admin_origin(request: Request) -> bool:
    origin = _request_origin_host_or_ip(request)
    if not origin:
        return False
    parsed_ip = _parse_ip(origin)
    if parsed_ip:
        return _is_admin_infrastructure_host("", parsed_ip)
    return _is_admin_infrastructure_host(origin, "")


async def _admin_or_blocked_in_safe_mode(request: Request):
    """Block management endpoints in client-safe mode unless explicit admin bypass is provided."""
    if not _client_safe_mode_enabled():
        return True

    if _request_is_admin_origin(request):
        return True

    expected_bypass = str(os.getenv("SENTINEL_ADMIN_BYPASS_KEY", "") or "").strip()
    provided_bypass = str(request.headers.get("X-Sentinel-Admin-Bypass", "") or "").strip()
    if expected_bypass and provided_bypass and hmac.compare_digest(expected_bypass, provided_bypass):
        return True

    raise HTTPException(
        status_code=403,
        detail="Client-safe mode blocks management endpoints. Use an admin backend session or provide X-Sentinel-Admin-Bypass.",
    )


def _normalize_hostname(value: str) -> str:
    host = str(value or "").strip().lower().rstrip(".")
    return host


def _parse_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except Exception:
        return ""


def _local_admin_host_markers() -> tuple[set[str], set[str]]:
    hosts: set[str] = set()
    ips: set[str] = set()

    for raw in [socket.gethostname(), socket.getfqdn()]:
        norm = _normalize_hostname(raw)
        if norm:
            hosts.add(norm)

    try:
        for raw in socket.gethostbyname_ex(socket.gethostname())[2] or []:
            parsed = _parse_ip(raw)
            if parsed:
                ips.add(parsed)
    except Exception:
        pass

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = _parse_ip(sock.getsockname()[0])
        sock.close()
        if local_ip:
            ips.add(local_ip)
    except Exception:
        pass

    ips.update({"127.0.0.1", "::1"})
    return hosts, ips


def _is_admin_infrastructure_host(hostname: str, ip_address: str) -> bool:
    configured_hosts = {_normalize_hostname(v) for v in settings.admin_infra_hostnames_list}
    configured_ips = {_parse_ip(v) for v in settings.admin_infra_ips_list}
    configured_ips = {v for v in configured_ips if v}

    local_hosts, local_ips = _local_admin_host_markers()
    host = _normalize_hostname(hostname)
    ip = _parse_ip(ip_address)

    if host and (host in configured_hosts or host in local_hosts):
        return True
    if ip and (ip in configured_ips or ip in local_ips):
        return True
    return False


def _extract_runtime_identity(status_payload: Optional[dict]) -> dict:
    """Extract lightweight runtime identity metadata from heartbeat status payload."""
    if not isinstance(status_payload, dict):
        return {}

    session = status_payload.get("session") if isinstance(status_payload.get("session"), dict) else {}
    raw_user = (
        session.get("os_user")
        or status_payload.get("current_os_user")
        or status_payload.get("os_user")
        or status_payload.get("user")
    )

    os_user = _sanitize_response_text(raw_user, max_len=80)
    if os_user:
        os_user = re.sub(r"[^A-Za-z0-9_.@-]", "", os_user)

    uid_value = session.get("uid") if "uid" in session else status_payload.get("uid")
    try:
        uid_value = int(uid_value) if uid_value is not None else None
    except Exception:
        uid_value = None

    data = {
        "current_os_user": os_user or None,
        "current_os_uid": uid_value,
        "updated_at": datetime.utcnow().isoformat(),
    }
    if not data["current_os_user"] and data["current_os_uid"] is None:
        return {}
    return data


def _get_fresh_runtime_identity(client_id: str) -> dict:
    runtime = _CLIENT_RUNTIME_STATE.get(client_id) or {}
    if not runtime:
        return {}

    try:
        updated_at = datetime.fromisoformat(str(runtime.get("updated_at")))
        if (datetime.utcnow() - updated_at).total_seconds() > _RUNTIME_STATE_TTL_SECONDS:
            return {}
    except Exception:
        return {}
    return runtime


def _should_auto_block(severity: ThreatSeverity, confidence: float) -> bool:
    """Policy gate for automatic blocking actions."""
    min_sev = str(getattr(settings, "SENTINEL_AUTO_BLOCK_MIN_SEVERITY", "high") or "high").strip().lower()
    min_required = _SEVERITY_ORDER.get(min_sev, 3)
    cur = _SEVERITY_ORDER.get(str(severity.value).lower(), 1)
    if cur < min_required:
        return False
    min_conf = float(getattr(settings, "SENTINEL_MANUAL_REVIEW_MIN_CONFIDENCE", 0.65) or 0.65)
    return float(confidence or 0.0) >= min_conf


class ClientRegistrationRequest(BaseModel):
    """Request model for client registration"""

    hostname: str
    ip_address: str
    mac_address: Optional[str] = None
    os_type: str
    os_version: Optional[str] = None
    network_segment: Optional[str] = None
    gateway: Optional[str] = None
    dns_servers: Optional[List[str]] = None
    version: str = "1.0.0"


class AttackReportRequest(BaseModel):
    """Request model for reporting an attack"""

    client_id: str
    attack_type: str
    source_ip: Optional[str] = None
    source_domain: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    severity: str = "medium"
    description: Optional[str] = None
    indicators: Optional[dict] = None
    confidence: Optional[float] = None


class DefenseActionRequest(BaseModel):
    """Request model for defense action"""

    action_type: str  # block_ip, block_domain, quarantine_file, alert_admin
    target: str
    client_id: Optional[str] = None
    attack_event_id: Optional[str] = None
    details: Optional[dict] = None


class DefenseEventRequest(BaseModel):
    """Generic event stream from endpoint agents and monitor modules."""

    client_id: Optional[str] = None
    event: str
    attack_id: Optional[str] = None
    attack: Optional[dict] = None
    severity: Optional[str] = None
    risk: Optional[str] = None
    alert_number: Optional[int] = None
    max_alerts: Optional[int] = None
    user_initiated: Optional[bool] = None
    source_ip: Optional[str] = None
    source_domain: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    description: Optional[str] = None
    reason: Optional[str] = None
    details: Optional[dict] = None
    monitor_event: Optional[dict] = None
    timestamp: Optional[str] = None


class ClientHeartbeatRequest(BaseModel):
    """Optional client heartbeat payload with module status snapshot."""

    status: Optional[dict] = None
    timestamp: Optional[str] = None


class DefenseEventResponseRequest(BaseModel):
    """Analyst/operator response to an active attack prompt."""

    action: str  # BLOCK | IGNORE | QUARANTINE
    client_id: Optional[str] = None
    attack_id: Optional[str] = None
    event_id: Optional[str] = None
    target: Optional[str] = None
    target_type: Optional[str] = None
    reason: Optional[str] = None
    metadata: Optional[dict] = None


class NIDSBatchIngestRequest(BaseModel):
    """Batch ingest request for Suricata EVE / Zeek logs."""

    source: str  # suricata | zeek
    records: List[dict]
    client_id: Optional[str] = None
    zeek_log_type: str = "conn"


class ReplayScenarioRequest(BaseModel):
    event: str
    severity: str = "medium"
    payload: dict = {}
    client_id: Optional[str] = None
    source_ip: Optional[str] = None


class ReplayBatchRequest(BaseModel):
    scenarios: List[ReplayScenarioRequest]


def _map_text_severity(value: Optional[str]) -> ThreatSeverity:
    raw = (value or "").strip().lower()
    if raw in {"critical", "p1", "sev1"}:
        return ThreatSeverity.CRITICAL
    if raw in {"high", "sev2"}:
        return ThreatSeverity.HIGH
    if raw in {"medium", "moderate", "sev3", "suspicious"}:
        return ThreatSeverity.MEDIUM
    return ThreatSeverity.LOW


def _is_security_event(event_name: str) -> bool:
    lowered = (event_name or "").lower()
    return any(
        token in lowered
        for token in [
            "attack",
            "threat",
            "alert",
            "malicious",
            "suspicious",
            "intrusion",
            "quarantine",
            "brute",
            "sql",
            "sqli",
            "nmap",
            "metasploit",
            "scan",
            "exploit",
            "phishing",
            "dns",
            "usb",
            "process",
        ]
    )


def _merge_event_payload(request: DefenseEventRequest) -> dict:
    payload: dict = {}
    if isinstance(request.monitor_event, dict):
        payload.update(request.monitor_event)
    if isinstance(request.attack, dict):
        payload.update(request.attack)
    if isinstance(request.details, dict):
        for key, value in request.details.items():
            payload.setdefault(key, value)
    return payload


def _sanitize_external_event_id(raw_value: Optional[str]) -> Optional[str]:
    if not raw_value:
        return None
    cleaned = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in str(raw_value))
    cleaned = cleaned.strip("_")
    return cleaned[:100] if cleaned else None


def _log_level_for_event(
    event_kind: str,
    severity: ThreatSeverity,
    alert_number: Optional[int] = None,
    max_alerts: Optional[int] = None,
) -> str:
    lowered = (event_kind or "").lower()
    if "quarantine" in lowered or lowered in {"system_quarantined", "quarantine_activated"}:
        return "CRITICAL"
    if alert_number and max_alerts and alert_number >= max_alerts:
        return "CRITICAL"
    if severity == ThreatSeverity.CRITICAL:
        return "CRITICAL"
    if severity == ThreatSeverity.HIGH or "alert" in lowered or "attack" in lowered:
        return "WARNING"
    return "INFO"


def _status_from_event(event_kind: str, default_status: str = "detected") -> str:
    lowered = (event_kind or "").lower()
    if "quarantine" in lowered:
        return "quarantined"
    if "block" in lowered:
        return "blocked"
    if "ignore" in lowered:
        return "ignored"
    if lowered in {"attack_alert", "threat_alert"}:
        return default_status
    return default_status


def _derive_target_type(target: Optional[str], explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    if not target:
        return "indicator"
    target_text = str(target)
    if "." in target_text and all(part.isdigit() for part in target_text.replace(":", ".").split(".") if part):
        return "ip"
    if "." in target_text and any(ch.isalpha() for ch in target_text):
        return "domain"
    return "indicator"


def _sanitize_response_text(value: Optional[str], max_len: int = 512) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    return text[:max_len]


def _sanitize_response_metadata(metadata: Optional[dict], max_items: int = 24) -> dict:
    if not isinstance(metadata, dict):
        return {}
    sanitized: dict = {}
    for idx, (raw_key, raw_val) in enumerate(metadata.items()):
        if idx >= max_items:
            break
        key = _sanitize_response_text(raw_key, max_len=64)
        if not key:
            continue
        if isinstance(raw_val, (str, int, float, bool)) or raw_val is None:
            sanitized[key] = raw_val if not isinstance(raw_val, str) else _sanitize_response_text(raw_val, max_len=512)
        elif isinstance(raw_val, dict):
            sanitized[key] = _sanitize_response_metadata(raw_val, max_items=12)
        elif isinstance(raw_val, list):
            compact_list = []
            for item in raw_val[:12]:
                if isinstance(item, (str, int, float, bool)) or item is None:
                    compact_list.append(item if not isinstance(item, str) else _sanitize_response_text(item, max_len=256))
            sanitized[key] = compact_list
    return sanitized


def _extract_corroboration_sources(payload: dict) -> set[str]:
    """Extract independent evidence sources from endpoint event payload."""
    sources: set[str] = set()
    if not isinstance(payload, dict):
        return sources

    raw_candidates = []
    for key in ["source", "module", "detector", "engine", "artifact_type"]:
        if payload.get(key):
            raw_candidates.append(payload.get(key))

    for key in ["signals", "source_modules", "evidence_sources", "matched_rules"]:
        value = payload.get(key)
        if isinstance(value, list):
            raw_candidates.extend(value)

    for item in raw_candidates:
        normalized = _sanitize_response_text(item, max_len=64)
        if normalized:
            sources.add(normalized.lower())
    return sources


def _estimate_event_confidence(payload: dict, severity: ThreatSeverity, event_name: str, event_kind: str) -> float:
    """Estimate confidence from severity + payload richness for safer event promotion."""
    base_map = {
        ThreatSeverity.CRITICAL: 0.90,
        ThreatSeverity.HIGH: 0.78,
        ThreatSeverity.MEDIUM: 0.58,
        ThreatSeverity.LOW: 0.38,
    }
    score = float(base_map.get(severity, 0.50))

    if isinstance(payload, dict):
        if payload.get("ioc") or payload.get("iocs"):
            score += 0.05
        if payload.get("rule_id") or payload.get("signature"):
            score += 0.06
        if payload.get("matched_rules"):
            score += 0.05
        if payload.get("confidence") is not None:
            try:
                score = max(score, min(1.0, float(payload.get("confidence"))))
            except Exception:
                pass

    lower_blob = f"{event_name} {event_kind}".lower()
    if any(token in lower_blob for token in ["metasploit", "rce", "exploit", "brute", "quarantine"]):
        score += 0.05

    return max(0.0, min(1.0, score))


def _apply_behavior_baseline_adjustment(client_id: Optional[str], artifact_type: str, count_in_window: int, base_confidence: float) -> tuple[float, dict]:
    """Adjust confidence using per-client behavioral baselines to reduce false alerts."""
    if not client_id:
        return float(base_confidence), {"available": False}
    try:
        principal = f"client:{client_id}"
        baseline = security_telemetry.baseline_anomaly_score(
            principal=principal,
            artifact_type=str(artifact_type or "defense_event")[:80],
            count_in_window=max(0, int(count_in_window)),
        )
        z = float(baseline.get("z_score", 0.0) or 0.0)
        adjusted = float(base_confidence)
        # Normal repeated behavior should slightly reduce confidence escalation.
        if z <= -0.5:
            adjusted -= 0.05
        elif z <= 0.5:
            adjusted -= 0.02
        # Significant behavioral spike should increase confidence.
        elif z >= 3.5:
            adjusted += 0.10
        elif z >= 2.5:
            adjusted += 0.06
        elif z >= 1.5:
            adjusted += 0.03
        return max(0.0, min(1.0, adjusted)), {
            "available": True,
            "z_score": round(z, 3),
            "mean": round(float(baseline.get("mean", 0.0) or 0.0), 3),
            "std": round(float(baseline.get("std", 1.0) or 1.0), 3),
            "sample_count": int(float(baseline.get("sample_count", 0.0) or 0.0)),
            "anomalous": bool(float(baseline.get("anomalous", 0.0) or 0.0) >= 1.0),
        }
    except Exception as exc:
        logger.debug("Baseline adjustment unavailable for %s: %s", client_id, exc)
        return float(base_confidence), {"available": False, "error": str(exc)}


async def _auto_revert_after_window(action_id: str, delay_seconds: int) -> None:
    """Rollback temporary block rules after safety window when still active."""
    try:
        await asyncio.sleep(max(1, int(delay_seconds)))
        with execute_sqlite_write() as cursor:
            cursor.execute(
                """
                SELECT action_id, action_type, target, status
                FROM defense_actions
                WHERE action_id = ?
                """,
                (action_id,),
            )
            row = cursor.fetchone()
            if not row:
                return
            orig_action_id, action_type, target, status = row
            if str(status or "").lower() != "executed":
                return
            if str(action_type or "").lower() not in {"block_ip", "block_domain"}:
                return

            revert_type = "unblock_ip" if action_type == "block_ip" else "unblock_domain"
            rollback_id = f"DEF_{uuid.uuid4().hex[:12].upper()}"
            details = json.dumps(
                {
                    "rollback_of": orig_action_id,
                    "reason": "automatic safety-window rollback",
                    "delay_seconds": int(delay_seconds),
                }
            )
            cursor.execute(
                """
                INSERT INTO defense_actions(action_id, action_type, target, details, status, successful, executed_at)
                VALUES (?, ?, ?, ?, 'executed', 1, CURRENT_TIMESTAMP)
                """,
                (rollback_id, revert_type, target, details),
            )
            cursor.execute(
                """
                UPDATE defense_actions
                SET status = 'reverted', reverted_at = CURRENT_TIMESTAMP
                WHERE action_id = ?
                """,
                (orig_action_id,),
            )
    except Exception as exc:
        logger.warning("Auto rollback failed for %s: %s", action_id, exc)
    finally:
        _ROLLBACK_TASKS.pop(action_id, None)


def _schedule_auto_rollback(action_id: str, delay_seconds: int) -> None:
    if not action_id:
        return
    existing = _ROLLBACK_TASKS.get(action_id)
    if existing and not existing.done():
        return
    _ROLLBACK_TASKS[action_id] = asyncio.create_task(_auto_revert_after_window(action_id, delay_seconds))


@router.post("/client/register")
async def register_client(request: ClientRegistrationRequest, db: AsyncSession = Depends(get_db)):
    """
    Register a new client installation or update existing one
    """
    try:
        if _is_admin_infrastructure_host(request.hostname, request.ip_address):
            return {
                "status": "admin_infrastructure",
                "message": "Host is designated as admin infrastructure and excluded from client inventory",
                "client_scope": {
                    "role": "admin_infrastructure",
                    "excluded_from_client_inventory": True,
                },
            }

        # Check if client already exists (by IP or hostname)
        query = select(ClientInstallation).where(
            or_(
                ClientInstallation.ip_address == request.ip_address,
                ClientInstallation.hostname == request.hostname,
            )
        )
        result = await db.execute(query)
        existing_client = result.scalar_one_or_none()

        if existing_client:
            # Update existing client (do NOT reset protection_enabled)
            existing_client.last_seen = datetime.utcnow()
            existing_client.is_active = True
            existing_client.version = request.version
            existing_client.os_version = request.os_version or existing_client.os_version
            # DO NOT reset protection_enabled here!
            await db.commit()
            await db.refresh(existing_client)

            return {
                "status": "updated",
                "client_id": existing_client.client_id,
                "message": "Client registration updated",
            }
        else:
            # Create new client
            client_id = f"CLIENT_{uuid.uuid4().hex[:12].upper()}"

            new_client = ClientInstallation(
                client_id=client_id,
                hostname=request.hostname,
                ip_address=request.ip_address,
                mac_address=request.mac_address,
                os_type=request.os_type,
                os_version=request.os_version,
                network_segment=request.network_segment,
                gateway=request.gateway,
                dns_servers=request.dns_servers or [],
                version=request.version,
                protection_enabled=True,
                blocked_ips=[],
                blocked_domains=[],
            )

            db.add(new_client)
            await db.commit()
            await db.refresh(new_client)

            logger.info("New client registered from hostname=%s ip=%s", request.hostname, request.ip_address)

            # ── Email alert: new client enrolled ──────────────────────────
            recipients = _registration_alert_recipients()
            if recipients:
                _now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                _subj = f"SENTINEL-AI: New Client Enrolled — {request.hostname}"
                _body = (
                    "<div style='font-family:Inter,system-ui,sans-serif;max-width:580px;"
                    "margin:0 auto;background:#070b12;border:1px solid #22324a;"
                    "border-radius:10px;overflow:hidden'>"
                    "<div style='background:#0e1522;padding:16px 22px;"
                    "border-bottom:3px solid #14b8a6'>"
                    "<h2 style='margin:0;color:#14b8a6;font-size:1rem;font-weight:700'>"
                    "🖥️&nbsp; SENTINEL-AI &mdash; New Client Enrolled</h2>"
                    "</div>"
                    "<div style='padding:20px 22px;color:#e6f0ff;font-size:0.9rem;line-height:1.6'>"
                    "<p style='margin-top:0'>A new endpoint has successfully registered with "
                    "the SENTINEL-AI protection network and real-time protection is now active.</p>"
                    "<table style='width:100%;border-collapse:collapse;background:#0a1525;"
                    "border-radius:8px;overflow:hidden;margin-bottom:14px'>"
                    f"<tr style='border-bottom:1px solid #22324a'>"
                    f"<td style='padding:10px 14px;color:#8ea3c0;font-size:0.82rem;width:140px'>Client ID</td>"
                    f"<td style='padding:10px 14px;font-family:monospace;color:#86efac'>{client_id}</td></tr>"
                    f"<tr style='border-bottom:1px solid #22324a'>"
                    f"<td style='padding:10px 14px;color:#8ea3c0;font-size:0.82rem'>Hostname</td>"
                    f"<td style='padding:10px 14px'>{request.hostname}</td></tr>"
                    f"<tr style='border-bottom:1px solid #22324a'>"
                    f"<td style='padding:10px 14px;color:#8ea3c0;font-size:0.82rem'>IP Address</td>"
                    f"<td style='padding:10px 14px;font-family:monospace'>{request.ip_address}</td></tr>"
                    f"<tr style='border-bottom:1px solid #22324a'>"
                    f"<td style='padding:10px 14px;color:#8ea3c0;font-size:0.82rem'>Operating System</td>"
                    f"<td style='padding:10px 14px'>{request.os_type}"
                    f"{' &mdash; ' + request.os_version if request.os_version else ''}</td></tr>"
                    f"<tr style='border-bottom:1px solid #22324a'>"
                    f"<td style='padding:10px 14px;color:#8ea3c0;font-size:0.82rem'>Agent Version</td>"
                    f"<td style='padding:10px 14px'>{request.version}</td></tr>"
                    f"<tr>"
                    f"<td style='padding:10px 14px;color:#8ea3c0;font-size:0.82rem'>Enrolled At</td>"
                    f"<td style='padding:10px 14px'>{_now} UTC</td></tr>"
                    "</table>"
                    "<p style='margin:0;color:#8ea3c0;font-size:0.82rem'>"
                    "View and manage all enrolled clients from the Active Clients section of the SENTINEL-AI Dashboard."
                    "</p></div></div>"
                )
                asyncio.create_task(
                    NotificationEngine.send_email(recipients, _subj, _body)
                )
            # ──────────────────────────────────────────────────────────────

            return {
                "status": "registered",
                "client_id": client_id,
                "client_scope": {
                    "can_send": ["heartbeat", "attack_report", "defense_events"],
                    "cannot_access": [
                        "client_management",
                        "admin_controls",
                        "api_key_configuration",
                        "other_client_inventory",
                    ],
                },
                "message": "Client successfully registered",
            }

    except Exception as e:
        logger.error(f"Client registration failed: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@router.post("/client/heartbeat")
async def client_heartbeat(
    client_id: str,
    request: Optional[ClientHeartbeatRequest] = None,
    db: AsyncSession = Depends(get_db),
    client=Depends(approved_client_required),
):
    """
    Update client last_seen timestamp (heartbeat)
    """
    try:
        notify_quarantine: dict = {}
        runtime_identity: dict = {}

        async def _persist_heartbeat():
            nonlocal runtime_identity
            query = select(ClientInstallation).where(ClientInstallation.client_id == client_id)
            result = await db.execute(query)
            client = result.scalar_one_or_none()

            if not client:
                raise HTTPException(status_code=404, detail="Client not found")

            client.last_seen = datetime.utcnow()
            client.is_active = True
            # DO NOT reset protection_enabled here!

            heartbeat_status = request.status if request and isinstance(request.status, dict) else {}
            runtime_identity = _extract_runtime_identity(heartbeat_status)
            defense_state = heartbeat_status.get("defense_coordinator") if isinstance(heartbeat_status, dict) else {}
            if isinstance(defense_state, dict):
                is_quarantined = bool(defense_state.get("is_quarantined"))
                active_attacks = int(defense_state.get("active_attacks") or 0)
                if is_quarantined or active_attacks > 0:
                    signature = {
                        "client_id": client_id,
                        "is_quarantined": is_quarantined,
                        "active_attacks": active_attacks,
                    }
                    recent_log_query = (
                        select(SystemLog)
                        .where(SystemLog.component == "client_heartbeat")
                        .order_by(SystemLog.timestamp.desc())
                        .limit(5)
                    )
                    recent_result = await db.execute(recent_log_query)
                    recent_logs = recent_result.scalars().all()

                    should_log = True
                    cutoff = datetime.utcnow() - timedelta(minutes=2)
                    for row in recent_logs:
                        details = row.details or {}
                        if details.get("state_signature") == signature and (row.timestamp or cutoff) >= cutoff:
                            should_log = False
                            break

                    if should_log:
                        db.add(
                            SystemLog(
                                log_level="CRITICAL" if is_quarantined else "WARNING",
                                component="client_heartbeat",
                                message=(
                                    f"Client heartbeat indicates {'quarantine active' if is_quarantined else 'active attack pressure'} "
                                    f"for {client_id}"
                                ),
                                details={
                                    "client_id": client_id,
                                    "state_signature": signature,
                                    "status": heartbeat_status,
                                    "timestamp": request.timestamp if request else None,
                                },
                            )
                        )
                        if is_quarantined:
                            notify_quarantine.update(
                                {
                                    "client_id": client_id,
                                    "hostname": client.hostname,
                                    "ip_address": client.ip_address,
                                    "active_attacks": active_attacks,
                                    "timestamp": request.timestamp if request else None,
                                }
                            )
            await db.commit()
            return client.last_seen.isoformat()

        last_seen = await execute_sqlite_write(
            db,
            f"heartbeat update for {client_id}",
            _persist_heartbeat,
            max_attempts=5,
            base_delay=0.2,
        )

        if runtime_identity:
            _CLIENT_RUNTIME_STATE[client_id] = runtime_identity

        if notify_quarantine and settings.ALERT_EMAIL:
            subject = f"SENTINEL-AI Alert: Quarantine active on {notify_quarantine.get('hostname') or client_id}"
            body = (
                "<h3>SENTINEL-AI Quarantine Alert</h3>"
                f"<p><strong>Client ID:</strong> {notify_quarantine.get('client_id')}</p>"
                f"<p><strong>Hostname:</strong> {notify_quarantine.get('hostname')}</p>"
                f"<p><strong>IP:</strong> {notify_quarantine.get('ip_address')}</p>"
                f"<p><strong>Active attacks:</strong> {notify_quarantine.get('active_attacks')}</p>"
                f"<p><strong>Timestamp:</strong> {notify_quarantine.get('timestamp') or datetime.utcnow().isoformat()}</p>"
            )
            sent = await NotificationEngine.send_email(settings.ALERT_EMAIL, subject, body)
            if not sent:
                logger.warning("Quarantine email alert failed for client %s", client_id)

        return {"status": "ok", "last_seen": last_seen}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Heartbeat failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/client/approve")
async def approve_client(
    request: ClientApprovalRequest,
    db: AsyncSession = Depends(get_db),
    _gate=Depends(_admin_or_blocked_in_safe_mode),
):
    """Approve or deny pending client registrations (admin-managed endpoint)."""
    query = select(ClientInstallation).where(ClientInstallation.client_id == request.client_id)
    result = await db.execute(query)
    client = result.scalar_one_or_none()
    if not client:
        return JSONResponse({"success": False, "message": "Client not found."}, status_code=404)

    if request.approve:
        client.is_active = True
        await db.commit()
        await db.refresh(client)
        return JSONResponse({"success": True, "message": "Client approved and activated."})

    await db.delete(client)
    await db.commit()
    return JSONResponse({"success": True, "message": "Client registration denied and removed."})


@router.get("/clients")
async def list_clients(
    active_only: bool = True,
    db: AsyncSession = Depends(get_db),
    # user=Depends(admin_required),  # Bypassed for development
):
    """
    List all client installations
    """
    try:
        if active_only:
            # Only show clients seen in last 10 minutes and marked active
            cutoff_time = datetime.utcnow() - timedelta(minutes=10)
            query = select(ClientInstallation).where(
                and_(ClientInstallation.is_active == True, ClientInstallation.last_seen >= cutoff_time)
            )
        else:
            # Show ALL clients, regardless of is_active or last_seen
            query = select(ClientInstallation)

        query = query.order_by(ClientInstallation.last_seen.desc())
        result = await db.execute(query)
        clients = result.scalars().all()

        clients_payload = []
        identified_users = set()

        for c in clients:
            if _is_admin_infrastructure_host(c.hostname, c.ip_address):
                continue

            runtime_identity = _get_fresh_runtime_identity(c.client_id)
            current_user = runtime_identity.get("current_os_user")
            if current_user:
                identified_users.add(current_user)

            clients_payload.append(
                {
                    "client_id": c.client_id,
                    "hostname": c.hostname,
                    "ip_address": c.ip_address,
                    "os_type": c.os_type,
                    "network_segment": c.network_segment,
                    "version": c.version,
                    "last_seen": c.last_seen.isoformat() if c.last_seen else None,
                    "protection_enabled": c.protection_enabled,
                    "blocked_ips_count": len(c.blocked_ips) if c.blocked_ips else 0,
                    "blocked_domains_count": len(c.blocked_domains) if c.blocked_domains else 0,
                    "current_os_user": current_user,
                    "current_os_uid": runtime_identity.get("current_os_uid"),
                    "runtime_identity_updated_at": runtime_identity.get("updated_at"),
                }
            )

        local_hosts, local_ips = _local_admin_host_markers()
        configured_hosts = {_normalize_hostname(v) for v in settings.admin_infra_hostnames_list}
        configured_hosts = {h for h in configured_hosts if h}
        configured_ips = {_parse_ip(v) for v in settings.admin_infra_ips_list}
        configured_ips = {i for i in configured_ips if i}
        admin_hosts = sorted(configured_hosts.union(local_hosts))
        admin_ips = sorted(configured_ips.union(local_ips))

        return {
            "total": len(clients_payload),
            "identified_active_users_count": len(identified_users),
            "identified_active_users": sorted(identified_users),
            "clients": clients_payload,
            "admin_infrastructure": {
                "hostnames": admin_hosts,
                "ips": admin_ips,
                "primary_ip": next((ip for ip in admin_ips if ip not in {"127.0.0.1", "::1"}), admin_ips[0] if admin_ips else None),
            },
            "server_time": datetime.utcnow().isoformat() + "Z",
        }

    except Exception as e:
        logger.error(f"Failed to list clients: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/attack/report")
async def report_attack(
    request: AttackReportRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    client=Depends(approved_client_required),
):
    """
    Report an attack detected on a client
    Automatically triggers defense mechanisms and network-wide alerts
    """
    try:
        # Verify client exists
        query = select(ClientInstallation).where(ClientInstallation.client_id == request.client_id)
        result = await db.execute(query)
        client = result.scalar_one_or_none()

        if not client:
            raise HTTPException(status_code=404, detail="Client not found")

        # Create attack event
        event_id = f"ATK_{uuid.uuid4().hex[:12].upper()}"

        severity_map = {
            "low": ThreatSeverity.LOW,
            "medium": ThreatSeverity.MEDIUM,
            "high": ThreatSeverity.HIGH,
            "critical": ThreatSeverity.CRITICAL,
        }

        base_confidence = float(
            request.confidence
            if request.confidence is not None
            else {
                "critical": 0.92,
                "high": 0.82,
                "medium": 0.62,
                "low": 0.40,
            }.get(request.severity.lower(), 0.62)
        )

        recent_cutoff = datetime.utcnow() - timedelta(minutes=10)
        recent_query = (
            select(func.count(AttackEvent.id))
            .where(AttackEvent.target_client_id == client.id)
            .where(AttackEvent.detected_at >= recent_cutoff)
        )
        recent_result = await db.execute(recent_query)
        recent_count = int(recent_result.scalar() or 0) + 1

        adjusted_confidence, baseline_meta = _apply_behavior_baseline_adjustment(
            client_id=request.client_id,
            artifact_type=str(request.attack_type or "attack"),
            count_in_window=recent_count,
            base_confidence=base_confidence,
        )

        attack = AttackEvent(
            event_id=event_id,
            attack_type=request.attack_type,
            source_ip=request.source_ip,
            source_domain=request.source_domain,
            destination_ip=request.destination_ip,
            destination_port=request.destination_port,
            severity=severity_map.get(request.severity.lower(), ThreatSeverity.MEDIUM),
            confidence=adjusted_confidence,
            description=request.description,
            indicators={
                **(request.indicators or {}),
                "baseline_adjustment": baseline_meta,
                "baseline_recent_event_count_10m": recent_count,
                "base_confidence": round(base_confidence, 3),
                "adjusted_confidence": round(adjusted_confidence, 3),
            },
            status="detected",
            target_client_id=client.id,
        )

        db.add(attack)
        await db.commit()
        await db.refresh(attack)

        logger.warning(
            f"Attack reported: {event_id} - {request.attack_type} on {client.hostname} from {request.source_ip}"
        )

        # Trigger defense mechanisms in background
        background_tasks.add_task(
            _execute_defense_response, attack.id, request.client_id, request.source_ip, db
        )

        # Check for network-wide attack patterns
        background_tasks.add_task(_check_network_attack_patterns, request.attack_type, request.source_ip, db)

        return {
            "status": "reported",
            "event_id": event_id,
            "message": "Attack reported and defense mechanisms triggered",
            "severity": request.severity,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Attack report failed: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/defense/action")
async def execute_defense_action(
    request: DefenseActionRequest,
    db: AsyncSession = Depends(get_db),
    _gate=Depends(_admin_or_blocked_in_safe_mode),
):
    """
    Execute a defense action (block IP, block domain, quarantine file, etc.)
    """
    try:
        action_id = f"DEF_{uuid.uuid4().hex[:12].upper()}"

        # Get client if specified
        client_id_fk = None
        if request.client_id:
            query = select(ClientInstallation).where(ClientInstallation.client_id == request.client_id)
            result = await db.execute(query)
            client = result.scalar_one_or_none()
            if client:
                client_id_fk = client.id

        # Get attack event if specified
        attack_id_fk = None
        if request.attack_event_id:
            query = select(AttackEvent).where(AttackEvent.event_id == request.attack_event_id)
            result = await db.execute(query)
            attack = result.scalar_one_or_none()
            if attack:
                attack_id_fk = attack.id

        action = DefenseAction(
            action_id=action_id,
            action_type=request.action_type,
            target=request.target,
            details=request.details or {},
            status="pending",
            attack_event_id=attack_id_fk,
            client_id=client_id_fk,
        )

        db.add(action)
        await db.commit()
        await db.refresh(action)

        # Execute the action based on type
        success = await _apply_defense_action(action, db)

        action.status = "executed" if success else "failed"
        action.successful = success
        action.executed_at = datetime.utcnow()

        if success and request.action_type in {"block_ip", "block_domain"}:
            req_details = request.details if isinstance(request.details, dict) else {}
            rollback_seconds = int(
                req_details.get("temporary_seconds")
                or req_details.get("rollback_in_seconds")
                or getattr(settings, "SENTINEL_TEMP_BLOCK_ROLLBACK_SECONDS", 900)
                or 900
            )
            disable_rollback = bool(req_details.get("disable_auto_rollback"))
            if not disable_rollback and rollback_seconds > 0:
                action.details = {
                    **(action.details if isinstance(action.details, dict) else {}),
                    "rollback_in_seconds": rollback_seconds,
                    "auto_rollback_enabled": True,
                }
                _schedule_auto_rollback(action.action_id, rollback_seconds)

        await db.commit()

        logger.info(f"Defense action {action_id}: {request.action_type} on {request.target} - {'Success' if success else 'Failed'}")

        return {
            "action_id": action_id,
            "status": action.status,
            "successful": success,
            "message": f"Defense action {'executed' if success else 'failed'}",
        }

    except Exception as e:
        logger.error(f"Defense action failed: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/event")
async def ingest_defense_event(request: DefenseEventRequest, db: AsyncSession = Depends(get_db)):
    """
    Ingest endpoint monitor events and convert high-confidence events into
    attack records + actionable network alerts.
    """
    try:
        payload = _merge_event_payload(request)
        event_kind = request.event or payload.get("event") or "unknown_event"
        event_name = payload.get("type") or payload.get("attack_type") or event_kind or "unknown_event"
        risk_text = payload.get("risk") or payload.get("severity") or request.risk or request.severity
        severity = _map_text_severity(risk_text)

        source_ip = payload.get("source_ip") or payload.get("remote_ip") or request.source_ip
        source_domain = payload.get("source_domain") or payload.get("domain") or request.source_domain
        destination_ip = payload.get("destination_ip") or request.destination_ip
        destination_port = payload.get("destination_port") or request.destination_port
        description = (
            payload.get("description")
            or request.description
            or request.reason
            or f"Endpoint event: {event_name}"
        )
        attack_identifier = request.attack_id or payload.get("attack_id") or payload.get("event_id")
        external_event_id = _sanitize_external_event_id(attack_identifier)
        event_log_level = _log_level_for_event(event_kind, severity, request.alert_number, request.max_alerts)
        corroboration_sources = _extract_corroboration_sources(payload)
        corroboration_count = len(corroboration_sources)
        computed_confidence = _estimate_event_confidence(payload, severity, event_name, event_kind)

        # Resolve client foreign key (optional)
        client_fk = None
        if request.client_id:
            q = select(ClientInstallation).where(ClientInstallation.client_id == request.client_id)
            r = await db.execute(q)
            client = r.scalar_one_or_none()
            if client:
                client_fk = client.id

        recent_baseline_count = 1
        if client_fk:
            recent_cutoff = datetime.utcnow() - timedelta(minutes=10)
            recent_q = (
                select(func.count(AttackEvent.id))
                .where(AttackEvent.target_client_id == client_fk)
                .where(AttackEvent.detected_at >= recent_cutoff)
            )
            recent_r = await db.execute(recent_q)
            recent_baseline_count = int(recent_r.scalar() or 0) + 1
        adjusted_confidence, baseline_meta = _apply_behavior_baseline_adjustment(
            client_id=request.client_id,
            artifact_type=str(event_name or event_kind or "defense_event"),
            count_in_window=recent_baseline_count,
            base_confidence=computed_confidence,
        )
        computed_confidence = adjusted_confidence

        # Always persist raw event in structured system log
        db.add(
            SystemLog(
                log_level=event_log_level,
                component="defense_event",
                message=f"{event_kind}: {event_name} - {description}",
                details={
                    "client_id": request.client_id,
                    "event": event_kind,
                    "attack_type": event_name,
                    "attack_id": attack_identifier,
                    "severity": severity.value,
                    "alert_number": request.alert_number,
                    "max_alerts": request.max_alerts,
                    "user_initiated": request.user_initiated,
                    "reason": request.reason,
                    "source_ip": source_ip,
                    "source_domain": source_domain,
                    "destination_ip": destination_ip,
                    "destination_port": destination_port,
                    "description": description,
                    "payload": payload,
                    "baseline_adjustment": baseline_meta,
                    "baseline_recent_event_count_10m": recent_baseline_count,
                },
            )
        )

        created_attack_id = None

        # Promote to attack event only with sufficient confidence/corroboration to reduce false positives.
        is_security_signal = _is_security_event(event_name) or _is_security_event(event_kind)
        promote_event = False
        if severity in {ThreatSeverity.HIGH, ThreatSeverity.CRITICAL}:
            promote_event = computed_confidence >= 0.72
        elif severity == ThreatSeverity.MEDIUM:
            promote_event = is_security_signal and (computed_confidence >= 0.66 and corroboration_count >= 2)
        else:
            promote_event = is_security_signal and (computed_confidence >= 0.80 and corroboration_count >= 2)

        if baseline_meta.get("available") and not baseline_meta.get("anomalous") and computed_confidence < 0.74:
            promote_event = False

        if promote_event:
            attack = None
            if external_event_id:
                existing_res = await db.execute(select(AttackEvent).where(AttackEvent.event_id == external_event_id))
                attack = existing_res.scalar_one_or_none()

            if attack is None:
                event_id = external_event_id or f"EVT_{uuid.uuid4().hex[:12].upper()}"
                attack = AttackEvent(
                    event_id=event_id,
                    attack_type=event_name,
                    source_ip=source_ip,
                    source_domain=source_domain,
                    destination_ip=destination_ip,
                    destination_port=destination_port,
                    severity=severity,
                    confidence=float(computed_confidence),
                    description=description,
                    indicators={
                        **(payload if payload else {}),
                        "event_kind": event_kind,
                        "attack_id": attack_identifier,
                        "alert_number": request.alert_number,
                        "max_alerts": request.max_alerts,
                        "reason": request.reason,
                        "corroboration_sources": sorted(corroboration_sources),
                        "corroboration_count": corroboration_count,
                        "baseline_adjustment": baseline_meta,
                        "baseline_recent_event_count_10m": recent_baseline_count,
                    },
                    status=_status_from_event(event_kind),
                    target_client_id=client_fk,
                )
                db.add(attack)
                await db.flush()
            else:
                attack.attack_type = event_name or attack.attack_type
                attack.source_ip = source_ip or attack.source_ip
                attack.source_domain = source_domain or attack.source_domain
                attack.destination_ip = destination_ip or attack.destination_ip
                attack.destination_port = destination_port or attack.destination_port
                attack.severity = severity
                attack.confidence = max(float(attack.confidence or 0.0), float(computed_confidence))
                attack.description = description or attack.description
                attack.indicators = {
                    **(attack.indicators if isinstance(attack.indicators, dict) else {}),
                    **(payload if payload else {}),
                    "event_kind": event_kind,
                    "attack_id": attack_identifier,
                    "alert_number": request.alert_number,
                    "max_alerts": request.max_alerts,
                    "reason": request.reason,
                    "corroboration_sources": sorted(corroboration_sources),
                    "corroboration_count": corroboration_count,
                    "baseline_adjustment": baseline_meta,
                    "baseline_recent_event_count_10m": recent_baseline_count,
                }
                attack.status = _status_from_event(event_kind, attack.status or "detected")
                if client_fk:
                    attack.target_client_id = client_fk

            created_attack_id = attack.event_id

            if event_kind.lower() in {"quarantine_activated", "system_quarantined"}:
                db.add(
                    DefenseAction(
                        action_id=f"DEF_{uuid.uuid4().hex[:12].upper()}",
                        action_type="quarantine",
                        target=request.client_id or source_ip or source_domain or event_name,
                        details={
                            "event": event_kind,
                            "attack_id": created_attack_id,
                            "reason": request.reason or description,
                            "user_initiated": bool(request.user_initiated),
                        },
                        status="executed",
                        executed_at=datetime.utcnow(),
                        attack_event_id=attack.id,
                        client_id=client_fk,
                        successful=True,
                    )
                )

        # Correlate burst activity for the same source/client in the last 10 minutes
        since_time = datetime.utcnow() - timedelta(minutes=10)
        base_query = select(func.count(AttackEvent.id)).where(AttackEvent.detected_at >= since_time)
        if source_ip:
            base_query = base_query.where(AttackEvent.source_ip == source_ip)
        elif client_fk:
            base_query = base_query.where(AttackEvent.target_client_id == client_fk)

        count_res = await db.execute(base_query)
        recent_count = int(count_res.scalar() or 0)

        # Create a correlated alert when threshold reached
        alert_created = None
        if recent_count >= 4:
            alert = NetworkAlert(
                alert_id=f"ALERT_{uuid.uuid4().hex[:12].upper()}",
                alert_type="correlated_multi_event_incident",
                severity=ThreatSeverity.CRITICAL if recent_count >= 8 else ThreatSeverity.HIGH,
                title="Correlated multi-event attack pattern",
                description=(
                    f"Detected {recent_count} related security events within 10 minutes"
                    + (f" from source {source_ip}" if source_ip else "")
                ),
                affected_clients=[request.client_id] if request.client_id else [],
                affected_count=1 if request.client_id else 0,
                status="active",
            )
            db.add(alert)
            await db.flush()
            alert_created = alert.alert_id

        await db.commit()

        if created_attack_id or _is_security_event(event_name) or _is_security_event(event_kind):
            terminal_monitor.log_attack_activity(
                attack_type=event_name,
                source=source_ip or source_domain or request.client_id or "unknown",
                severity=severity.value,
                description=description,
            )

        return {
            "status": "ingested",
            "event": event_kind,
            "attack_type": event_name,
            "severity": severity.value,
            "confidence": round(computed_confidence, 3),
            "corroboration_count": corroboration_count,
            "created_attack_event": created_attack_id,
            "correlated_alert": alert_created,
            "recent_related_events_10m": recent_count,
        }

    except Exception as e:
        await db.rollback()
        logger.error(f"Defense event ingestion failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/event/respond")
async def respond_to_defense_event(
    request: DefenseEventResponseRequest,
    db: AsyncSession = Depends(get_db),
):
    """Persist analyst responses for popup actions such as block/ignore/quarantine."""
    try:
        action = (request.action or "").strip().upper()
        if action not in {"BLOCK", "IGNORE", "QUARANTINE"}:
            raise HTTPException(status_code=400, detail="action must be BLOCK, IGNORE, or QUARANTINE")

        client_fk = None
        if request.client_id:
            client_res = await db.execute(select(ClientInstallation).where(ClientInstallation.client_id == request.client_id))
            client = client_res.scalar_one_or_none()
            if client:
                client_fk = client.id

        metadata = _sanitize_response_metadata(request.metadata)

        req_target_type = str(request.target_type or "").strip().lower()
        req_target_text = str(request.target or "").strip().lower()
        is_global_quarantine = action == "QUARANTINE" and (
            req_target_type in {"system", "global", "all", "infrastructure"}
            or req_target_text in {"system", "all", "*", "system_all", "global", "system:all"}
            or bool(metadata.get("auto_global_quarantine"))
            or bool(metadata.get("system_wide"))
            or bool(metadata.get("quarantine_all"))
        )

        if action == "QUARANTINE" and is_global_quarantine:
            confirmed = bool(metadata.get("user_confirmed_quarantine"))
            if not confirmed:
                raise HTTPException(
                    status_code=400,
                    detail="System-wide quarantine requires explicit user confirmation",
                )

        attack = None
        attack_lookup_id = _sanitize_external_event_id(request.attack_id or request.event_id)
        if attack_lookup_id:
            attack_res = await db.execute(select(AttackEvent).where(AttackEvent.event_id == attack_lookup_id))
            attack = attack_res.scalar_one_or_none()

        target = _sanitize_response_text(request.target, max_len=320) or (attack.source_ip if attack else None) or (attack.source_domain if attack else None)
        target_type = _derive_target_type(target, request.target_type)
        if is_global_quarantine:
            target = "SYSTEM_ALL"
            target_type = "system"

        action_type = {
            "BLOCK": "block_ip" if target_type == "ip" else "block_indicator",
            "IGNORE": "ignore",
            "QUARANTINE": "quarantine",
        }[action]
        if action == "QUARANTINE" and is_global_quarantine:
            action_type = "quarantine_system"
        if action == "BLOCK" and target_type == "domain":
            action_type = "block_domain"

        response_action = DefenseAction(
            action_id=f"DEF_{uuid.uuid4().hex[:12].upper()}",
            action_type=action_type,
            target=target or request.client_id or request.event_id or "unknown",
            details={
                "requested_action": action,
                "reason": _sanitize_response_text(request.reason, max_len=512) or f"Dashboard action: {action}",
                "metadata": metadata,
                "target_type": target_type,
                "scope": "system-wide" if is_global_quarantine else "targeted",
            },
            status="pending",
            attack_event_id=attack.id if attack else None,
            client_id=client_fk,
        )
        db.add(response_action)
        await db.flush()

        successful = True
        affected_attack_events = 0
        affected_clients = []

        if is_global_quarantine:
            now = datetime.utcnow()

            active_attacks_res = await db.execute(select(AttackEvent))
            for attack_event in active_attacks_res.scalars().all():
                status = str(attack_event.status or "detected").lower()
                if status in {"ignored", "resolved", "false_positive"}:
                    continue
                attack_event.status = "quarantined"
                attack_event.blocked = True
                if not attack_event.blocked_at:
                    attack_event.blocked_at = now
                affected_attack_events += 1

            clients_res = await db.execute(select(ClientInstallation).where(ClientInstallation.is_active == True))
            active_clients = clients_res.scalars().all()
            affected_clients = [c.client_id for c in active_clients if c and c.client_id]

            db.add(
                NetworkAlert(
                    alert_id=f"ALERT_{uuid.uuid4().hex[:12].upper()}",
                    alert_type="system_wide_quarantine",
                    severity=ThreatSeverity.CRITICAL,
                    title="System-wide quarantine initiated",
                    description=(
                        f"System-wide quarantine was triggered from dashboard response. "
                        f"Affected attack events: {affected_attack_events}."
                    ),
                    affected_clients=affected_clients,
                    affected_count=len(affected_clients),
                    status="active",
                )
            )

        if action == "BLOCK" and action_type in {"block_ip", "block_domain"}:
            response_action.action_type = action_type
            successful = await _apply_defense_action(response_action, db)
        else:
            successful = True

        response_action.status = "executed" if successful else "failed"
        response_action.successful = successful
        response_action.executed_at = datetime.utcnow()
        if successful and action == "BLOCK" and action_type in {"block_ip", "block_domain"}:
            rollback_seconds = int(
                metadata.get("temporary_seconds")
                or metadata.get("rollback_in_seconds")
                or getattr(settings, "SENTINEL_TEMP_BLOCK_ROLLBACK_SECONDS", 900)
                or 900
            )
            if not bool(metadata.get("disable_auto_rollback")) and rollback_seconds > 0:
                response_action.details = {
                    **(response_action.details if isinstance(response_action.details, dict) else {}),
                    "rollback_in_seconds": rollback_seconds,
                    "auto_rollback_enabled": True,
                }
                _schedule_auto_rollback(response_action.action_id, rollback_seconds)
        response_action.details = {
            **(response_action.details if isinstance(response_action.details, dict) else {}),
            "affected_attack_events": affected_attack_events,
            "affected_clients": affected_clients,
        }

        if attack is not None:
            attack.status = {
                "BLOCK": "blocked",
                "IGNORE": "ignored",
                "QUARANTINE": "quarantined",
            }[action]
            if action == "BLOCK":
                attack.blocked = successful
                attack.blocked_at = datetime.utcnow() if successful else attack.blocked_at

        db.add(
            SystemLog(
                log_level="CRITICAL" if action == "QUARANTINE" else "WARNING" if action == "BLOCK" else "INFO",
                component="defense_response",
                message=f"Dashboard response {action} applied to {request.event_id or request.attack_id or target or 'security event'}",
                details={
                    "action": action,
                    "attack_id": request.attack_id,
                    "event_id": request.event_id,
                    "client_id": request.client_id,
                    "target": target,
                    "target_type": target_type,
                    "successful": successful,
                    "reason": _sanitize_response_text(request.reason, max_len=512),
                    "metadata": metadata,
                    "scope": "system-wide" if is_global_quarantine else "targeted",
                    "affected_attack_events": affected_attack_events,
                    "affected_clients": affected_clients,
                },
            )
        )

        await db.commit()

        return {
            "status": "ok",
            "action": action,
            "successful": successful,
            "attack_event_id": attack.event_id if attack else None,
            "defense_action_id": response_action.action_id,
            "scope": "system-wide" if is_global_quarantine else "targeted",
            "affected_attack_events": affected_attack_events,
            "affected_clients": len(affected_clients),
        }
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Defense response failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ingest/nids")
async def ingest_nids_events(request: NIDSBatchIngestRequest, db: AsyncSession = Depends(get_db)):
    """
    Ingest normalized NIDS events from Suricata or Zeek and persist as
    `AttackEvent` records. This endpoint enables hybrid NIDS/HIDS correlation.
    """
    try:
        source = (request.source or "").strip().lower()
        if source not in {"suricata", "zeek"}:
            raise HTTPException(status_code=400, detail="source must be 'suricata' or 'zeek'")

        client_fk = None
        if request.client_id:
            q = select(ClientInstallation).where(ClientInstallation.client_id == request.client_id)
            r = await db.execute(q)
            client = r.scalar_one_or_none()
            if client:
                client_fk = client.id

        normalized = NIDSIngestor.batch_normalize(source, request.records, zeek_log_type=request.zeek_log_type)
        created = 0
        high_critical = 0

        for evt in normalized:
            sev = _map_text_severity(evt.severity)
            if sev in {ThreatSeverity.HIGH, ThreatSeverity.CRITICAL}:
                high_critical += 1

            attack = AttackEvent(
                event_id=f"NIDS_{uuid.uuid4().hex[:12].upper()}",
                attack_type=evt.attack_type,
                source_ip=evt.source_ip,
                source_domain=evt.source_domain,
                destination_ip=evt.destination_ip,
                destination_port=evt.destination_port,
                severity=sev,
                confidence=float(evt.confidence),
                description=evt.description,
                indicators=evt.indicators,
                status="detected",
                target_client_id=client_fk,
            )
            db.add(attack)
            created += 1

        # Persist a summarized log entry
        db.add(
            SystemLog(
                log_level="WARNING" if high_critical > 0 else "INFO",
                component="nids_ingestion",
                message=f"Ingested {created} {source} events ({high_critical} high/critical)",
                details={
                    "source": source,
                    "client_id": request.client_id,
                    "records_received": len(request.records or []),
                    "events_created": created,
                    "high_critical": high_critical,
                    "zeek_log_type": request.zeek_log_type,
                },
            )
        )

        # Raise network alert for sustained high-severity NIDS input
        alert_id = None
        if high_critical >= 5:
            alert = NetworkAlert(
                alert_id=f"ALERT_{uuid.uuid4().hex[:12].upper()}",
                alert_type="nids_high_severity_burst",
                severity=ThreatSeverity.CRITICAL,
                title="Burst of high-severity NIDS detections",
                description=f"{high_critical} high/critical {source} detections in a single batch",
                affected_clients=[request.client_id] if request.client_id else [],
                affected_count=1 if request.client_id else 0,
                status="active",
            )
            db.add(alert)
            await db.flush()
            alert_id = alert.alert_id

        await db.commit()

        return {
            "status": "ingested",
            "source": source,
            "records_received": len(request.records or []),
            "events_created": created,
            "high_critical": high_critical,
            "alert_id": alert_id,
        }
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"NIDS ingestion failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/replay/simulate")
async def simulate_threat_replay(request: ReplayBatchRequest, db: AsyncSession = Depends(get_db)):
    """Replay synthetic IDS/IPS scenarios and return predicted promotion/block decisions."""
    scenarios = list(request.scenarios or [])
    if not scenarios:
        return {"total": 0, "results": []}

    results = []
    for idx, scenario in enumerate(scenarios, start=1):
        event_name = str(scenario.event or "unknown_event")
        severity = _map_text_severity(scenario.severity)
        payload = scenario.payload if isinstance(scenario.payload, dict) else {}
        corroboration_sources = _extract_corroboration_sources(payload)
        corroboration_count = len(corroboration_sources)

        confidence = _estimate_event_confidence(payload, severity, event_name, event_name)

        recent_count = 1
        client_fk = None
        if scenario.client_id:
            c_res = await db.execute(select(ClientInstallation).where(ClientInstallation.client_id == scenario.client_id))
            client = c_res.scalar_one_or_none()
            if client:
                client_fk = client.id
                recent_cutoff = datetime.utcnow() - timedelta(minutes=10)
                recent_q = (
                    select(func.count(AttackEvent.id))
                    .where(AttackEvent.target_client_id == client_fk)
                    .where(AttackEvent.detected_at >= recent_cutoff)
                )
                recent_r = await db.execute(recent_q)
                recent_count = int(recent_r.scalar() or 0) + 1

        adjusted_conf, baseline_meta = _apply_behavior_baseline_adjustment(
            client_id=scenario.client_id,
            artifact_type=event_name,
            count_in_window=recent_count,
            base_confidence=confidence,
        )

        is_security_signal = _is_security_event(event_name)
        promote_event = False
        if severity in {ThreatSeverity.HIGH, ThreatSeverity.CRITICAL}:
            promote_event = adjusted_conf >= 0.72
        elif severity == ThreatSeverity.MEDIUM:
            promote_event = is_security_signal and (adjusted_conf >= 0.66 and corroboration_count >= 2)
        else:
            promote_event = is_security_signal and (adjusted_conf >= 0.80 and corroboration_count >= 2)

        if baseline_meta.get("available") and not baseline_meta.get("anomalous") and adjusted_conf < 0.74:
            promote_event = False

        source_ip = scenario.source_ip or payload.get("source_ip")
        auto_block = bool(promote_event and source_ip and _should_auto_block(severity, adjusted_conf))
        recommendation = (
            "auto_block" if auto_block
            else "manual_review" if promote_event
            else "monitor_only"
        )

        results.append(
            {
                "scenario": idx,
                "event": event_name,
                "severity": severity.value,
                "confidence": round(float(adjusted_conf), 3),
                "corroboration_count": corroboration_count,
                "promote_event": bool(promote_event),
                "auto_block": bool(auto_block),
                "recommendation": recommendation,
                "baseline": baseline_meta,
                "client_id": scenario.client_id,
                "source_ip": source_ip,
            }
        )

    return {
        "total": len(results),
        "results": results,
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/events")
async def list_defense_events(
    hours: int = 24,
    limit: int = 200,
    client_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Return recent defense event timeline for analyst investigation."""
    try:
        since_time = datetime.utcnow() - timedelta(hours=hours)
        query = (
            select(SystemLog)
            .where(SystemLog.component == "defense_event")
            .where(SystemLog.timestamp >= since_time)
            .order_by(SystemLog.timestamp.desc())
            .limit(max(1, min(limit, 1000)))
        )
        result = await db.execute(query)
        rows = result.scalars().all()

        events = []
        for row in rows:
            details = row.details or {}
            if client_id and details.get("client_id") != client_id:
                continue
            events.append(
                {
                    "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                    "log_level": row.log_level,
                    "event": details.get("event"),
                    "severity": details.get("severity"),
                    "client_id": details.get("client_id"),
                    "source_ip": details.get("source_ip"),
                    "source_domain": details.get("source_domain"),
                    "message": row.message,
                    "details": details,
                }
            )

        return {"total": len(events), "events": events}
    except Exception as e:
        logger.error(f"Failed to list defense events: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attacks")
async def list_attacks(
    hours: int = 24,
    severity: Optional[str] = None,
    client_id: Optional[str] = None,
    blocked_only: bool = False,
    db: AsyncSession = Depends(get_db),
):
    """
    List detected attacks
    """
    try:
        since_time = datetime.utcnow() - timedelta(hours=hours)

        query = select(AttackEvent).where(AttackEvent.detected_at >= since_time)

        if severity:
            severity_map = {
                "low": ThreatSeverity.LOW,
                "medium": ThreatSeverity.MEDIUM,
                "high": ThreatSeverity.HIGH,
                "critical": ThreatSeverity.CRITICAL,
            }
            if severity.lower() in severity_map:
                query = query.where(AttackEvent.severity == severity_map[severity.lower()])

        if client_id:
            query = query.join(ClientInstallation).where(ClientInstallation.client_id == client_id)

        if blocked_only:
            query = query.where(AttackEvent.blocked == True)

        query = query.order_by(AttackEvent.detected_at.desc())

        result = await db.execute(query)
        attacks = result.scalars().all()

        return {
            "total": len(attacks),
            "attacks": [
                {
                    "event_id": a.event_id,
                    "attack_type": a.attack_type,
                    "source_ip": a.source_ip,
                    "source_domain": a.source_domain,
                    "severity": a.severity.value if a.severity else "unknown",
                    "status": a.status,
                    "blocked": a.blocked,
                    "detected_at": a.detected_at.isoformat() if a.detected_at else None,
                }
                for a in attacks
            ],
        }

    except Exception as e:
        logger.error(f"Failed to list attacks: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts")
async def list_network_alerts(
    active_only: bool = True,
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    List network-wide security alerts
    """
    try:
        query = select(NetworkAlert)

        if active_only:
            query = query.where(NetworkAlert.status == "active")

        if severity:
            severity_map = {
                "low": ThreatSeverity.LOW,
                "medium": ThreatSeverity.MEDIUM,
                "high": ThreatSeverity.HIGH,
                "critical": ThreatSeverity.CRITICAL,
            }
            if severity.lower() in severity_map:
                query = query.where(NetworkAlert.severity == severity_map[severity.lower()])

        query = query.order_by(NetworkAlert.created_at.desc())

        result = await db.execute(query)
        alerts = result.scalars().all()

        return {
            "total": len(alerts),
            "alerts": [
                {
                    "alert_id": a.alert_id,
                    "alert_type": a.alert_type,
                    "severity": a.severity.value if a.severity else "unknown",
                    "title": a.title,
                    "description": a.description,
                    "affected_count": a.affected_count,
                    "status": a.status,
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                }
                for a in alerts
            ],
        }

    except Exception as e:
        logger.error(f"Failed to list alerts: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# Background task functions
async def _execute_defense_response(
    attack_id: int, client_id: str, source_ip: Optional[str], db: AsyncSession
):
    """
    Execute automatic defense response to an attack
    """
    try:
        async with db.begin():
            # Get attack details
            query = select(AttackEvent).where(AttackEvent.id == attack_id)
            result = await db.execute(query)
            attack = result.scalar_one_or_none()

            if not attack:
                return

            # Get client
            query = select(ClientInstallation).where(ClientInstallation.client_id == client_id)
            result = await db.execute(query)
            client = result.scalar_one_or_none()

            if not client:
                return

            # For medium-confidence/severity detections, require analyst approval when enabled.
            manual_approval_enabled = bool(getattr(settings, "SENTINEL_ENABLE_MANUAL_APPROVAL", True))
            min_review_conf = float(getattr(settings, "SENTINEL_MANUAL_REVIEW_MIN_CONFIDENCE", 0.65) or 0.65)
            if (
                source_ip
                and manual_approval_enabled
                and attack.severity in [ThreatSeverity.MEDIUM, ThreatSeverity.HIGH]
                and float(attack.confidence or 0.0) < min_review_conf
            ):
                db.add(
                    NetworkAlert(
                        alert_id=f"ALERT_{uuid.uuid4().hex[:12].upper()}",
                        alert_type="manual_approval_required",
                        severity=ThreatSeverity.MEDIUM,
                        title="Manual approval required before block",
                        description=(
                            f"Attack {attack.event_id} from {source_ip} is below confidence threshold "
                            f"({float(attack.confidence or 0.0):.2f} < {min_review_conf:.2f})."
                        ),
                        affected_clients=[client_id] if client_id else [],
                        affected_count=1,
                        status="active",
                    )
                )
                db.add(
                    SystemLog(
                        log_level="INFO",
                        component="defense_response",
                        message=f"Manual approval required for attack {attack.event_id}",
                        details={
                            "attack_id": attack.event_id,
                            "client_id": client_id,
                            "source_ip": source_ip,
                            "severity": attack.severity.value if attack.severity else "unknown",
                            "confidence": float(attack.confidence or 0.0),
                            "threshold": min_review_conf,
                        },
                    )
                )
                await db.commit()
                return

            # Block source IP if policy permits (default: high/critical with adequate confidence)
            if source_ip and _should_auto_block(attack.severity, float(attack.confidence or 0.0)):
                action = DefenseAction(
                    action_id=f"DEF_{uuid.uuid4().hex[:12].upper()}",
                    action_type="block_ip",
                    target=source_ip,
                    details={
                        "reason": "Automatic block - high severity attack",
                        "attack_id": attack.event_id,
                        "auto_rollback_enabled": True,
                    },
                    status="pending",
                    attack_event_id=attack.id,
                    client_id=client.id,
                )

                db.add(action)
                await db.flush()

                # Apply the block
                success = await _apply_defense_action(action, db)

                action.status = "executed" if success else "failed"
                action.successful = success
                action.executed_at = datetime.utcnow()

                if success:
                    attack.blocked = True
                    attack.blocked_at = datetime.utcnow()
                    attack.status = "blocked"

                    rollback_seconds = int(getattr(settings, "SENTINEL_TEMP_BLOCK_ROLLBACK_SECONDS", 900) or 900)
                    if rollback_seconds > 0:
                        action.details = {
                            **(action.details if isinstance(action.details, dict) else {}),
                            "rollback_in_seconds": rollback_seconds,
                        }
                        _schedule_auto_rollback(action.action_id, rollback_seconds)

                    logger.info(f"Auto-blocked IP {source_ip} due to attack {attack.event_id}")

            await db.commit()

    except Exception as e:
        logger.error(f"Defense response execution failed: {str(e)}")
        await db.rollback()


async def _check_network_attack_patterns(attack_type: str, source_ip: Optional[str], db: AsyncSession):
    """
    Check for network-wide attack patterns and generate alerts
    """
    try:
        async with db.begin():
            # Check for multiple attacks from same source
            if source_ip:
                since_time = datetime.utcnow() - timedelta(hours=1)

                query = (
                    select(AttackEvent)
                    .where(
                        and_(
                            AttackEvent.source_ip == source_ip,
                            AttackEvent.detected_at >= since_time,
                        )
                    )
                )

                result = await db.execute(query)
                attacks_from_source = result.scalars().all()

                # If multiple attacks from same source, create network alert
                if len(attacks_from_source) >= 3:
                    # Check if alert already exists
                    alert_query = select(NetworkAlert).where(
                        and_(
                            NetworkAlert.alert_type == "multiple_attacks_same_source",
                            NetworkAlert.status == "active",
                            NetworkAlert.created_at >= since_time,
                        )
                    )

                    result = await db.execute(alert_query)
                    existing_alert = result.scalar_one_or_none()

                    if not existing_alert:
                        alert = NetworkAlert(
                            alert_id=f"ALERT_{uuid.uuid4().hex[:12].upper()}",
                            alert_type="multiple_attacks_same_source",
                            severity=ThreatSeverity.CRITICAL,
                            title=f"Multiple Attacks from {source_ip}",
                            description=f"Detected {len(attacks_from_source)} attacks from {source_ip} in the last hour",
                            affected_clients=[],
                            affected_count=len(set(a.target_client_id for a in attacks_from_source)),
                            status="active",
                        )

                        db.add(alert)
                        logger.warning(f"Network alert created: Multiple attacks from {source_ip}")

            await db.commit()

    except Exception as e:
        logger.error(f"Attack pattern check failed: {str(e)}")
        await db.rollback()


async def _apply_defense_action(action: DefenseAction, db: AsyncSession) -> bool:
    """
    Apply a defense action to the target client
    """
    try:
        if action.action_type == "block_ip":
            # Update client's blocked IPs list
            if action.client_id:
                query = select(ClientInstallation).where(ClientInstallation.id == action.client_id)
                result = await db.execute(query)
                client = result.scalar_one_or_none()

                if client:
                    blocked_ips = client.blocked_ips or []
                    if action.target not in blocked_ips:
                        blocked_ips.append(action.target)
                        client.blocked_ips = blocked_ips
                        await db.flush()

            return True

        elif action.action_type == "unblock_ip":
            if action.client_id:
                query = select(ClientInstallation).where(ClientInstallation.id == action.client_id)
                result = await db.execute(query)
                client = result.scalar_one_or_none()
                if client:
                    blocked_ips = list(client.blocked_ips or [])
                    if action.target in blocked_ips:
                        blocked_ips = [ip for ip in blocked_ips if ip != action.target]
                        client.blocked_ips = blocked_ips
                        await db.flush()
            return True

        elif action.action_type == "block_domain":
            # Update client's blocked domains list
            if action.client_id:
                query = select(ClientInstallation).where(ClientInstallation.id == action.client_id)
                result = await db.execute(query)
                client = result.scalar_one_or_none()

                if client:
                    blocked_domains = client.blocked_domains or []
                    if action.target not in blocked_domains:
                        blocked_domains.append(action.target)
                        client.blocked_domains = blocked_domains
                        await db.flush()

            return True

        elif action.action_type == "unblock_domain":
            if action.client_id:
                query = select(ClientInstallation).where(ClientInstallation.id == action.client_id)
                result = await db.execute(query)
                client = result.scalar_one_or_none()
                if client:
                    blocked_domains = list(client.blocked_domains or [])
                    if action.target in blocked_domains:
                        blocked_domains = [d for d in blocked_domains if d != action.target]
                        client.blocked_domains = blocked_domains
                        await db.flush()
            return True

        elif action.action_type == "alert_admin":
            # Log alert (in production, send email/notification)
            logger.warning(f"ADMIN ALERT: {action.details}")
            return True

        else:
            logger.warning(f"Unknown action type: {action.action_type}")
            return False

    except Exception as e:
        logger.error(f"Failed to apply defense action: {str(e)}")
        return False


@router.post("/defense/action/revert/{action_id}")
async def revert_defense_action(
    action_id: str,
    db: AsyncSession = Depends(get_db),
    _gate=Depends(_admin_or_blocked_in_safe_mode),
):
    """Safely revert previously executed block actions (IP/domain) for rollback/unblock workflows."""
    try:
        res = await db.execute(select(DefenseAction).where(DefenseAction.action_id == action_id))
        action = res.scalar_one_or_none()
        if not action:
            raise HTTPException(status_code=404, detail="Defense action not found")

        if action.status == "reverted":
            return {"status": "ok", "message": "Action already reverted", "action_id": action_id}

        if action.action_type not in {"block_ip", "block_domain"}:
            raise HTTPException(status_code=400, detail="Only block_ip/block_domain actions can be reverted")

        rollback_action = DefenseAction(
            action_id=f"DEF_{uuid.uuid4().hex[:12].upper()}",
            action_type="unblock_ip" if action.action_type == "block_ip" else "unblock_domain",
            target=action.target,
            details={
                "rollback_of": action.action_id,
                "reason": "operator rollback",
            },
            status="pending",
            attack_event_id=action.attack_event_id,
            client_id=action.client_id,
        )
        db.add(rollback_action)
        await db.flush()

        success = await _apply_defense_action(rollback_action, db)
        rollback_action.status = "executed" if success else "failed"
        rollback_action.successful = success
        rollback_action.executed_at = datetime.utcnow()

        if success:
            action.status = "reverted"
            action.reverted_at = datetime.utcnow()

        db.add(
            SystemLog(
                log_level="INFO" if success else "WARNING",
                component="defense_response",
                message=f"Defense action rollback {'succeeded' if success else 'failed'} for {action_id}",
                details={
                    "action_id": action_id,
                    "target": action.target,
                    "original_action_type": action.action_type,
                    "rollback_action_id": rollback_action.action_id,
                    "successful": success,
                },
            )
        )

        await db.commit()
        return {
            "status": "ok" if success else "failed",
            "action_id": action_id,
            "rollback_action_id": rollback_action.action_id,
            "successful": success,
        }
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Defense action rollback failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/defense/action/rollback/sweep")
async def sweep_expired_rollbacks(
    db: AsyncSession = Depends(get_db),
    _gate=Depends(_admin_or_blocked_in_safe_mode),
):
    """Revert temporary blocks whose rollback windows have expired."""
    try:
        now = datetime.utcnow()
        res = await db.execute(
            select(DefenseAction).where(
                DefenseAction.status == "executed",
                DefenseAction.action_type.in_(["block_ip", "block_domain"]),
            )
        )
        actions = res.scalars().all()

        processed = 0
        reverted = 0
        skipped = 0

        for action in actions:
            processed += 1
            details = action.details if isinstance(action.details, dict) else {}
            rollback_seconds = int(details.get("rollback_in_seconds") or 0)
            if rollback_seconds <= 0:
                skipped += 1
                continue
            executed_at = action.executed_at or action.created_at
            if not executed_at:
                skipped += 1
                continue
            if (now - executed_at).total_seconds() < rollback_seconds:
                skipped += 1
                continue

            rollback_action = DefenseAction(
                action_id=f"DEF_{uuid.uuid4().hex[:12].upper()}",
                action_type="unblock_ip" if action.action_type == "block_ip" else "unblock_domain",
                target=action.target,
                details={
                    "rollback_of": action.action_id,
                    "reason": "scheduled rollback sweep",
                    "rollback_in_seconds": rollback_seconds,
                },
                status="pending",
                attack_event_id=action.attack_event_id,
                client_id=action.client_id,
            )
            db.add(rollback_action)
            await db.flush()
            ok = await _apply_defense_action(rollback_action, db)
            rollback_action.status = "executed" if ok else "failed"
            rollback_action.successful = bool(ok)
            rollback_action.executed_at = datetime.utcnow()

            if ok:
                action.status = "reverted"
                action.reverted_at = datetime.utcnow()
                reverted += 1

        await db.commit()
        return {
            "status": "ok",
            "processed": processed,
            "reverted": reverted,
            "skipped": skipped,
            "generated_at": now.isoformat() + "Z",
        }
    except Exception as exc:
        await db.rollback()
        logger.error("Rollback sweep failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
