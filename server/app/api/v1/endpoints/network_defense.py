"""
Network Monitoring and Defense System
Tracks attacks across all client installations and implements defense mechanisms
"""

import asyncio
import logging
import uuid
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import and_, func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ....database import get_db
from ....core.nids_ingestor import NIDSIngestor
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
    severity: Optional[str] = None
    risk: Optional[str] = None
    source_ip: Optional[str] = None
    source_domain: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    description: Optional[str] = None
    details: Optional[dict] = None
    monitor_event: Optional[dict] = None


class NIDSBatchIngestRequest(BaseModel):
    """Batch ingest request for Suricata EVE / Zeek logs."""

    source: str  # suricata | zeek
    records: List[dict]
    client_id: Optional[str] = None
    zeek_log_type: str = "conn"


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


@router.post("/client/register")
async def register_client(request: ClientRegistrationRequest, db: AsyncSession = Depends(get_db)):
    """
    Register a new client installation or update existing one
    """
    try:
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
            # Update existing client
            existing_client.last_seen = datetime.utcnow()
            existing_client.is_active = True
            existing_client.version = request.version
            existing_client.os_version = request.os_version or existing_client.os_version
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

            logger.info(f"New client registered: {client_id} ({request.hostname})")

            return {
                "status": "registered",
                "client_id": client_id,
                "message": "Client successfully registered",
            }

    except Exception as e:
        logger.error(f"Client registration failed: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@router.post("/client/heartbeat")
async def client_heartbeat(client_id: str, db: AsyncSession = Depends(get_db)):
    """
    Update client last_seen timestamp (heartbeat)
    """
    try:
        query = select(ClientInstallation).where(ClientInstallation.client_id == client_id)
        result = await db.execute(query)
        client = result.scalar_one_or_none()

        if not client:
            raise HTTPException(status_code=404, detail="Client not found")

        client.last_seen = datetime.utcnow()
        client.is_active = True
        await db.commit()

        return {"status": "ok", "last_seen": client.last_seen.isoformat()}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Heartbeat failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/clients")
async def list_clients(
    active_only: bool = True,
    db: AsyncSession = Depends(get_db),
):
    """
    List all client installations
    """
    try:
        query = select(ClientInstallation)

        if active_only:
            # Consider clients active if seen within last 10 minutes
            cutoff_time = datetime.utcnow() - timedelta(minutes=10)
            query = query.where(
                and_(ClientInstallation.is_active == True, ClientInstallation.last_seen >= cutoff_time)
            )

        query = query.order_by(ClientInstallation.last_seen.desc())

        result = await db.execute(query)
        clients = result.scalars().all()

        return {
            "total": len(clients),
            "clients": [
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
                }
                for c in clients
            ],
        }

    except Exception as e:
        logger.error(f"Failed to list clients: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/attack/report")
async def report_attack(
    request: AttackReportRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
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

        attack = AttackEvent(
            event_id=event_id,
            attack_type=request.attack_type,
            source_ip=request.source_ip,
            source_domain=request.source_domain,
            destination_ip=request.destination_ip,
            destination_port=request.destination_port,
            severity=severity_map.get(request.severity.lower(), ThreatSeverity.MEDIUM),
            description=request.description,
            indicators=request.indicators or {},
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
async def execute_defense_action(request: DefenseActionRequest, db: AsyncSession = Depends(get_db)):
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
        payload = request.monitor_event or {}
        event_name = payload.get("type") or request.event or "unknown_event"
        risk_text = payload.get("risk") or payload.get("severity") or request.risk or request.severity
        severity = _map_text_severity(risk_text)

        source_ip = payload.get("source_ip") or payload.get("remote_ip") or request.source_ip
        source_domain = payload.get("domain") or request.source_domain
        destination_ip = payload.get("destination_ip") or request.destination_ip
        destination_port = payload.get("destination_port") or request.destination_port
        description = (
            payload.get("description")
            or request.description
            or f"Endpoint event: {event_name}"
        )

        # Resolve client foreign key (optional)
        client_fk = None
        if request.client_id:
            q = select(ClientInstallation).where(ClientInstallation.client_id == request.client_id)
            r = await db.execute(q)
            client = r.scalar_one_or_none()
            if client:
                client_fk = client.id

        # Always persist raw event in structured system log
        db.add(
            SystemLog(
                log_level="WARNING" if severity in {ThreatSeverity.HIGH, ThreatSeverity.CRITICAL} else "INFO",
                component="defense_event",
                message=f"{event_name}: {description}",
                details={
                    "client_id": request.client_id,
                    "event": event_name,
                    "severity": severity.value,
                    "source_ip": source_ip,
                    "source_domain": source_domain,
                    "destination_ip": destination_ip,
                    "destination_port": destination_port,
                    "payload": payload,
                },
            )
        )

        created_attack_id = None

        # Promote to attack event when high confidence or security-significant event type
        if severity in {ThreatSeverity.HIGH, ThreatSeverity.CRITICAL} or _is_security_event(event_name):
            event_id = f"EVT_{uuid.uuid4().hex[:12].upper()}"
            attack = AttackEvent(
                event_id=event_id,
                attack_type=event_name,
                source_ip=source_ip,
                source_domain=source_domain,
                destination_ip=destination_ip,
                destination_port=destination_port,
                severity=severity,
                confidence=0.9 if severity == ThreatSeverity.CRITICAL else 0.75 if severity == ThreatSeverity.HIGH else 0.55,
                description=description,
                indicators=payload if payload else (request.details or {}),
                status="detected",
                target_client_id=client_fk,
            )
            db.add(attack)
            await db.flush()
            created_attack_id = event_id

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

        return {
            "status": "ingested",
            "event": event_name,
            "severity": severity.value,
            "created_attack_event": created_attack_id,
            "correlated_alert": alert_created,
            "recent_related_events_10m": recent_count,
        }

    except Exception as e:
        await db.rollback()
        logger.error(f"Defense event ingestion failed: {str(e)}")
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

            # Block source IP if present
            if source_ip and attack.severity in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]:
                action = DefenseAction(
                    action_id=f"DEF_{uuid.uuid4().hex[:12].upper()}",
                    action_type="block_ip",
                    target=source_ip,
                    details={"reason": "Automatic block - high severity attack", "attack_id": attack.event_id},
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
