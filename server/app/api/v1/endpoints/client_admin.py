
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ....database import get_db
from ....models import AuditLog, AttackEvent, ClientInstallation, DefenseAction, Department, EnrollmentToken, Organization, ScanHistory, User
from .auth import get_current_user_obj, require_permission

router = APIRouter()


class EnrollmentTokenCreateRequest(BaseModel):
	organization_id: Optional[int] = None
	department_id: Optional[int] = None
	description: Optional[str] = None
	ttl_hours: int = Field(default=24, ge=1, le=720)


class ClientScopeUpdateRequest(BaseModel):
	organization_id: Optional[int] = None
	department_id: Optional[int] = None
	is_active: Optional[bool] = None


def _serialize_client(client: ClientInstallation) -> Dict[str, Any]:
	return {
		"id": client.id,
		"client_id": client.client_id,
		"hostname": client.hostname,
		"ip_address": client.ip_address,
		"mac_address": client.mac_address,
		"os_type": client.os_type,
		"os_version": client.os_version,
		"organization_id": client.organization_id,
		"department_id": client.department_id,
		"is_active": bool(client.is_active),
		"protection_enabled": bool(client.protection_enabled),
		"last_seen": client.last_seen.isoformat() if client.last_seen else None,
		"installation_date": client.installation_date.isoformat() if client.installation_date else None,
	}


def _serialize_token(token: EnrollmentToken) -> Dict[str, Any]:
	return {
		"id": token.id,
		"organization_id": token.organization_id,
		"department_id": token.department_id,
		"token_prefix": token.token_prefix,
		"description": token.description,
		"is_active": bool(token.is_active),
		"expires_at": token.expires_at.isoformat() if token.expires_at else None,
		"created_at": token.created_at.isoformat() if token.created_at else None,
	}


async def _resolve_scope(db: AsyncSession, organization_id: Optional[int], department_id: Optional[int]) -> tuple[int, Optional[int]]:
	if organization_id is None:
		org = (await db.execute(select(Organization).where(Organization.slug == "sentinel-default"))).scalar_one_or_none()
		if org is None:
			raise HTTPException(status_code=404, detail="Default organization not initialized")
		organization_id = org.id
	if department_id is not None:
		department = (
			await db.execute(
				select(Department).where(
					Department.id == department_id,
					Department.organization_id == organization_id,
				)
			)
		).scalar_one_or_none()
		if department is None:
			raise HTTPException(status_code=400, detail="Invalid department for organization")
	return organization_id, department_id


async def _audit_admin_action(
	db: AsyncSession,
	*,
	actor: User,
	action: str,
	resource_type: str,
	resource_id: str,
	organization_id: Optional[int],
	department_id: Optional[int],
	details: Dict[str, Any],
) -> None:
	db.add(
		AuditLog(
			organization_id=organization_id,
			department_id=department_id,
			actor_user_id=actor.id,
			action=action,
			resource_type=resource_type,
			resource_id=resource_id,
			outcome="success",
			details=details,
		)
	)


@router.get("/clients")
async def list_clients(
	organization_id: Optional[int] = Query(default=None),
	department_id: Optional[int] = Query(default=None),
	active_only: bool = Query(default=True),
	db: AsyncSession = Depends(get_db),
	current_user: User = Depends(require_permission("devices.read")),
):
	org_id, dept_id = await _resolve_scope(db, organization_id, department_id)
	query = select(ClientInstallation).where(ClientInstallation.organization_id == org_id)
	if dept_id is not None:
		query = query.where(ClientInstallation.department_id == dept_id)
	if active_only:
		query = query.where(ClientInstallation.is_active.is_(True))
	result = await db.execute(query.order_by(ClientInstallation.last_seen.desc().nullslast(), ClientInstallation.id.desc()))
	clients = result.scalars().all()
	return {
		"organization_id": org_id,
		"department_id": dept_id,
		"count": len(clients),
		"clients": [_serialize_client(client) for client in clients],
	}


@router.post("/enrollment-tokens")
async def create_enrollment_token(
	request: EnrollmentTokenCreateRequest,
	db: AsyncSession = Depends(get_db),
	current_user: User = Depends(require_permission("devices.manage")),
):
	org_id, dept_id = await _resolve_scope(db, request.organization_id, request.department_id)
	raw_token = secrets.token_urlsafe(32)
	token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
	expires_at = datetime.utcnow() + timedelta(hours=request.ttl_hours)
	token = EnrollmentToken(
		organization_id=org_id,
		department_id=dept_id,
		token_hash=token_hash,
		token_prefix=raw_token[:8],
		description=request.description,
		is_active=True,
		expires_at=expires_at,
		created_by_user_id=current_user.id,
	)
	db.add(token)
	await db.flush()
	await _audit_admin_action(
		db,
		actor=current_user,
		action="enrollment_token.create",
		resource_type="enrollment_token",
		resource_id=str(token.id),
		organization_id=org_id,
		department_id=dept_id,
		details={"token_prefix": token.token_prefix, "expires_at": expires_at.isoformat()},
	)
	await db.commit()
	return {"status": "success", "token": raw_token, "enrollment_token": _serialize_token(token)}


@router.get("/enrollment-tokens")
async def list_enrollment_tokens(
	organization_id: Optional[int] = Query(default=None),
	department_id: Optional[int] = Query(default=None),
	include_inactive: bool = Query(default=False),
	db: AsyncSession = Depends(get_db),
	current_user: User = Depends(require_permission("devices.read")),
):
	org_id, dept_id = await _resolve_scope(db, organization_id, department_id)
	query = select(EnrollmentToken).where(EnrollmentToken.organization_id == org_id)
	if dept_id is not None:
		query = query.where(EnrollmentToken.department_id == dept_id)
	if not include_inactive:
		query = query.where(EnrollmentToken.is_active.is_(True))
	result = await db.execute(query.order_by(EnrollmentToken.created_at.desc().nullslast(), EnrollmentToken.id.desc()))
	tokens = result.scalars().all()
	return {
		"organization_id": org_id,
		"department_id": dept_id,
		"count": len(tokens),
		"tokens": [_serialize_token(token) for token in tokens],
	}


@router.post("/enrollment-tokens/{token_id}/revoke")
async def revoke_enrollment_token(
	token_id: int,
	db: AsyncSession = Depends(get_db),
	current_user: User = Depends(require_permission("devices.manage")),
):
	token = (await db.execute(select(EnrollmentToken).where(EnrollmentToken.id == token_id))).scalar_one_or_none()
	if token is None:
		raise HTTPException(status_code=404, detail="Enrollment token not found")
	token.is_active = False
	await _audit_admin_action(
		db,
		actor=current_user,
		action="enrollment_token.revoke",
		resource_type="enrollment_token",
		resource_id=str(token.id),
		organization_id=token.organization_id,
		department_id=token.department_id,
		details={"token_prefix": token.token_prefix},
	)
	await db.commit()
	return {"status": "success", "enrollment_token": _serialize_token(token)}


@router.patch("/clients/{client_id}")
async def update_client_scope(
	client_id: str,
	request: ClientScopeUpdateRequest,
	db: AsyncSession = Depends(get_db),
	current_user: User = Depends(require_permission("devices.manage")),
):
	client = (await db.execute(select(ClientInstallation).where(ClientInstallation.client_id == client_id))).scalar_one_or_none()
	if client is None:
		raise HTTPException(status_code=404, detail="Client not found")
	if request.organization_id is not None:
		client.organization_id = request.organization_id
	if request.department_id is not None:
		client.department_id = request.department_id
	if request.is_active is not None:
		client.is_active = request.is_active
	await _audit_admin_action(
		db,
		actor=current_user,
		action="client.update_scope",
		resource_type="client_installation",
		resource_id=client.client_id,
		organization_id=client.organization_id,
		department_id=client.department_id,
		details={"is_active": client.is_active},
	)
	await db.commit()
	return {"status": "success", "client": _serialize_client(client)}


@router.get("/fleet-summary")
async def get_fleet_summary(
	organization_id: Optional[int] = Query(default=None),
	department_id: Optional[int] = Query(default=None),
	lookback_days: int = Query(default=30, ge=1, le=365),
	db: AsyncSession = Depends(get_db),
	current_user: User = Depends(require_permission("devices.read")),
):
	org_id, dept_id = await _resolve_scope(db, organization_id, department_id)
	cutoff = datetime.utcnow() - timedelta(days=lookback_days)

	client_query = select(ClientInstallation).where(ClientInstallation.organization_id == org_id)
	if dept_id is not None:
		client_query = client_query.where(ClientInstallation.department_id == dept_id)
	client_result = await db.execute(client_query)
	clients = client_result.scalars().all()
	client_ids = [client.id for client in clients]

	active_clients = sum(1 for client in clients if client.is_active)
	protected_clients = sum(1 for client in clients if client.protection_enabled)
	recent_clients = sum(1 for client in clients if client.last_seen and client.last_seen >= cutoff)

	scan_count = 0
	malicious_scans = 0
	recent_scan_result = await db.execute(
		select(ScanHistory.threat_level, func.count(ScanHistory.id))
		.join(ClientInstallation, ScanHistory.client_id == ClientInstallation.id)
		.where(ClientInstallation.organization_id == org_id, ScanHistory.scan_timestamp >= cutoff)
		.group_by(ScanHistory.threat_level)
	)
	for threat_level, count in recent_scan_result.all():
		scan_count += int(count or 0)
		if str(threat_level or "").lower() in {"malicious", "critical", "high"}:
			malicious_scans += int(count or 0)

	attack_query = select(func.count(AttackEvent.id), func.coalesce(func.sum(func.cast(AttackEvent.blocked, func.INTEGER)), 0)).join(
		ClientInstallation, AttackEvent.target_client_id == ClientInstallation.id, isouter=False
	).where(ClientInstallation.organization_id == org_id, AttackEvent.detected_at >= cutoff)
	if dept_id is not None:
		attack_query = attack_query.where(ClientInstallation.department_id == dept_id)
	attack_result = await db.execute(attack_query)
	attack_row = attack_result.one()
	attack_events = int(attack_row[0] or 0)
	blocked_attacks = int(attack_row[1] or 0)

	defense_query = select(func.count(DefenseAction.id)).join(
		ClientInstallation, DefenseAction.client_id == ClientInstallation.id, isouter=False
	).where(ClientInstallation.organization_id == org_id, DefenseAction.created_at >= cutoff)
	if dept_id is not None:
		defense_query = defense_query.where(ClientInstallation.department_id == dept_id)
	defense_result = await db.execute(defense_query)
	defense_actions = int(defense_result.scalar_one_or_none() or 0)

	return {
		"organization_id": org_id,
		"department_id": dept_id,
		"lookback_days": lookback_days,
		"generated_at": datetime.utcnow().isoformat() + "Z",
		"clients": {
			"total": len(clients),
			"active": active_clients,
			"protected": protected_clients,
			"recently_seen": recent_clients,
		},
		"scans": {
			"total": scan_count,
			"malicious_or_high": malicious_scans,
		},
		"security_actions": {
			"attack_events": attack_events,
			"blocked_attacks": blocked_attacks,
			"defense_actions": defense_actions,
		},
		"client_ids": client_ids[:200],
	}

