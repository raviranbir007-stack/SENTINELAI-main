"""Policy administration endpoints for tenant-specific operational control."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ....database import get_db
from ....models import AuditLog, Department, Organization, Policy, User
from ....core.policy_manager import (
    normalize_policy_rules,
    policy_detector_snapshot,
    policy_runtime_snapshot,
)
from ....core.threat_analyzer import threat_analyzer
from .auth import get_current_user_obj, require_permission

logger = logging.getLogger(__name__)
router = APIRouter()


class PolicyCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    policy_type: str = Field("detection", min_length=2, max_length=80)
    organization_id: Optional[int] = None
    department_id: Optional[int] = None
    enabled: bool = True
    rules: Dict[str, Any] = Field(default_factory=dict)


class PolicyUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=120)
    policy_type: Optional[str] = Field(default=None, min_length=2, max_length=80)
    enabled: Optional[bool] = None
    rules: Optional[Dict[str, Any]] = None
    department_id: Optional[int] = None


def _serialize_policy(policy: Policy) -> Dict[str, Any]:
    return {
        "id": policy.id,
        "name": policy.name,
        "policy_type": policy.policy_type,
        "organization_id": policy.organization_id,
        "department_id": policy.department_id,
        "enabled": bool(policy.enabled),
        "version": int(policy.version or 1),
        "rules": policy.rules or {},
        "created_at": policy.created_at.isoformat() if policy.created_at else None,
        "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
    }


async def _get_default_org(db: AsyncSession) -> Organization:
    result = await db.execute(select(Organization).where(Organization.slug == "sentinel-default"))
    organization = result.scalar_one_or_none()
    if organization is None:
        raise HTTPException(status_code=404, detail="Default organization not initialized")
    return organization


async def _resolve_scope(
    db: AsyncSession,
    current_user: User,
    organization_id: Optional[int],
    department_id: Optional[int],
) -> tuple[int, Optional[int]]:
    if organization_id is None:
        organization_id = current_user.organization_id
    if organization_id is None:
        default_org = await _get_default_org(db)
        organization_id = default_org.id

    if department_id is None:
        department_id = current_user.department_id

    if department_id is not None:
        dept_result = await db.execute(
            select(Department).where(
                Department.id == department_id,
                Department.organization_id == organization_id,
            )
        )
        if dept_result.scalar_one_or_none() is None:
            raise HTTPException(status_code=400, detail="Invalid department for organization")

    return organization_id, department_id


async def _audit_policy_change(
    db: AsyncSession,
    *,
    actor: User,
    policy: Policy,
    action: str,
    before: Optional[Dict[str, Any]],
    after: Optional[Dict[str, Any]],
    outcome: str = "success",
) -> None:
    log_entry = AuditLog(
        organization_id=policy.organization_id,
        department_id=policy.department_id,
        actor_user_id=actor.id,
        action=action,
        resource_type="policy",
        resource_id=str(policy.id),
        outcome=outcome,
        details={"policy_name": policy.name, "policy_type": policy.policy_type},
        before_state=before,
        after_state=after,
    )
    db.add(log_entry)


@router.get("")
async def list_policies(
    organization_id: Optional[int] = Query(default=None),
    department_id: Optional[int] = Query(default=None),
    enabled_only: bool = Query(default=False),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("policies.read")),
):
    org_id, dept_id = await _resolve_scope(db, current_user, organization_id, department_id)
    query = select(Policy).where(Policy.organization_id == org_id)
    if dept_id is None:
        query = query.where(Policy.department_id.is_(None))
    else:
        query = query.where(or_(Policy.department_id.is_(None), Policy.department_id == dept_id))
    if enabled_only:
        query = query.where(Policy.enabled.is_(True))

    result = await db.execute(query.order_by(Policy.policy_type.asc(), Policy.name.asc()))
    policies = result.scalars().all()
    return {
        "available": True,
        "count": len(policies),
        "organization_id": org_id,
        "department_id": dept_id,
        "policies": [_serialize_policy(policy) for policy in policies],
    }


@router.get("/effective")
async def get_effective_policy(
    policy_type: str = Query("detection"),
    organization_id: Optional[int] = Query(default=None),
    department_id: Optional[int] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("policies.read")),
):
    org_id, dept_id = await _resolve_scope(db, current_user, organization_id, department_id)
    query = select(Policy).where(
        Policy.organization_id == org_id,
        Policy.policy_type == policy_type,
        Policy.enabled.is_(True),
    ).order_by(Policy.department_id.desc().nullslast(), Policy.version.desc(), Policy.id.desc())
    if dept_id is not None:
        query = query.where(or_(Policy.department_id.is_(None), Policy.department_id == dept_id))
    else:
        query = query.where(Policy.department_id.is_(None))

    result = await db.execute(query)
    policies = result.scalars().all()
    selected = policies[0] if policies else None
    if selected is None:
        return {
            "available": False,
            "policy_type": policy_type,
            "organization_id": org_id,
            "department_id": dept_id,
            "rules": {},
            "runtime": policy_runtime_snapshot({}),
        }

    rules = normalize_policy_rules(selected.rules or {})
    return {
        "available": True,
        "policy": _serialize_policy(selected),
        "organization_id": org_id,
        "department_id": dept_id,
        "rules": rules,
        "detector": policy_detector_snapshot(rules),
        "runtime": policy_runtime_snapshot(rules),
    }


@router.post("")
async def create_policy(
    request: PolicyCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("policies.manage")),
):
    org_id, dept_id = await _resolve_scope(db, current_user, request.organization_id, request.department_id)
    policy = Policy(
        organization_id=org_id,
        department_id=dept_id,
        name=request.name,
        policy_type=request.policy_type,
        enabled=request.enabled,
        version=1,
        rules=normalize_policy_rules(request.rules),
        created_by_user_id=current_user.id,
        updated_by_user_id=current_user.id,
    )
    db.add(policy)
    await db.flush()
    await _audit_policy_change(db, actor=current_user, policy=policy, action="policy.create", before=None, after=_serialize_policy(policy))
    await db.commit()

    if policy.policy_type == "detection" and policy.enabled:
        snapshot = policy_detector_snapshot(policy.rules)
        threat_analyzer.apply_detector_config(
            profiles=snapshot["profiles"],
            calibration=snapshot["calibration"],
            persist=True,
        )

    await db.refresh(policy)
    return {"status": "success", "policy": _serialize_policy(policy)}


@router.put("/{policy_id}")
async def update_policy(
    policy_id: int,
    request: PolicyUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("policies.manage")),
):
    result = await db.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")

    before = _serialize_policy(policy)
    if request.name is not None:
        policy.name = request.name
    if request.policy_type is not None:
        policy.policy_type = request.policy_type
    if request.enabled is not None:
        policy.enabled = request.enabled
    if request.rules is not None:
        policy.rules = normalize_policy_rules(request.rules)
    if request.department_id is not None:
        policy.department_id = request.department_id
    policy.version = int(policy.version or 1) + 1
    policy.updated_by_user_id = current_user.id
    policy.updated_at = datetime.utcnow()

    await _audit_policy_change(db, actor=current_user, policy=policy, action="policy.update", before=before, after=_serialize_policy(policy))
    await db.commit()
    await db.refresh(policy)

    if policy.policy_type == "detection" and policy.enabled:
        snapshot = policy_detector_snapshot(policy.rules)
        threat_analyzer.apply_detector_config(
            profiles=snapshot["profiles"],
            calibration=snapshot["calibration"],
            persist=True,
        )

    return {"status": "success", "policy": _serialize_policy(policy)}


@router.post("/{policy_id}/apply")
async def apply_policy(
    policy_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("policies.manage")),
):
    result = await db.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")

    rules = normalize_policy_rules(policy.rules or {})
    runtime = policy_runtime_snapshot(rules)
    detector = runtime["detector"]
    applied = threat_analyzer.apply_detector_config(
        profiles=detector.get("profiles", {}),
        calibration=detector.get("calibration", {}),
        persist=True,
    )

    await _audit_policy_change(
        db,
        actor=current_user,
        policy=policy,
        action="policy.apply",
        before={"runtime": runtime},
        after={"applied": applied},
    )
    await db.commit()
    return {"status": "success", "policy": _serialize_policy(policy), "applied": applied, "runtime": runtime}


@router.get("/audit")
async def policy_audit_log(
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("audits.read")),
):
    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.resource_type == "policy")
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
    )
    items = result.scalars().all()
    return {
        "available": True,
        "count": len(items),
        "items": [
            {
                "id": item.id,
                "action": item.action,
                "resource_id": item.resource_id,
                "outcome": item.outcome,
                "actor_user_id": item.actor_user_id,
                "organization_id": item.organization_id,
                "department_id": item.department_id,
                "created_at": item.created_at.isoformat() if item.created_at else None,
                "before_state": item.before_state,
                "after_state": item.after_state,
                "details": item.details,
            }
            for item in items
        ],
    }
