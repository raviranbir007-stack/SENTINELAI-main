
from datetime import timedelta
from functools import wraps
from typing import Callable, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ....auth import create_access_token, get_password_hash, verify_password, verify_token
from ....config import settings
from ....database import get_db
from ....models import Department, Organization, Permission, Role, User

router = APIRouter()
auth_scheme = HTTPBearer(auto_error=False)

DEFAULT_ORGANIZATION_SLUG = "sentinel-default"
DEFAULT_DEPARTMENT_SLUG = "general"

DEFAULT_PERMISSION_DEFINITIONS = {
    "users.read": "View users and identity records",
    "users.manage": "Create and update users and roles",
    "devices.read": "View endpoint inventory",
    "devices.manage": "Enroll, update, or disable endpoints",
    "alerts.read": "View alerts and incidents",
    "alerts.manage": "Acknowledge, escalate, or close alerts",
    "reports.read": "View reports and dashboards",
    "reports.export": "Export reports and evidence",
    "policies.read": "View policies and control settings",
    "policies.manage": "Create and update policies",
    "audits.read": "View audit logs and compliance history",
}

DEFAULT_ROLE_PERMISSIONS = {
    "admin": set(DEFAULT_PERMISSION_DEFINITIONS.keys()),
    "analyst": {"alerts.read", "reports.read", "reports.export", "devices.read", "audits.read"},
    "responder": {"alerts.read", "alerts.manage", "devices.read", "devices.manage", "audits.read"},
    "auditor": {"alerts.read", "reports.read", "reports.export", "audits.read"},
    "standard_user": {"alerts.read", "reports.read"},
}


class LoginRequest(BaseModel):
    username: str
    password: str


def _slugify(value: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value or "")).strip("-")
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned or "default"


async def _ensure_default_catalog(db: AsyncSession) -> Dict[str, object]:
    organization = (
        await db.execute(select(Organization).where(Organization.slug == DEFAULT_ORGANIZATION_SLUG))
    ).scalar_one_or_none()
    if organization is None:
        organization = Organization(
            name=settings.PROJECT_NAME,
            slug=DEFAULT_ORGANIZATION_SLUG,
            description="Default organization created for Sentinel AI",
            retention_days=90,
            is_active=True,
        )
        db.add(organization)
        await db.flush()

    department = (
        await db.execute(
            select(Department).where(
                Department.organization_id == organization.id,
                Department.slug == DEFAULT_DEPARTMENT_SLUG,
            )
        )
    ).scalar_one_or_none()
    if department is None:
        department = Department(
            organization_id=organization.id,
            name="General",
            slug=DEFAULT_DEPARTMENT_SLUG,
            description="Default department",
            is_active=True,
        )
        db.add(department)
        await db.flush()

    permissions: Dict[str, Permission] = {}
    for code, description in DEFAULT_PERMISSION_DEFINITIONS.items():
        permission = (await db.execute(select(Permission).where(Permission.code == code))).scalar_one_or_none()
        if permission is None:
            permission = Permission(code=code, description=description)
            db.add(permission)
            await db.flush()
        permissions[code] = permission

    roles: Dict[str, Role] = {}
    for role_name, permission_codes in DEFAULT_ROLE_PERMISSIONS.items():
        role = (await db.execute(select(Role).where(Role.name == role_name))).scalar_one_or_none()
        if role is None:
            role = Role(name=role_name, description=f"System role: {role_name}", is_system=True)
            db.add(role)
            await db.flush()
        current_permission_codes = {permission.code for permission in role.permissions}
        for code in permission_codes:
            permission = permissions[code]
            if code not in current_permission_codes:
                role.permissions.append(permission)
        roles[role_name] = role

    await db.flush()
    return {"organization": organization, "department": department, "roles": roles}


def _user_context(user: User) -> Dict[str, object]:
    role_names = sorted({role.name for role in user.roles})
    permission_codes = sorted({permission.code for role in user.roles for permission in role.permissions})
    role_name = "admin" if user.is_admin else (role_names[0] if role_names else "standard_user")
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "role": role_name,
        "roles": role_names,
        "permissions": permission_codes,
        "organization_id": user.organization_id,
        "department_id": user.department_id,
        "organization": user.organization.name if user.organization else None,
        "department": user.department.name if user.department else None,
    }


async def _load_user_by_username(db: AsyncSession, username: str) -> Optional[User]:
    result = await db.execute(
        select(User)
        .options(
            selectinload(User.roles).selectinload(Role.permissions),
            selectinload(User.organization),
            selectinload(User.department),
        )
        .where(User.username == username)
    )
    return result.scalar_one_or_none()


async def get_current_user_obj(
    credentials: HTTPAuthorizationCredentials = Depends(auth_scheme),
    db: AsyncSession = Depends(get_db),
):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    try:
        token_data = verify_token(credentials.credentials)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")

    user = await _load_user_by_username(db, token_data.username or "")
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is disabled")
    return user


async def admin_required(user: User = Depends(get_current_user_obj)):
    if not user.is_admin and all(role.name != "admin" for role in user.roles):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user


def user_has_permission(user: User, permission_code: str) -> bool:
    if user.is_admin:
        return True
    return any(permission.code == permission_code for role in user.roles for permission in role.permissions)


def require_permission(permission_code: str) -> Callable:
    async def _dependency(user: User = Depends(get_current_user_obj)) -> User:
        if not user_has_permission(user, permission_code):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {permission_code}",
            )
        return user

    return _dependency


@router.post("/register")
async def register(
    username: str,
    password: str,
    email: Optional[str] = None,
    full_name: Optional[str] = None,
    organization_name: Optional[str] = None,
    department_name: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Register a new user and place them in the default tenant structure."""
    existing = await db.execute(select(User).where(User.username == username))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already exists")

    defaults = await _ensure_default_catalog(db)
    organization = defaults["organization"]
    department = defaults["department"]

    if organization_name:
        custom_org = _slugify(organization_name)
        org_result = await db.execute(select(Organization).where(Organization.slug == custom_org))
        organization = org_result.scalar_one_or_none() or Organization(
            name=organization_name,
            slug=custom_org,
            description="User-provisioned organization",
            retention_days=90,
            is_active=True,
        )
        if organization.id is None:
            db.add(organization)
            await db.flush()

    if department_name:
        custom_department = _slugify(department_name)
        dept_result = await db.execute(
            select(Department).where(
                Department.organization_id == organization.id,
                Department.slug == custom_department,
            )
        )
        department = dept_result.scalar_one_or_none() or Department(
            organization_id=organization.id,
            name=department_name,
            slug=custom_department,
            description="User-provisioned department",
            is_active=True,
        )
        if department.id is None:
            db.add(department)
            await db.flush()

    hashed = get_password_hash(password)
    new_user = User(
        username=username,
        email=email or f"{username}@sentinel-ai.local",
        full_name=full_name,
        hashed_password=hashed,
        is_active=True,
        is_admin=False,
        organization_id=organization.id,
        department_id=department.id,
    )
    db.add(new_user)
    await db.flush()

    standard_role = defaults["roles"]["standard_user"]
    if standard_role not in new_user.roles:
        new_user.roles.append(standard_role)

    await db.commit()
    await db.refresh(new_user)
    return {
        "status": "success",
        "message": "User registered successfully",
        "user": _user_context(new_user),
    }


@router.post("/login")
async def login(request: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Login against the database-backed identity store."""
    user = await _load_user_by_username(db, request.username)

    if user and verify_password(request.password, user.hashed_password):
        defaults = await _ensure_default_catalog(db)
        if user.organization_id is None or user.department_id is None:
            user.organization_id = user.organization_id or defaults["organization"].id
            user.department_id = user.department_id or defaults["department"].id
            await db.commit()
            await db.refresh(user)

        token = create_access_token(
            {
                "sub": user.username,
                "admin": user.is_admin,
                "organization_id": user.organization_id,
                "department_id": user.department_id,
                "roles": [role.name for role in user.roles],
            },
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        )
        return {
            "status": "success",
            "access_token": token,
            "token_type": "bearer",
            "user": _user_context(user),
        }

    admin_user = str(getattr(settings, "ADMIN_EMAIL", "") or "admin").split("@")[0] or "admin"
    master_pw = str(settings.MASTER_CLIENT_PASSWORD or "")
    if master_pw and request.username in {"admin", admin_user} and request.password == master_pw:
        defaults = await _ensure_default_catalog(db)
        token = create_access_token(
            {
                "sub": "admin",
                "admin": True,
                "organization_id": defaults["organization"].id,
                "department_id": defaults["department"].id,
                "roles": ["admin"],
            },
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        )
        return {
            "status": "success",
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": 0,
                "username": "admin",
                "email": settings.ADMIN_EMAIL or "admin@sentinel-ai.com",
                "role": "admin",
                "roles": ["admin"],
                "organization_id": defaults["organization"].id,
                "department_id": defaults["department"].id,
            },
        }

    raise HTTPException(status_code=401, detail="Invalid username or password")


@router.post("/logout")
async def logout():
    """Logout — client should discard the token."""
    return {"status": "success", "message": "Logged out successfully"}


@router.get("/me")
async def get_current_user(user: User = Depends(get_current_user_obj)):
    """Get current user info from the verified JWT token."""
    return _user_context(user)
