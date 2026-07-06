import asyncio
import os
import logging
from pathlib import Path

from .config import settings

from sqlalchemy import event, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import NullPool


logger = logging.getLogger(__name__)


SQLITE_WRITE_LOCK = asyncio.Lock()


# Ensure an async driver is used for sqlite when running async engine
db_url = settings.DATABASE_URL

# Normalize relative sqlite paths to an absolute path under the server directory
if db_url.startswith("sqlite:///"):
    sqlite_path = db_url.replace("sqlite:///", "")
    if sqlite_path.startswith("./"):
        base_dir = Path(__file__).resolve().parents[2]
        abs_path = (base_dir / sqlite_path[2:]).resolve()
        db_url = f"sqlite:///{abs_path}"
    elif not sqlite_path.startswith("/"):
        base_dir = Path(__file__).resolve().parents[2]
        abs_path = (base_dir / sqlite_path).resolve()
        db_url = f"sqlite:///{abs_path}"
if db_url.startswith("sqlite://") and "+aiosqlite" not in db_url:
    if db_url.startswith("sqlite:///"):
        db_url = db_url.replace("sqlite:///", "sqlite+aiosqlite:///")
    else:
        db_url = db_url.replace("sqlite://", "sqlite+aiosqlite://")


is_sqlite_async = db_url.startswith("sqlite+aiosqlite://")

engine_kwargs = {
    "echo": os.getenv("SQL_ECHO", "false").lower() == "true",
    "future": True,
}

if is_sqlite_async:
    # Avoid reusing stale/closed sqlite connections under async workloads.
    # This also prevents rollback-on-checkin against already-closed handles.
    engine_kwargs.update(
        {
            "poolclass": NullPool,
            "connect_args": {"timeout": 120},  # Increased from 60 for more concurrency
        }
    )
else:
    engine_kwargs.update(
        {
            "pool_pre_ping": True,
            "pool_recycle": 3600,
        }
    )

engine = create_async_engine(
    db_url,
    **engine_kwargs,
)


if is_sqlite_async:
    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, _connection_record):
        """Harden sqlite for concurrent read/write workloads."""
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA busy_timeout=120000")  # Increased from 60000 for lock waits
            cursor.execute("PRAGMA temp_store=MEMORY")
            cursor.execute("PRAGMA cache_size=-64000")  # 64MB cache for better performance
            cursor.execute("PRAGMA foreign_keys=ON")  # Enable foreign key constraints
            cursor.execute("PRAGMA wal_autocheckpoint=1000")  # Checkpoint every 1000 pages
        finally:
            cursor.close()

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)

# Base class for models
Base = declarative_base()


async def get_db():
    """Get database session"""
    session = AsyncSessionLocal()
    try:
        yield session
    finally:
        try:
            await session.close()
        except (OperationalError, ValueError) as exc:
            # Defensive guard for intermittent aiosqlite teardown race:
            # ValueError("no active connection") wrapped as sqlite OperationalError.
            if "no active connection" in str(exc).lower():
                logger.debug("Suppressed sqlite close race in get_db: %s", exc)
            else:
                raise


async def init_db():
    """Initialize database and apply safe column migrations"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Safe column migrations — add new columns that might not exist in older DBs
        safe_migrations = [
            "ALTER TABLE scan_history ADD COLUMN scan_source VARCHAR(20) DEFAULT 'manual'",
            "ALTER TABLE users ADD COLUMN organization_id INTEGER",
            "ALTER TABLE users ADD COLUMN department_id INTEGER",
            "ALTER TABLE client_installations ADD COLUMN organization_id INTEGER",
            "ALTER TABLE client_installations ADD COLUMN department_id INTEGER",
            (
                "UPDATE scan_history "
                "SET scan_source = 'client_protection' "
                "WHERE scan_source = 'manual' "
                "AND client_id IS NULL "
                "AND target_type = 'file_hash' "
                "AND (scan_id LIKE 'SCAN_%' OR scan_id LIKE 'GEN_%')"
            ),
        ]
        for stmt in safe_migrations:
            try:
                await conn.execute(text(stmt))
                logger.info(f"Migration applied: {stmt[:60]}")
            except Exception as e:
                if "duplicate column" in str(e).lower() or "already exists" in str(e).lower():
                    pass  # Column already present — ignore
                else:
                    logger.debug(f"Migration skipped ({stmt[:50]}): {e}")

    # Seed the default tenant and identity catalog so the platform starts usable.
    try:
        from .models import (
            Department,
            Policy,
            Organization,
            Permission,
            Role,
        )
        from .core.policy_manager import DEFAULT_POLICY_RULES

        default_permissions = {
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
        role_permissions = {
            "admin": set(default_permissions.keys()),
            "analyst": {"alerts.read", "reports.read", "reports.export", "devices.read", "audits.read"},
            "responder": {"alerts.read", "alerts.manage", "devices.read", "devices.manage", "audits.read"},
            "auditor": {"alerts.read", "reports.read", "reports.export", "audits.read"},
            "standard_user": {"alerts.read", "reports.read"},
        }

        async with AsyncSessionLocal() as session:
            org_result = await session.execute(select(Organization).where(Organization.slug == "sentinel-default"))
            organization = org_result.scalar_one_or_none()
            if organization is None:
                organization = Organization(
                    name=settings.PROJECT_NAME,
                    slug="sentinel-default",
                    description="Default organization created on startup",
                    retention_days=90,
                    is_active=True,
                )
                session.add(organization)
                await session.flush()

            dept_result = await session.execute(
                select(Department).where(
                    Department.organization_id == organization.id,
                    Department.slug == "general",
                )
            )
            department = dept_result.scalar_one_or_none()
            if department is None:
                department = Department(
                    organization_id=organization.id,
                    name="General",
                    slug="general",
                    description="Default department",
                    is_active=True,
                )
                session.add(department)
                await session.flush()

            permissions = {}
            for code, description in default_permissions.items():
                perm_result = await session.execute(select(Permission).where(Permission.code == code))
                permission = perm_result.scalar_one_or_none()
                if permission is None:
                    permission = Permission(code=code, description=description)
                    session.add(permission)
                    await session.flush()
                permissions[code] = permission

            for role_name, permission_codes in role_permissions.items():
                role_result = await session.execute(select(Role).where(Role.name == role_name))
                role = role_result.scalar_one_or_none()
                if role is None:
                    role = Role(name=role_name, description=f"System role: {role_name}", is_system=True)
                    session.add(role)
                    await session.flush()
                current_codes = {permission.code for permission in role.permissions}
                for code in permission_codes:
                    permission = permissions[code]
                    if code not in current_codes:
                        role.permissions.append(permission)

            policy_result = await session.execute(
                select(Policy).where(
                    Policy.organization_id == organization.id,
                    Policy.department_id.is_(None),
                    Policy.policy_type == "detection",
                    Policy.name == "Default Detection Policy",
                )
            )
            policy = policy_result.scalar_one_or_none()
            if policy is None:
                policy = Policy(
                    organization_id=organization.id,
                    department_id=None,
                    name="Default Detection Policy",
                    policy_type="detection",
                    enabled=True,
                    version=1,
                    rules=DEFAULT_POLICY_RULES,
                )
                session.add(policy)

            await session.commit()
    except Exception as exc:
        logger.debug("Default tenant seeding skipped: %s", exc)


async def close_db():
    """Close database connection"""
    await engine.dispose()


def is_sqlite_lock_error(exc: Exception) -> bool:
    """Return True when an exception corresponds to a transient SQLite lock."""
    message = str(exc).lower()
    return "database is locked" in message or "database table is locked" in message


async def execute_sqlite_write(
    db: AsyncSession,
    operation_name: str,
    operation,
    max_attempts: int = 4,
    base_delay: float = 0.2,
):
    """Serialize and retry SQLite write operations to reduce lock contention."""
    last_error = None
    for attempt in range(max_attempts):
        try:
            if is_sqlite_async:
                async with SQLITE_WRITE_LOCK:
                    return await operation()
            return await operation()
        except OperationalError as exc:
            last_error = exc
            try:
                await db.rollback()
            except Exception:
                pass

            if is_sqlite_lock_error(exc) and attempt < (max_attempts - 1):
                backoff = base_delay * (attempt + 1)
                logger.warning(
                    "Database locked during %s (attempt %s/%s); retrying in %.1fs",
                    operation_name,
                    attempt + 1,
                    max_attempts,
                    backoff,
                )
                await asyncio.sleep(backoff)
                continue
            raise

    if last_error:
        raise last_error
