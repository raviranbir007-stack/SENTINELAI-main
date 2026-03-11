import os
from pathlib import Path

from .config import settings

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker


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


engine = create_async_engine(
    db_url,
    echo=os.getenv("SQL_ECHO", "false").lower() == "true",
    future=True,
    pool_pre_ping=True,
    pool_recycle=3600,
)

# Create async session factory
AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)

# Base class for models
Base = declarative_base()


async def get_db():
    """Get database session"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """Initialize database"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db():
    """Close database connection"""
    await engine.dispose()
