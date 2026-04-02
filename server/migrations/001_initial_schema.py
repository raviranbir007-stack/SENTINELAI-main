"""
001_initial_schema - Initial Database Schema
Creates all core tables for SENTINEL-AI
"""

import asyncio
import sys
from pathlib import Path

# Add server directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import Base, engine
from app.models import (
    APICache,
    AttackEvent,
    ClientInstallation,
    DefenseAction,
    NetworkAlert,
    ResponseAction,
    ScanHistory,
    SystemLog,
    Threat,
    User,
)


async def upgrade():
    """Create initial database schema"""
    async with engine.begin() as conn:
        # Create all tables
        await conn.run_sync(Base.metadata.create_all)

        print("✅ Created initial database schema with all tables")


async def main():
    """Run migration directly"""
    await upgrade()


if __name__ == "__main__":
    asyncio.run(main())