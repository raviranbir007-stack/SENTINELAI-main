#!/usr/bin/env python3
"""
SENTINEL-AI Database Migration Runner
Unified migration system for database schema updates
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import List

# Add server directory to path
sys.path.insert(0, str(Path(__file__).parent))

from app.database import engine
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MigrationRunner:
    """Unified database migration runner"""

    def __init__(self, migrations_dir: Path):
        self.migrations_dir = migrations_dir
        self.applied_migrations = set()

    async def get_applied_migrations(self) -> set:
        """Get list of already applied migrations"""
        applied = set()
        try:
            async with AsyncSession(engine) as session:
                # Check if migrations table exists
                result = await session.execute(text("""
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND name='schema_migrations'
                """))
                if result.fetchone():
                    # Get applied migrations
                    result = await session.execute(text("SELECT migration_id FROM schema_migrations"))
                    applied = {row[0] for row in result.fetchall()}
        except Exception:
            pass  # Table doesn't exist yet
        return applied

    async def record_migration(self, migration_id: str):
        """Record a migration as applied"""
        async with AsyncSession(engine) as session:
            # Create migrations table if it doesn't exist
            await session.execute(text("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    migration_id TEXT PRIMARY KEY,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            # Record the migration
            await session.execute(
                text("INSERT INTO schema_migrations (migration_id) VALUES (:id)"),
                {"id": migration_id}
            )
            await session.commit()

    async def run_migration_file(self, migration_file: Path):
        """Run a single migration file"""
        migration_id = migration_file.stem

        if migration_id in self.applied_migrations:
            logger.info(f"Skipping already applied migration: {migration_id}")
            return

        logger.info(f"Running migration: {migration_id}")

        try:
            # Import the migration module
            spec = importlib.util.spec_from_file_location(migration_id, migration_file)
            migration_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(migration_module)

            # Run the migration
            if hasattr(migration_module, 'upgrade'):
                await migration_module.upgrade()
            else:
                logger.error(f"Migration {migration_id} missing upgrade() function")
                return

            # Record as applied
            await self.record_migration(migration_id)
            logger.info(f"Successfully applied migration: {migration_id}")

        except Exception as e:
            logger.error(f"Failed to apply migration {migration_id}: {e}")
            raise

    async def run_all_migrations(self):
        """Run all pending migrations in order"""
        logger.info("Starting database migrations...")

        # Get applied migrations
        self.applied_migrations = await self.get_applied_migrations()

        # Find all migration files
        migration_files = sorted(self.migrations_dir.glob("*.py"))
        migration_files = [f for f in migration_files if not f.name.startswith('_')]

        if not migration_files:
            logger.info("No migration files found")
            return

        logger.info(f"Found {len(migration_files)} migration files")

        # Run migrations in order
        for migration_file in migration_files:
            await self.run_migration_file(migration_file)

        logger.info("All migrations completed successfully")


async def main():
    """Main migration runner"""
    migrations_dir = Path(__file__).parent / "migrations"

    if not migrations_dir.exists():
        logger.error(f"Migrations directory not found: {migrations_dir}")
        sys.exit(1)

    runner = MigrationRunner(migrations_dir)
    await runner.run_all_migrations()


if __name__ == "__main__":
    import importlib.util
    asyncio.run(main())