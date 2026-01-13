"""
Database Migration Script
Initializes or updates the database with all required tables
"""

import asyncio
import sys
from pathlib import Path

# Add server directory to path
sys.path.insert(0, str(Path(__file__).parent))

from app.database import Base, engine, init_db
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


async def migrate_database():
    """Initialize or migrate database schema"""
    print("=" * 60)
    print("SENTINEL-AI Database Migration")
    print("=" * 60)
    print()

    try:
        print("Creating database tables...")
        print()

        # Initialize all tables
        await init_db()

        print("✓ Database tables created successfully!")
        print()
        print("Tables created:")
        print("  - users")
        print("  - threats")
        print("  - response_actions")
        print("  - system_logs")
        print("  - api_cache")
        print("  - scan_history (NEW)")
        print("  - client_installations (NEW)")
        print("  - attack_events (NEW)")
        print("  - defense_actions (NEW)")
        print("  - network_alerts (NEW)")
        print()
        print("✓ Database migration complete!")

    except Exception as e:
        print(f"✗ Migration failed: {e}")
        sys.exit(1)


async def verify_database():
    """Verify database tables exist"""
    print()
    print("Verifying database structure...")
    print()

    try:
        from sqlalchemy import inspect
        from sqlalchemy.ext.asyncio import AsyncSession

        async with AsyncSession(engine) as session:
            # Use run_sync to run the inspection in a sync context
            def check_tables(conn):
                inspector = inspect(conn)
                return inspector.get_table_names()

            async with engine.begin() as conn:
                tables = await conn.run_sync(check_tables)

            expected_tables = [
                "users",
                "threats",
                "response_actions",
                "system_logs",
                "api_cache",
                "scan_history",
                "client_installations",
                "attack_events",
                "defense_actions",
                "network_alerts",
            ]

            missing_tables = [t for t in expected_tables if t not in tables]

            if missing_tables:
                print(f"⚠ Warning: Missing tables: {', '.join(missing_tables)}")
                return False
            else:
                print("✓ All tables verified successfully!")
                print()
                print(f"Total tables: {len(tables)}")
                for table in sorted(tables):
                    print(f"  ✓ {table}")
                return True

    except Exception as e:
        print(f"✗ Verification failed: {e}")
        return False


async def create_test_data():
    """Create sample test data"""
    print()
    print("Creating test data...")
    print()

    try:
        from sqlalchemy.ext.asyncio import AsyncSession

        async with AsyncSession(engine) as session:
            # Check if admin user exists
            from sqlalchemy.future import select

            result = await session.execute(select(User).where(User.username == "admin"))
            admin = result.scalar_one_or_none()

            if not admin:
                from app.auth import get_password_hash

                admin = User(
                    username="admin",
                    email="admin@sentinelai.local",
                    hashed_password=get_password_hash("admin123"),
                    full_name="System Administrator",
                    is_active=True,
                    is_admin=True,
                )
                session.add(admin)
                await session.commit()
                print("✓ Created admin user (username: admin, password: admin123)")
            else:
                print("✓ Admin user already exists")

            print()
            print("✓ Test data creation complete!")

    except Exception as e:
        print(f"⚠ Test data creation failed: {e}")
        print("  You may need to create users manually")


async def main():
    """Main migration function"""
    import argparse

    parser = argparse.ArgumentParser(description="SENTINEL-AI Database Migration")
    parser.add_argument(
        "--verify-only", action="store_true", help="Only verify database structure"
    )
    parser.add_argument(
        "--with-test-data", action="store_true", help="Create test data after migration"
    )

    args = parser.parse_args()

    if args.verify_only:
        await verify_database()
    else:
        await migrate_database()
        await verify_database()

        if args.with_test_data:
            await create_test_data()

    print()
    print("=" * 60)
    print("Migration process complete!")
    print("=" * 60)
    print()
    print("Next steps:")
    print("1. Start the server: python run_server.py")
    print("2. Register clients: python client/sentinel_client_enhanced.py")
    print("3. Generate reports via API endpoints")
    print()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nMigration cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
        sys.exit(1)
