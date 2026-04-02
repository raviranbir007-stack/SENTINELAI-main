"""
002_v3_features - Version 3.0 Features Migration
Adds defense events, quarantine, activity logging, and blocking tables
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def upgrade():
    """Migrate database to v3.0 schema"""
    # For now, this is a direct SQLite migration
    # In the future, this should be converted to SQLAlchemy operations

    db_path = Path(__file__).parent.parent / "sentinel.db"
    if not db_path.exists():
        # Try alternative locations
        alt_paths = [
            Path(__file__).parent.parent / "instance" / "sentinel.db",
            Path(__file__).parent.parent.parent / "sentinel.db",
        ]
        for alt_path in alt_paths:
            if alt_path.exists():
                db_path = alt_path
                break

    if not db_path.exists():
        logger.warning(f"Database not found at {db_path}, skipping v3 migration")
        return

    logger.info(f"Starting database migration to v3.0...")
    logger.info(f"Database path: {db_path}")

    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # 1. Defense Events Table
        logger.info("Creating defense_events table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS defense_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                source_ip TEXT,
                target_ip TEXT,
                action_taken TEXT,
                success BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT
            )
        ''')

        # 2. Quarantine Table
        logger.info("Creating quarantine table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                file_hash TEXT,
                threat_type TEXT,
                quarantined_by TEXT,
                quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                original_location TEXT,
                restore_status TEXT DEFAULT 'available'
            )
        ''')

        # 3. Activity Log Table
        logger.info("Creating activity_log table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT NOT NULL,
                activity_type TEXT NOT NULL,
                description TEXT,
                source TEXT,
                severity TEXT DEFAULT 'info',
                logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT
            )
        ''')

        # 4. Blocking Rules Table
        logger.info("Creating blocking_rules table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocking_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_type TEXT NOT NULL,  -- 'ip', 'domain', 'port'
                target_value TEXT NOT NULL,
                reason TEXT,
                created_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                hit_count INTEGER DEFAULT 0
            )
        ''')

        # 5. Client Heartbeat Table
        logger.info("Creating client_heartbeat table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS client_heartbeat (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT NOT NULL UNIQUE,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'active',
                version TEXT,
                ip_address TEXT,
                metadata TEXT
            )
        ''')

        # Create indexes for performance
        logger.info("Creating indexes...")
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_defense_events_client_id ON defense_events(client_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_defense_events_created_at ON defense_events(created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_log_client_id ON activity_log(client_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_log_logged_at ON activity_log(logged_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocking_rules_type ON blocking_rules(rule_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_client_heartbeat_last_seen ON client_heartbeat(last_seen)')

        conn.commit()
        logger.info("✅ Successfully migrated database to v3.0 schema")

    except Exception as e:
        logger.error(f"Failed to migrate database: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()


async def main():
    """Run migration directly"""
    await upgrade()


if __name__ == "__main__":
    asyncio.run(main())