"""
003_forensic_columns - Forensic Evidence Tracking
Adds forensic evidence columns to existing tables
"""

import sqlite3
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def upgrade():
    """Add forensic evidence tracking columns"""

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
        logger.warning(f"Database not found at {db_path}, skipping forensic columns migration")
        return

    logger.info("Adding forensic evidence tracking columns...")

    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # Add forensic columns to threats table
        logger.info("Adding forensic columns to threats table...")
        try:
            cursor.execute('ALTER TABLE threats ADD COLUMN evidence_sources TEXT')
            logger.info("Added evidence_sources column to threats")
        except sqlite3.OperationalError:
            logger.info("evidence_sources column already exists in threats")

        try:
            cursor.execute('ALTER TABLE threats ADD COLUMN corroboration_count INTEGER DEFAULT 0')
            logger.info("Added corroboration_count column to threats")
        except sqlite3.OperationalError:
            logger.info("corroboration_count column already exists in threats")

        try:
            cursor.execute('ALTER TABLE threats ADD COLUMN analyst_override TEXT')
            logger.info("Added analyst_override column to threats")
        except sqlite3.OperationalError:
            logger.info("analyst_override column already exists in threats")

        try:
            cursor.execute('ALTER TABLE threats ADD COLUMN override_timestamp TIMESTAMP')
            logger.info("Added override_timestamp column to threats")
        except sqlite3.OperationalError:
            logger.info("override_timestamp column already exists in threats")

        # Add forensic columns to scan_history table
        logger.info("Adding forensic columns to scan_history table...")
        try:
            cursor.execute('ALTER TABLE scan_history ADD COLUMN ml_confidence REAL')
            logger.info("Added ml_confidence column to scan_history")
        except sqlite3.OperationalError:
            logger.info("ml_confidence column already exists in scan_history")

        try:
            cursor.execute('ALTER TABLE scan_history ADD COLUMN ai_analysis TEXT')
            logger.info("Added ai_analysis column to scan_history")
        except sqlite3.OperationalError:
            logger.info("ai_analysis column already exists in scan_history")

        try:
            cursor.execute('ALTER TABLE scan_history ADD COLUMN threat_intel_matches TEXT')
            logger.info("Added threat_intel_matches column to scan_history")
        except sqlite3.OperationalError:
            logger.info("threat_intel_matches column already exists in scan_history")

        # Add reliability columns to various tables
        tables_to_update = [
            ('attack_events', ['reliability_score REAL', 'false_positive BOOLEAN DEFAULT 0']),
            ('network_alerts', ['reliability_score REAL', 'escalation_level TEXT DEFAULT "low"']),
            ('system_logs', ['parsed BOOLEAN DEFAULT 0', 'correlation_id TEXT']),
        ]

        for table_name, columns in tables_to_update:
            logger.info(f"Adding reliability columns to {table_name}...")
            for column_def in columns:
                column_name = column_def.split()[0]
                try:
                    cursor.execute(f'ALTER TABLE {table_name} ADD COLUMN {column_def}')
                    logger.info(f"Added {column_name} column to {table_name}")
                except sqlite3.OperationalError:
                    logger.info(f"{column_name} column already exists in {table_name}")

        conn.commit()
        logger.info("✅ Successfully added forensic evidence tracking columns")

    except Exception as e:
        logger.error(f"Failed to add forensic columns: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()


async def main():
    """Run migration directly"""
    await upgrade()


if __name__ == "__main__":
    asyncio.run(main())