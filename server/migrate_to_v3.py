"""
Database Migration for v3.0 Features
Adds tables for defense events, quarantine, activity logging, and blocking
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def migrate_database(db_path: str = "instance/sentinel.db"):
    """Migrate database to v3.0 schema"""
    
    logger.info(f"Starting database migration to v3.0...")
    logger.info(f"Database path: {db_path}")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # 1. Defense Events Table
        logger.info("Creating defense_events table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS defense_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_data TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (client_id) REFERENCES clients(client_id)
            )
        ''')
        
        # 2. Quarantine Actions Table
        logger.info("Creating quarantine_actions table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantine_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT,
                admin_user TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (client_id) REFERENCES clients(client_id)
            )
        ''')
        
        # 3. Blocked Entities Table
        logger.info("Creating blocked_entities table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_entities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target TEXT NOT NULL,
                reason TEXT,
                blocked_by TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                unblocked BOOLEAN DEFAULT 0,
                unblocked_at DATETIME,
                FOREIGN KEY (client_id) REFERENCES clients(client_id)
            )
        ''')
        
        # 4. Activity Logs Table
        logger.info("Creating activity_logs table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT NOT NULL,
                activity_type TEXT NOT NULL,
                target TEXT NOT NULL,
                risk_level TEXT,
                analysis_data TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (client_id) REFERENCES clients(client_id)
            )
        ''')
        
        # 5. Update clients table to add quarantine fields
        logger.info("Updating clients table...")
        try:
            cursor.execute('''
                ALTER TABLE clients ADD COLUMN quarantine_time DATETIME
            ''')
            logger.info("Added quarantine_time column to clients table")
        except sqlite3.OperationalError as e:
            if "duplicate column" in str(e).lower():
                logger.info("quarantine_time column already exists")
            else:
                raise
        
        try:
            cursor.execute('''
                ALTER TABLE clients ADD COLUMN last_activity DATETIME
            ''')
            logger.info("Added last_activity column to clients table")
        except sqlite3.OperationalError as e:
            if "duplicate column" in str(e).lower():
                logger.info("last_activity column already exists")
            else:
                raise
        
        # 6. Create indexes for performance
        logger.info("Creating indexes...")
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_defense_events_client 
            ON defense_events(client_id, timestamp)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_defense_events_type 
            ON defense_events(event_type, timestamp)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_blocked_entities_client 
            ON blocked_entities(client_id, timestamp)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_blocked_entities_target 
            ON blocked_entities(target_type, target)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_activity_logs_client 
            ON activity_logs(client_id, timestamp)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_activity_logs_type 
            ON activity_logs(activity_type, timestamp)
        ''')
        
        # Commit all changes
        conn.commit()
        
        logger.info("✅ Database migration completed successfully!")
        
        # Print table stats
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        logger.info(f"Total tables: {len(tables)}")
        
        conn.close()
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Migration failed: {e}", exc_info=True)
        return False


if __name__ == "__main__":
    import sys
    
    # Get database path from command line or use default
    db_path = sys.argv[1] if len(sys.argv) > 1 else "instance/sentinel.db"
    
    # Ensure instance directory exists
    Path("instance").mkdir(exist_ok=True)
    
    print("="*60)
    print("SENTINEL-AI Database Migration to v3.0")
    print("="*60)
    print()
    
    success = migrate_database(db_path)
    
    if success:
        print("\n✅ Migration completed successfully!")
        print("\nNew features added:")
        print("  • Real-time defense event tracking")
        print("  • Quarantine management")
        print("  • Blocked entities tracking")
        print("  • Comprehensive activity logging")
        print()
    else:
        print("\n❌ Migration failed. Check logs for details.")
        sys.exit(1)
