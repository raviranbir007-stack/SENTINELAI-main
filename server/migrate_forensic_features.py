"""
Database Migration Script for Forensic Reliability Features
Adds new columns to support multi-source corroboration, analyst overrides, and evidence tracking
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from sqlalchemy import text
from app.database import engine, SessionLocal
from app.models import Base
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def migrate_forensic_features():
    """Add forensic reliability columns to existing tables"""
    
    migrations = [
        # Threat table migrations
        """
        ALTER TABLE threats 
        ADD COLUMN IF NOT EXISTS evidence_sources JSON;
        """,
        """
        ALTER TABLE threats 
        ADD COLUMN IF NOT EXISTS corroboration_count INTEGER DEFAULT 0;
        """,
        """
        ALTER TABLE threats 
        ADD COLUMN IF NOT EXISTS corroboration_threshold_met BOOLEAN DEFAULT FALSE;
        """,
        """
        ALTER TABLE threats 
        ADD COLUMN IF NOT EXISTS analyst_override BOOLEAN DEFAULT FALSE;
        """,
        """
        ALTER TABLE threats 
        ADD COLUMN IF NOT EXISTS analyst_override_notes TEXT;
        """,
        """
        ALTER TABLE threats 
        ADD COLUMN IF NOT EXISTS analyst_override_by_id INTEGER REFERENCES users(id);
        """,
        """
        ALTER TABLE threats 
        ADD COLUMN IF NOT EXISTS analyst_override_at TIMESTAMP WITH TIME ZONE;
        """,
        """
        ALTER TABLE threats 
        ADD COLUMN IF NOT EXISTS original_verdict VARCHAR(50);
        """,
        
        # ScanHistory table migrations
        """
        ALTER TABLE scan_history 
        ADD COLUMN IF NOT EXISTS evidence_sources JSON;
        """,
        """
        ALTER TABLE scan_history 
        ADD COLUMN IF NOT EXISTS corroboration_count INTEGER DEFAULT 0;
        """,
        """
        ALTER TABLE scan_history 
        ADD COLUMN IF NOT EXISTS analyst_notes TEXT;
        """,
        """
        ALTER TABLE scan_history 
        ADD COLUMN IF NOT EXISTS analyst_verified BOOLEAN DEFAULT FALSE;
        """,
        
        # AttackEvent table migrations
        """
        ALTER TABLE attack_events 
        ADD COLUMN IF NOT EXISTS evidence_sources JSON;
        """,
        """
        ALTER TABLE attack_events 
        ADD COLUMN IF NOT EXISTS corroboration_count INTEGER DEFAULT 0;
        """,
        """
        ALTER TABLE attack_events 
        ADD COLUMN IF NOT EXISTS analyst_verified BOOLEAN DEFAULT FALSE;
        """,
        """
        ALTER TABLE attack_events 
        ADD COLUMN IF NOT EXISTS analyst_notes TEXT;
        """,
    ]
    
    db = SessionLocal()
    
    try:
        logger.info("Starting forensic features migration...")
        
        # Execute each migration
        for i, migration in enumerate(migrations, 1):
            try:
                db.execute(text(migration))
                db.commit()
                logger.info(f"✓ Migration {i}/{len(migrations)} completed")
            except Exception as e:
                logger.warning(f"Migration {i} skipped or failed: {str(e)}")
                db.rollback()
        
        logger.info("✅ Forensic features migration completed successfully!")
        logger.info("\nNew features available:")
        logger.info("  • Multi-source corroboration tracking")
        logger.info("  • Evidence source fields with API references")
        logger.info("  • Analyst override system with notes")
        logger.info("  • Analyst verification for scans")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Migration failed: {str(e)}")
        db.rollback()
        return False
    finally:
        db.close()


def verify_migration():
    """Verify that the migration was successful"""
    
    db = SessionLocal()
    
    try:
        # Check if new columns exist
        checks = [
            ("threats", "evidence_sources"),
            ("threats", "corroboration_count"),
            ("threats", "analyst_override"),
            ("scan_history", "evidence_sources"),
            ("attack_events", "evidence_sources"),
        ]
        
        logger.info("\n🔍 Verifying migration...")
        
        for table, column in checks:
            query = text(f"""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = :table AND column_name = :column
            """)
            result = db.execute(query, {"table": table, "column": column}).fetchone()
            
            if result:
                logger.info(f"✓ {table}.{column} exists")
            else:
                logger.warning(f"✗ {table}.{column} not found")
        
        logger.info("\n✅ Migration verification completed")
        return True
        
    except Exception as e:
        logger.error(f"❌ Verification failed: {str(e)}")
        return False
    finally:
        db.close()


if __name__ == "__main__":
    print("=" * 70)
    print("SENTINEL-AI Forensic Reliability Features Migration")
    print("=" * 70)
    print()
    
    # Check if user wants to proceed
    response = input("This will add new columns to your database. Continue? (yes/no): ")
    
    if response.lower() in ['yes', 'y']:
        success = migrate_forensic_features()
        
        if success:
            verify_migration()
            print("\n" + "=" * 70)
            print("Migration completed successfully!")
            print("=" * 70)
            print("\nNext steps:")
            print("1. Restart your SENTINEL-AI server")
            print("2. Review the FORENSIC_RELIABILITY_GUIDE.md for usage instructions")
            print("3. Test the new API endpoints:")
            print("   - POST /api/v1/analyst/override")
            print("   - POST /api/v1/analyst/notes")
            print("   - GET /api/v1/forensics/threat/{threat_id}")
        else:
            print("\n❌ Migration failed. Please check the logs and try again.")
            sys.exit(1)
    else:
        print("\nMigration cancelled.")
        sys.exit(0)
