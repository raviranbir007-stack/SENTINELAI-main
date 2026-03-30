#!/usr/bin/env python3
"""
Forensic Features Database Migration
Adds forensic reliability columns to existing tables
"""

import sys
import sqlite3
from pathlib import Path

# Database path
DB_PATH = Path(__file__).parent / "test.db"


def migrate_forensic_features():
    """Add forensic reliability columns to existing tables"""
    print("=" * 70)
    print("SENTINEL-AI FORENSIC FEATURES DATABASE MIGRATION")
    print("=" * 70)
    print()
    
    if not DB_PATH.exists():
        print(f"✗ Database not found at: {DB_PATH}")
        print("  Run migrate_database.py first to create the database")
        return False
    
    print(f"Database: {DB_PATH}")
    print()
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    migrations = []
    
    # Check and add columns to threats table
    print("Checking threats table...")
    cursor.execute("PRAGMA table_info(threats)")
    threats_columns = {row[1] for row in cursor.fetchall()}
    
    if 'evidence_sources' not in threats_columns:
        migrations.append(("threats", "evidence_sources", "TEXT"))
    if 'corroboration_count' not in threats_columns:
        migrations.append(("threats", "corroboration_count", "INTEGER DEFAULT 0"))
    if 'corroboration_threshold_met' not in threats_columns:
        migrations.append(("threats", "corroboration_threshold_met", "BOOLEAN DEFAULT 0"))
    if 'analyst_override' not in threats_columns:
        migrations.append(("threats", "analyst_override", "BOOLEAN DEFAULT 0"))
    if 'analyst_override_notes' not in threats_columns:
        migrations.append(("threats", "analyst_override_notes", "TEXT"))
    if 'analyst_override_by_id' not in threats_columns:
        migrations.append(("threats", "analyst_override_by_id", "INTEGER"))
    if 'analyst_override_at' not in threats_columns:
        migrations.append(("threats", "analyst_override_at", "DATETIME"))
    if 'original_verdict' not in threats_columns:
        migrations.append(("threats", "original_verdict", "VARCHAR(50)"))
    
    # Check and add columns to scan_history table
    print("Checking scan_history table...")
    cursor.execute("PRAGMA table_info(scan_history)")
    scan_columns = {row[1] for row in cursor.fetchall()}
    
    if 'evidence_sources' not in scan_columns:
        migrations.append(("scan_history", "evidence_sources", "TEXT"))
    if 'corroboration_count' not in scan_columns:
        migrations.append(("scan_history", "corroboration_count", "INTEGER DEFAULT 0"))
    if 'analyst_notes' not in scan_columns:
        migrations.append(("scan_history", "analyst_notes", "TEXT"))
    if 'analyst_verified' not in scan_columns:
        migrations.append(("scan_history", "analyst_verified", "BOOLEAN DEFAULT 0"))
    if 'is_read' not in scan_columns:
        migrations.append(("scan_history", "is_read", "BOOLEAN DEFAULT 0"))
    
    # Check and add columns to attack_events table
    print("Checking attack_events table...")
    cursor.execute("PRAGMA table_info(attack_events)")
    attack_columns = {row[1] for row in cursor.fetchall()}
    
    if 'evidence_sources' not in attack_columns:
        migrations.append(("attack_events", "evidence_sources", "TEXT"))
    if 'corroboration_count' not in attack_columns:
        migrations.append(("attack_events", "corroboration_count", "INTEGER DEFAULT 0"))
    if 'analyst_verified' not in attack_columns:
        migrations.append(("attack_events", "analyst_verified", "BOOLEAN DEFAULT 0"))
    if 'analyst_notes' not in attack_columns:
        migrations.append(("attack_events", "analyst_notes", "TEXT"))
    
    print()
    
    if not migrations:
        print("✓ All forensic columns already exist - no migration needed")
        conn.close()
        return True
    
    print(f"Found {len(migrations)} columns to add:")
    print()
    
    # Apply migrations
    try:
        for table, column, column_type in migrations:
            sql = f"ALTER TABLE {table} ADD COLUMN {column} {column_type}"
            print(f"  Adding {table}.{column} ({column_type})...")
            cursor.execute(sql)
            print(f"  ✓ {table}.{column} added")
        
        conn.commit()
        print()
        print("=" * 70)
        print("✓ MIGRATION COMPLETED SUCCESSFULLY")
        print("=" * 70)
        print()
        print("Forensic reliability features are now active:")
        print("  ✓ Multi-source evidence tracking")
        print("  ✓ Corroboration counting (threshold: ≥2 sources)")
        print("  ✓ Analyst override capabilities")
        print("  ✓ Enhanced forensic reliability in reports")
        print()
        
        return True
        
    except Exception as e:
        conn.rollback()
        print()
        print("=" * 70)
        print("✗ MIGRATION FAILED")
        print("=" * 70)
        print(f"Error: {e}")
        print()
        return False
        
    finally:
        conn.close()


def verify_migration():
    """Verify that all forensic columns exist"""
    print("=" * 70)
    print("VERIFYING FORENSIC FEATURES")
    print("=" * 70)
    print()
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    required_columns = {
        'threats': [
            'evidence_sources',
            'corroboration_count',
            'corroboration_threshold_met',
            'analyst_override',
            'analyst_override_notes',
            'analyst_override_by_id',
            'analyst_override_at',
            'original_verdict'
        ],
        'scan_history': [
            'evidence_sources',
            'corroboration_count',
            'analyst_notes',
            'analyst_verified'
        ],
        'attack_events': [
            'evidence_sources',
            'corroboration_count',
            'analyst_verified',
            'analyst_notes'
        ]
    }
    
    all_good = True
    
    for table, columns in required_columns.items():
        print(f"Checking {table}...")
        cursor.execute(f"PRAGMA table_info({table})")
        existing_columns = {row[1] for row in cursor.fetchall()}
        
        for col in columns:
            if col in existing_columns:
                print(f"  ✓ {col}")
            else:
                print(f"  ✗ {col} MISSING")
                all_good = False
        print()
    
    conn.close()
    
    if all_good:
        print("=" * 70)
        print("✓ ALL FORENSIC COLUMNS VERIFIED")
        print("=" * 70)
    else:
        print("=" * 70)
        print("✗ SOME COLUMNS ARE MISSING")
        print("=" * 70)
    
    return all_good


if __name__ == "__main__":
    success = migrate_forensic_features()
    
    if success:
        print("Verifying migration...")
        print()
        verify_migration()
        sys.exit(0)
    else:
        sys.exit(1)
