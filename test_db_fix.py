#!/usr/bin/env python3
"""
Test script to verify the activity database is properly initialized
"""

import os
import sqlite3
import sys
from pathlib import Path

# Test client database
def _check_client_db() -> bool:
    print("=" * 60)
    print("Testing CLIENT Database (activity_logs.db)")
    print("=" * 60)
    
    db_path = Path("activity_logs.db")
    
    # Clean up if exists
    if db_path.exists():
        db_path.unlink()
        print(f"✓ Removed existing {db_path}")
    
    # Initialize database using the ActivityLogger
    sys.path.insert(0, str(Path(__file__).parent))
    from client.scanner.activity_logger import ActivityLogger
    
    logger = ActivityLogger(db_path=str(db_path))
    print(f"✓ ActivityLogger initialized")
    
    # Verify tables exist
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    
    required_tables = ['websites', 'applications', 'network_connections', 'blocked_activities', 'file_events', 'os_logs']
    
    print(f"\nTables found: {tables}")
    print(f"Required tables: {required_tables}")
    
    missing = set(required_tables) - set(tables)
    if missing:
        print(f"❌ Missing tables: {missing}")
        conn.close()
        return False
    
    print(f"✓ All required tables exist")
    
    # Test applications table
    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='applications'")
    schema = cursor.fetchone()
    if schema:
        print(f"\nApplications table schema:")
        print(schema[0])
    
    conn.close()
    return True

# Test server database
def _check_server_db() -> bool:
    print("\n" + "=" * 60)
    print("Testing SERVER Database (activity_monitoring.db)")
    print("=" * 60)
    
    db_path = (Path(__file__).parent / "server" / "activity_monitoring.db").resolve()
    
    # Clean up if exists
    if db_path.exists():
        db_path.unlink()
        print(f"✓ Removed existing {db_path}")
    
    # Initialize database using ActivityDatabase
    sys.path.insert(0, str(Path(__file__).parent))
    from server.app.core.activity_database import ActivityDatabase
    
    activity_db = ActivityDatabase(db_path=str(db_path))
    print(f"✓ ActivityDatabase initialized")
    
    # Verify tables exist
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    
    required_tables = ['websites', 'applications', 'network_connections', 'file_operations', 'dns_queries', 'threat_scans', 'activity_summary']
    
    print(f"\nTables found: {tables}")
    print(f"Required tables: {required_tables}")
    
    missing = set(required_tables) - set(tables)
    if missing:
        print(f"❌ Missing tables: {missing}")
        conn.close()
        return False
    
    print(f"✓ All required tables exist")
    
    # Test applications table
    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='applications'")
    schema = cursor.fetchone()
    if schema:
        print(f"\nApplications table schema:")
        print(schema[0])
    
    conn.close()
    return True


def test_client_db():
    assert _check_client_db() is True


def test_server_db():
    assert _check_server_db() is True

if __name__ == "__main__":
    try:
        client_ok = _check_client_db()
    except Exception as e:
        print(f"❌ Client DB test failed: {e}")
        import traceback
        traceback.print_exc()
        client_ok = False
    
    try:
        server_ok = _check_server_db()
    except Exception as e:
        print(f"❌ Server DB test failed: {e}")
        import traceback
        traceback.print_exc()
        server_ok = False
    
    print("\n" + "=" * 60)
    if client_ok and server_ok:
        print("✓ ALL TESTS PASSED - Databases initialized correctly!")
        print("=" * 60)
        sys.exit(0)
    else:
        print("❌ SOME TESTS FAILED")
        print("=" * 60)
        sys.exit(1)
