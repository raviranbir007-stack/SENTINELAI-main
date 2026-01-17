#!/usr/bin/env python3
"""
Initialize database with forensic features
Creates a fresh database with all tables and forensic columns
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.database import Base, engine
from app.models import *


async def init_database():
    """Initialize database with all tables including forensic columns"""
    print("=" * 70)
    print("SENTINEL-AI DATABASE INITIALIZATION")
    print("=" * 70)
    print()
    
    try:
        print("Creating all database tables with forensic features...")
        print()
        
        # Create all tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
        
        print("✓ Database created successfully!")
        print()
        print("Tables created with forensic features:")
        print("  ✓ users")
        print("  ✓ threats (with forensic columns)")
        print("    - evidence_sources")
        print("    - corroboration_count")
        print("    - corroboration_threshold_met")
        print("    - analyst_override fields")
        print("  ✓ response_actions")
        print("  ✓ system_logs")
        print("  ✓ api_cache")
        print("  ✓ scan_history (with forensic columns)")
        print("    - evidence_sources")
        print("    - corroboration_count")
        print("    - analyst_notes")
        print("    - analyst_verified")
        print("  ✓ client_installations")
        print("  ✓ attack_events (with forensic columns)")
        print("    - evidence_sources")
        print("    - corroboration_count")
        print("    - analyst_verified")
        print("    - analyst_notes")
        print("  ✓ defense_actions")
        print("  ✓ network_alerts")
        print()
        print("=" * 70)
        print("✓ DATABASE INITIALIZATION COMPLETE")
        print("=" * 70)
        print()
        print("Forensic reliability features are now active!")
        print()
        
        return True
        
    except Exception as e:
        print("=" * 70)
        print("✗ DATABASE INITIALIZATION FAILED")
        print("=" * 70)
        print(f"Error: {e}")
        print()
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(init_database())
    sys.exit(0 if success else 1)
