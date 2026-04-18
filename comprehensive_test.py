#!/usr/bin/env python3
import asyncio
import json
import sys
from pathlib import Path

# Test imports
try:
    from server.app.api.v1.endpoints import scan as scan_ep
    from server.app.api.v1.endpoints import dashboard as dash_ep
    from server.app.api.v1.endpoints import reports as reports_ep
    from server.app.api.v1.endpoints import network_defense as net_ep
    from server.app.api.compat import generic_scan, list_scans, get_dashboard_stats, get_threats
    from server.app.database import AsyncSessionLocal
    from server.app.models import ScanHistory, SystemLog, AttackEvent
    print("✅ All imports successful")
except ImportError as e:
    print(f"❌ Import failed: {e}")
    sys.exit(1)

async def run_tests():
    """Run comprehensive endpoint tests"""
    try:
        async with AsyncSessionLocal() as db:
            # Test 1: Check scan history endpoint
            print("\n📊 Test 1: Scan History Endpoint")
            history = await scan_ep.get_scan_history(source='all', limit=20, db=db)
            count = len(history.get('scans', []))
            print(f"  ✅ Scan history returned {count} records")
            
            # Test 2: Check dashboard logs
            print("\n📋 Test 2: Dashboard Logs Endpoint")
            logs = await dash_ep.get_dashboard_logs(limit=20, level=None, component=None, db=db)
            log_count = len(logs)
            print(f"  ✅ Dashboard logs returned {log_count} records")
            
            # Test 3: Check incidents/threats
            print("\n🚨 Test 3: Network Incidents Endpoint")
            incidents = await net_ep.list_incidents(hours=72, limit=50, db=db)
            incidents_count = len(incidents.get('items', []))
            print(f"  ✅ Incidents returned {incidents_count} records")
            
            # Test 4: Check reports
            print("\n📄 Test 4: Reports List Endpoint")
            reports = await reports_ep.list_reports()
            reports_count = len(reports) if isinstance(reports, list) else 0
            print(f"  ✅ Reports list returned {reports_count} records")
            
            # Test 5: Check compatibility endpoints
            print("\n🔄 Test 5: Compatibility Endpoints")
            compat_stats = await get_dashboard_stats(db=db)
            print(f"  ✅ Dashboard stats: {compat_stats['total_scans']} scans, {compat_stats['attack_events']} attacks")
            
            threats = await get_threats(db=db)
            print(f"  ✅ Threats endpoint returned {len(threats)} threats")
            
            # Test 6: Database connectivity
            print("\n💾 Test 6: Database Connectivity")
            from sqlalchemy import text
            result = await db.execute(text("SELECT COUNT(*) FROM scan_history"))
            count = result.scalar()
            print(f"  ✅ Database connected, scan_history has {count} rows")
            
            # Test 7: Check file paths
            print("\n📁 Test 7: File Paths Verification")
            generated_dir = Path(__file__).resolve().parents[0] / "generated_reports"
            protection_log = Path(__file__).resolve().parents[0] / "logs" / "protection.log"
            activity_db = Path(__file__).resolve().parents[0] / "server" / "activity_monitoring.db"
            
            print(f"  📂 Generated reports dir: {generated_dir.exists() and '✅' or '⚠️'}")
            print(f"  📂 Protection log: {protection_log.exists() and '✅' or '⚠️'}")
            print(f"  📂 Activity DB: {activity_db.exists() and '✅' or '⚠️'}")
            
            print("\n✅ All endpoint tests passed!")
            return True
            
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

# Run tests
success = asyncio.run(run_tests())
sys.exit(0 if success else 1)
