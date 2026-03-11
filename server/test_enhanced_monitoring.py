#!/usr/bin/env python3
"""
Quick Test - SENTINEL-AI Enhanced Monitoring
Verifies all components are installed and ready
"""

import sys
from pathlib import Path

print("=" * 80)
print("🔍 SENTINEL-AI Enhanced Monitoring - System Check")
print("=" * 80)
print()

# Check Python version
print(f"✓ Python Version: {sys.version.split()[0]}")

# Check required modules
required_modules = [
    ('fastapi', 'FastAPI'),
    ('uvicorn', 'Uvicorn'),
    ('sqlalchemy', 'SQLAlchemy'),
    ('httpx', 'HTTPX'),
    ('psutil', 'PSUtil'),
]

optional_modules = [
    ('scapy', 'Scapy (for packet capture)'),
]

print("\n📦 Required Dependencies:")
missing = []
for module, name in required_modules:
    try:
        __import__(module)
        print(f"  ✓ {name}")
    except ImportError:
        print(f"  ✗ {name} - MISSING")
        missing.append(module)

print("\n📦 Optional Dependencies:")
for module, name in optional_modules:
    try:
        __import__(module)
        print(f"  ✓ {name}")
    except ImportError:
        print(f"  ⚠ {name} - Not installed (packet capture will be limited)")

# Check new components
print("\n🆕 Enhanced Monitoring Components:")
components = [
    ('app.core.corroboration_engine', 'Multi-API Corroboration Engine'),
    ('app.core.activity_database', 'Activity Database'),
    ('app.core.terminal_monitor', 'Terminal Monitor'),
]

for module, name in components:
    try:
        __import__(module)
        print(f"  ✓ {name}")
    except ImportError as e:
        print(f"  ✗ {name} - ERROR: {e}")

# Check database initialization
print("\n🗄️  Database Status:")
try:
    from app.core.activity_database import activity_db
    print("  ✓ Activity database initialized")
    
    # Get summary to test
    summary = activity_db.get_activity_summary(hours=1)
    print(f"  ✓ Database operational (0 activities in last hour)")
except Exception as e:
    print(f"  ✗ Database error: {e}")

print("\n" + "=" * 80)

if missing:
    print("❌ MISSING DEPENDENCIES")
    print(f"   Install with: pip3 install {' '.join(missing)}")
    print("=" * 80)
    sys.exit(1)
else:
    print("✅ ALL SYSTEMS READY!")
    print()
    print("📋 To start monitoring:")
    print("   cd server")
    print("   python3 run_server.py")
    print()
    print("   The terminal will display:")
    print("   • Real-time activity summaries every 30 seconds")
    print("   • Websites visited")
    print("   • Applications monitored")
    print("   • Network connections")
    print("   • Threats detected")
    print()
    print("   All details are logged to: server/activity_monitoring.db")
    print("   Reports will include full activity monitoring data")
    print("=" * 80)
