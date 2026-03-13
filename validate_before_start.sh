#!/bin/bash
# Quick validation test before starting the system

set -u

echo "🔍 Validating system before start..."
echo ""

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
if [ ! -x "$PYTHON_BIN" ]; then
    PYTHON_BIN="$(command -v python3)"
fi

cd "$ROOT_DIR/server" || exit 1

"$PYTHON_BIN" << 'EOF'
import sys
from pathlib import Path

print("Testing all components can initialize...")
print()

# Setup paths
client_dir = Path('..') / 'client'
sys.path.insert(0, str(client_dir))
sys.path.insert(0, str(client_dir / 'scanner'))

try:
    # Test 1: IDS
    from scanner.intrusion_detector import IntrusionDetector
    ids = IntrusionDetector(callback=None)
    print("✓ IDS (Intrusion Detection System)")
    
    # Test 2: IPS
    from scanner.prevention_system import PreventionSystem
    ips = PreventionSystem(callback=None)
    print("✓ IPS (Intrusion Prevention System)")
    
    # Test 3: Activity Logger
    from scanner.activity_logger import ActivityLogger
    al = ActivityLogger(db_path="/tmp/test.db", callback=None)
    print("✓ Activity Logger (Monitoring)")
    
    # Test 4: Traffic Monitor (with proper config)
    from scanner.traffic_monitor import AutomaticTrafficMonitor
    config = {'scan_interval': 60, 'batch_size': 10}
    tm = AutomaticTrafficMonitor(scan_callback=None, config=config)
    print("✓ Traffic Monitor (Network Analysis)")
    
    # Test 5: Defense Coordinator
    from scanner.defense_coordinator import DefenseCoordinator
    dc = DefenseCoordinator(server_url="http://localhost:8000", callback=None)
    print("✓ Defense Coordinator (Alert & Quarantine)")

    # Test 6-10: Extended endpoint monitors
    from scanner.usb_monitor import USBMonitor
    from scanner.email_monitor import EmailMonitor
    from scanner.vulnerability_scanner import VulnerabilityScanner
    from scanner.behavioral_monitor import BehavioralMonitor
    from scanner.dns_monitor import DNSMonitor
    from scanner.network_scanner import NetworkScanner
    from scanner.process_scanner import ProcessScanner
    from scanner.file_scanner import FileScanner

    USBMonitor(callback=None)
    EmailMonitor(callback=None)
    VulnerabilityScanner(callback=None)
    BehavioralMonitor(callback=None)
    DNSMonitor(callback=None)
    NetworkScanner(callback=None)
    ProcessScanner(callback=None)
    FileScanner(threat_analyzer=None)
    print("✓ Extended monitors (USB/Email/Vuln/Behavior/DNS/Network/Process/File)")

    # Test 11: API route registration for defense event pipeline
    from app.main import app
    route_paths = {r.path for r in app.routes}
    required = {
        "/api/v1/network/event",
        "/api/v1/network/events",
        "/api/v1/network/ingest/nids",
    }
    missing = sorted(required - route_paths)
    if missing:
        raise RuntimeError(f"Missing required API routes: {missing}")
    print("✓ Server API routes (defense event + NIDS ingest)")
    
    print()
    print("="*60)
    print("✅ All components validated successfully!")
    print("="*60)
    print()
    print("System is ready to start:")
    print("  sudo python3 run_server.py")
    print()
    
except Exception as e:
    print(f"\n❌ Validation failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

EOF
