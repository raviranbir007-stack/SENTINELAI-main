#!/bin/bash
# Quick validation test before starting the system

echo "🔍 Validating system before start..."
echo ""

cd /home/kali/Documents/SENTINELAI-main/server || exit 1

python3 << 'EOF'
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
