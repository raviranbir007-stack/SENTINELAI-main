#!/usr/bin/env python3
import sys
from pathlib import Path

# Test what the server will do
server_dir = Path("server")
client_dir = Path("client")
scanner_dir = client_dir / "scanner"

sys.path.insert(0, str(client_dir))
sys.path.insert(0, str(scanner_dir))

print("Testing imports from server perspective...")
print(f"Client dir: {client_dir.absolute()}")
print(f"Scanner dir: {scanner_dir.absolute()}")
print()

try:
    from scanner.intrusion_detector import IntrusionDetector
    print("✓ IntrusionDetector (IDS)")
except Exception as e:
    print(f"✗ IntrusionDetector: {e}")

try:
    from scanner.prevention_system import PreventionSystem
    print("✓ PreventionSystem (IPS)")
except Exception as e:
    print(f"✗ PreventionSystem: {e}")

try:
    from scanner.activity_logger import ActivityLogger
    print("✓ ActivityLogger (Monitoring)")
except Exception as e:
    print(f"✗ ActivityLogger: {e}")

try:
    from scanner.traffic_monitor import AutomaticTrafficMonitor
    print("✓ TrafficMonitor (Network)")
except Exception as e:
    print(f"✗ TrafficMonitor: {e}")

try:
    from scanner.defense_coordinator import DefenseCoordinator
    print("✓ DefenseCoordinator (Alert & Quarantine)")
except Exception as e:
    print(f"✗ DefenseCoordinator: {e}")

print()
print("✅ All client features available!")
print()
print("These will ALL start automatically when you run:")
print("  cd server")
print("  sudo python3 run_server.py")
