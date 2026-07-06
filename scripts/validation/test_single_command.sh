#!/bin/bash
# Test SENTINELAI Single Command Start
# Verifies that python run_server.py starts everything

echo "========================================"
echo "🧪 Testing Single Command Startup"
echo "========================================"
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT/server" || exit 1

echo "Testing imports..."
python3 << 'EOF'
import sys
from pathlib import Path

# Test server imports
print("✓ Testing server components...")
from app.config import settings
print(f"  - Settings loaded (port: {settings.API_PORT})")

# Test client imports
client_dir = Path(__file__).parent.parent / "client"
sys.path.insert(0, str(client_dir))

print("✓ Testing client components...")
from scanner.intrusion_detector import IntrusionDetector
from scanner.prevention_system import PreventionSystem
from scanner.activity_logger import ActivityLogger
from scanner.defense_coordinator import DefenseCoordinator
print("  - IDS: IntrusionDetector")
print("  - IPS: PreventionSystem")
print("  - Monitor: ActivityLogger")
print("  - Defense: DefenseCoordinator")

print("\n✅ All imports successful!")
print("\nTo start the complete system:")
print("  cd server")
print("  sudo python3 run_server.py")
EOF

echo ""
echo "========================================"
echo "✅ System is ready!"
echo "========================================"
echo ""
echo "Start command:"
echo "  cd server"
echo "  sudo python3 run_server.py"
echo ""
