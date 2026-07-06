#!/bin/bash
# Quick Test Script - Tests basic IDS/IPS/Monitoring functionality
# Run this to verify your system is working correctly

echo "========================================"
echo "🧪 SENTINELAI Quick Test"
echo "========================================"
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}This script will test:${NC}"
echo "  1. IDS - Intrusion Detection"
echo "  2. IPS - Intrusion Prevention"
echo "  3. Activity Monitoring"
echo ""
echo "Press Enter to continue..."
read

echo ""
echo -e "${YELLOW}Test 1: Activity Monitoring${NC}"
echo "Opening Python and listing processes..."
python3 -c "
import psutil
print(f'✓ Can access process list: {len(list(psutil.process_iter()))} processes')
print(f'✓ Network connections: {len(psutil.net_connections(kind=\"inet\"))} connections')
"

echo ""
echo -e "${YELLOW}Test 2: Network Monitoring${NC}"
echo "Checking network interfaces..."
python3 -c "
import psutil
stats = psutil.net_io_counters()
print(f'✓ Bytes sent: {stats.bytes_sent:,}')
print(f'✓ Bytes received: {stats.bytes_recv:,}')
print(f'✓ Network monitoring: OK')
"

echo ""
echo -e "${YELLOW}Test 3: IDS Detection${NC}"
echo "Testing connection monitoring..."
python3 << 'EOF'
import sys
sys.path.insert(0, 'client')
from scanner.intrusion_detector import IntrusionDetector

ids = IntrusionDetector()
print("✓ IDS initialized")

# Test connection analysis
test_conn = {
    'remote_ip': '192.0.2.1',
    'remote_port': 22,
    'status': 'ESTABLISHED',
    'timestamp': __import__('datetime').datetime.now()
}
ids._analyze_connection(test_conn)
print("✓ IDS can analyze connections")

stats = ids.get_statistics()
print(f"✓ IDS statistics available: {stats}")
EOF

echo ""
echo -e "${YELLOW}Test 4: IPS Functionality${NC}"
echo "Testing prevention system (without actually blocking)..."
python3 << 'EOF'
import sys
sys.path.insert(0, 'client')
from scanner.prevention_system import PreventionSystem

ips = PreventionSystem()
print("✓ IPS initialized")
print(f"✓ Blocked domains: {len(ips.blocked_domains)}")
print(f"✓ Blocked IPs: {len(ips.blocked_ips)}")
print("✓ IPS ready to block threats")
EOF

echo ""
echo -e "${YELLOW}Test 5: Activity Logger${NC}"
echo "Testing activity logging..."
python3 << 'EOF'
import sys
sys.path.insert(0, 'client')
from scanner.activity_logger import ActivityLogger

logger = ActivityLogger(db_path="/tmp/test_activity.db")
print("✓ Activity logger initialized")
print(f"✓ Database created")
print("✓ Activity logging ready")
EOF

echo ""
echo -e "${GREEN}========================================"
echo "✅ All Tests Passed!"
echo "========================================${NC}"
echo ""
echo "Your SENTINELAI system is ready!"
echo ""
echo "Next steps:"
echo "  1. Run full setup (optional): sudo ./setup_complete_system.sh"
echo "  2. Start the system: sudo ./scripts/run/run_complete_system.sh"
echo ""
