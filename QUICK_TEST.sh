#!/bin/bash
# Quick System Test Script

echo "🛡️  SENTINELAI - QUICK SYSTEM TEST"
echo "=================================="
echo ""

echo "1️⃣  Verifying System Components..."
python3 COMPLETE_SYSTEM_VERIFICATION.py 2>&1 | grep -A 5 "VERIFICATION SUMMARY"

echo ""
echo "2️⃣  Testing Server Imports..."
cd server
python3 -c "
from app.api.v1.api import api_router
from app.api.v1.endpoints import ai_threat_prediction, advanced_reports
from app.gemini_integration import get_gemini_client
from app.services import virus_total, abuseipdb, shodan, urlscan, hybrid_analysis
print('✅ All server imports successful!')
"

echo ""
echo "3️⃣  Testing Client Imports..."
cd ../client
python3 -c "
import sentinel_realtime_protection as rt
print('✅ Real-time protection client imported')
print(f'   - ThreatWarningSystem: {hasattr(rt, \"ThreatWarningSystem\")}')
print(f'   - RealTimeDefenseSystem: {hasattr(rt, \"RealTimeDefenseSystem\")}')
"

cd ..
echo ""
echo "4️⃣  Listing Key Files..."
echo "📄 Documentation:"
ls -lh *.md | awk '{print "   " $9 " (" $5 ")"}'
echo ""
echo "📄 Scripts:"
ls -lh *.py *.sh 2>/dev/null | awk '{print "   " $9 " (" $5 ")"}'

echo ""
echo "✅ SYSTEM TEST COMPLETE"
echo ""
echo "🚀 Ready to start:"
echo "   Server: cd server && python3 run_server.py"
echo "   Client: cd client && python3 sentinel_realtime_protection.py"
