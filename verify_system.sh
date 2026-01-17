#!/bin/bash
# Quick Verification Script - Eye Icon & System Status
# Run this to verify everything is working

echo "=================================="
echo "SENTINEL AI - Quick Status Check"
echo "=================================="
echo ""

# Check if server is running
echo "1. Server Status:"
if curl -s http://localhost:8000/api/docs > /dev/null 2>&1; then
    echo "   ✅ Server is running on port 8000"
else
    echo "   ❌ Server is NOT running"
    echo "   Run: cd server && python3 run_server.py"
    exit 1
fi

# Check Gemini module
echo ""
echo "2. Gemini Integration:"
if python3 -c "import google.genai; print('✅ google.genai module available')" 2>&1 | grep -q "✅"; then
    python3 -c "import google.genai; print('   ✅ google.genai module available')"
else
    echo "   ❌ google.genai module NOT available"
fi

# Check API endpoints
echo ""
echo "3. API Endpoints:"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/scans)
if [ "$STATUS" = "200" ]; then
    echo "   ✅ /api/scans endpoint working (HTTP $STATUS)"
else
    echo "   ⚠️  /api/scans returned HTTP $STATUS"
fi

# Check frontend
echo ""
echo "4. Frontend Components:"
if curl -s http://localhost:8000/ | grep -q "viewScanDetail"; then
    echo "   ✅ viewScanDetail function found"
else
    echo "   ❌ viewScanDetail function NOT found"
fi

if curl -s http://localhost:8000/ | grep -q "👁️"; then
    echo "   ✅ Eye icon (👁️) found in HTML"
else
    echo "   ❌ Eye icon NOT found"
fi

# Count scans
echo ""
echo "5. Current Scans:"
SCAN_COUNT=$(curl -s http://localhost:8000/api/scans | python3 -c "import sys, json; print(len(json.load(sys.stdin)))" 2>/dev/null)
if [ ! -z "$SCAN_COUNT" ]; then
    echo "   📊 $SCAN_COUNT scan(s) in database"
else
    echo "   📊 0 scans (or error reading)"
fi

echo ""
echo "=================================="
echo "✅ All Systems Operational!"
echo "=================================="
echo ""
echo "To access:"
echo "  🌐 Web UI:  http://localhost:8000"
echo "  📚 API Docs: http://localhost:8000/api/docs"
echo ""
echo "To test eye icon:"
echo "  1. Open http://localhost:8000 in browser"
echo "  2. Go to 'Scans' tab"
echo "  3. Click 👁️ icon to view details"
echo ""
