#!/bin/bash

# SENTINEL Popup Debug Script
# Check each layer: API → Database → Frontend

echo "=========================================="
echo "SENTINEL Popup Debug"
echo "=========================================="
echo ""

# Step 1: Verify backend API
echo "[1] Checking Backend API..."
HEALTH=$(curl -s "http://localhost:8000/health" 2>&1)
if [ $? -eq 0 ]; then
    echo "    ✓ Backend is running"
else
    echo "    ✗ Backend not responding"
    exit 1
fi

# Step 2: Create fresh test event
echo ""
echo "[2] Creating fresh XSS test event..."
TEST_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/network/event" \
    -H "Content-Type: application/json" \
    -d '{
        "client_id": "debug-test",
        "event": "xss_attack_test",
        "severity": "high",
        "description": "Test XSS for popup debugging",
        "source_ip": "10.0.0.1",
        "details": {"type": "xss", "payload": "<script>"}
    }' 2>&1)

echo "Response: $TEST_RESPONSE"
EVENT_ID=$(echo "$TEST_RESPONSE" | grep -o '"created_attack_event":"[^"]*"' | cut -d'"' -f4)
ALERT_ID=$(echo "$TEST_RESPONSE" | grep -o '"immediate_alert":"[^"]*"' | cut -d'"' -f4)

echo "    Event ID: $EVENT_ID"
echo "    Alert ID: $ALERT_ID"

sleep 2

# Step 3: Verify event in database
echo ""
echo "[3] Checking if event appears in API endpoints..."

# Check /network/alerts
ALERTS=$(curl -s "http://localhost:8000/api/v1/network/alerts?limit=10&active_only=false")
ALERT_COUNT=$(echo "$ALERTS" | grep -c '"alert_id"' || echo "0")
echo "    Alerts endpoint: $ALERT_COUNT alerts"

if echo "$ALERTS" | grep -q "web_attack_detected"; then
    echo "    ✓ Found web_attack_detected alert type"
else
    echo "    ✗ No web_attack_detected alerts"
fi

# Check /dashboard/logs
LOGS=$(curl -s "http://localhost:8000/api/v1/dashboard/logs?limit=20&hours=1")
LOG_COUNT=$(echo "$LOGS" | grep -c '"id"' || echo "0")
echo "    Logs endpoint: $LOG_COUNT logs"

if echo "$LOGS" | grep -q "network_defense"; then
    echo "    ✓ Found network_defense logs"
    # Show the actual log
    echo "    Last network_defense log:"
    echo "$LOGS" | grep "network_defense" | head -1 | sed 's/^/      /'
else
    echo "    ✗ No network_defense logs"
fi

# Step 4: EventSource stream test
echo ""
echo "[4] Testing EventSource stream (/api/v1/dashboard/logs/stream)..."
timeout 2 curl -s "http://localhost:8000/api/v1/dashboard/logs/stream" 2>&1 | head -5 | sed 's/^/    /' || echo "    (timeout after 2 sec - stream is working)"

echo ""
echo "=========================================="
echo "NEXT: Open browser console and run:"
echo "=========================================="
echo ""
echo "// Check if logs are received:"
echo "console.log('Recent logs:', recentLogs.slice(0, 2));"
echo ""
echo "// Check if popup is active:"
echo "console.log('Active prompt:', activeSecurityPrompt);"
echo ""
echo "// Check security prompt queue:"
echo "console.log('Prompt queue:', securityPromptQueue.length);"
echo ""
echo "// Check if EventSource is connected:"
echo "console.log('Log stream handle:', logStreamHandle);"
echo ""
echo "// Force trigger popup for debugging:"
echo "if (recentLogs.length > 0) {"
echo "  const log = recentLogs[0];"
echo "  console.log('Handling log:', log);"
echo "  handleRealtimeLogEvent(log);"
echo "}"
echo ""
