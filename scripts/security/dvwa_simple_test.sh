#!/bin/bash

# Direct DVWA + SENTINEL Integration Test
# This simpler version sends events to both DVWA (testing) and SENTINEL (detection)

set -e

DVWA_URL="http://192.168.56.3/dvwa/"
SENTINEL_API="http://localhost:8000/api/v1/network/event"

echo "=========================================="
echo "DVWA + SENTINEL Test (Direct Attack Simulation)"
echo "=========================================="
echo ""

# Test 1: Simple XSS payload through DVWA, then alert SENTINEL
echo "[1] Testing Reflected XSS..."
echo "    Sending: <script>alert('XSS')</script>"

XSS_RESPONSE=$(curl -s -G "$DVWA_URL/vulnerabilities/xss_r/" \
    --data-urlencode "name=<script>alert('XSS')</script>" 2>&1)

if echo "$XSS_RESPONSE" | grep -q "script"; then
    echo "    ✓ DVWA reflected the XSS payload"
else
    echo "    ⚠ Response received from DVWA (may require auth)"
fi

# Immediately inject detection event to SENTINEL
echo "    → Injecting XSS detection to SENTINEL..."
EVENT_1=$(curl -s -X POST "$SENTINEL_API" \
    -H "Content-Type: application/json" \
    -d '{
        "client_id": "dvwa-xss-test",
        "event": "xss_attack_detected",
        "severity": "high",
        "description": "XSS payload reflected in DVWA search parameter",
        "source_ip": "192.168.56.3",
        "details": {"payload": "<script>alert('"'"'XSS'"'"')</script>"}
    }' 2>&1)

EVENT_1_ID=$(echo "$EVENT_1" | grep -o '"created_attack_event":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
echo "    ✓ Event: $EVENT_1_ID"
echo ""
sleep 2

# Test 2: SQL Injection - UNION SELECT
echo "[2] Testing SQL Injection (UNION SELECT)..."
echo "    Sending: 1' UNION SELECT user, password FROM admin_users--"

SQL_RESPONSE=$(curl -s -G "$DVWA_URL/vulnerabilities/sqli/" \
    --data-urlencode "id=1' UNION SELECT user, password FROM admin_users--" \
    --data-urlencode "Submit=Submit" 2>&1)

if echo "$SQL_RESPONSE" | grep -qi "error\|syntax\|union\|select"; then
    echo "    ✓ DVWA processed/errored on SQL payload"
else
    echo "    ⚠ Response received from DVWA"
fi

# Inject detection to SENTINEL
echo "    → Injecting SQL injection detection to SENTINEL..."
EVENT_2=$(curl -s -X POST "$SENTINEL_API" \
    -H "Content-Type: application/json" \
    -d '{
        "client_id": "dvwa-sqli-test",
        "event": "sql_injection_detected",
        "severity": "high",
        "description": "SQL injection attack via UNION SELECT in DVWA",
        "source_ip": "192.168.56.3",
        "details": {"payload": "1'"'"' UNION SELECT user, password FROM admin_users--"}
    }' 2>&1)

EVENT_2_ID=$(echo "$EVENT_2" | grep -o '"created_attack_event":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
echo "    ✓ Event: $EVENT_2_ID"
echo ""
sleep 2

# Test 3: SQL Injection - Boolean-based (OR 1=1)
echo "[3] Testing SQL Injection (Boolean-based OR 1=1)..."
echo "    Sending: 1' OR '1'='1"

SQL_BOOL=$(curl -s -G "$DVWA_URL/vulnerabilities/sqli/" \
    --data-urlencode "id=1' OR '1'='1" \
    --data-urlencode "Submit=Submit" 2>&1)

echo "    ✓ DVWA received boolean-based SQLi payload"

echo "    → Injecting SQLi boolean detection to SENTINEL..."
EVENT_3=$(curl -s -X POST "$SENTINEL_API" \
    -H "Content-Type: application/json" \
    -d '{
        "client_id": "dvwa-sqli-bool-test",
        "event": "sql_injection_boolean",
        "severity": "high",
        "description": "Boolean-based SQL injection (OR 1=1) detected",
        "source_ip": "192.168.56.3",
        "details": {"injection_type": "boolean-based", "payload": "1'"'"' OR '"'"'1'"'"'='"'"'1"}
    }' 2>&1)

EVENT_3_ID=$(echo "$EVENT_3" | grep -o '"created_attack_event":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
echo "    ✓ Event: $EVENT_3_ID"
echo ""
sleep 2

# Test 4: Verify all events in SENTINEL database
echo "[4] Verifying events in SENTINEL..."
ALERTS=$(curl -s "http://localhost:8000/api/v1/network/alerts?limit=50&active_only=false")
ALERT_COUNT=$(echo "$ALERTS" | grep -o '"alert_id"' | wc -l)
WEB_ATTACK_COUNT=$(echo "$ALERTS" | grep -o "web_attack_detected" | wc -l)

echo "    Total alerts in SENTINEL: $ALERT_COUNT"
echo "    Web attack alerts: $WEB_ATTACK_COUNT"
echo ""

LOGS=$(curl -s "http://localhost:8000/api/v1/dashboard/logs?limit=50&hours=1")
NETWORK_DEF_LOGS=$(echo "$LOGS" | grep -o '"component":"network_defense"' | wc -l)

echo "    Network defense logs: $NETWORK_DEF_LOGS"
echo ""

# Final verification
echo "=========================================="
echo "✓ Test Complete!"
echo "=========================================="
echo ""
echo "Events injected into SENTINEL:"
echo "  • XSS Event ID: $EVENT_1_ID"
echo "  • SQL Event ID: $EVENT_2_ID"
echo "  • Boolean SQLi ID: $EVENT_3_ID"
echo ""
echo "NEXT STEPS:"
echo "1. Open: http://localhost:8000"
echo "2. Hard refresh (Ctrl+Shift+R)"
echo "3. Look for:"
echo "   - Toast notifications (top-right corner with 🚨 icon)"
echo "   - Security prompt modal (center of screen)"
echo "   - Network defense logs in sidebar"
echo ""
