#!/bin/bash

# SENTINEL XSS/SQL Popup Testing Script
# This script sends guaranteed XSS/SQL events to the backend and verifies the full flow

set -e

# Configuration
SERVER_URL="http://localhost:8000"
API_ENDPOINT="/api/v1/network/event"
CLIENT_ID="test-client-lab-$(date +%s)"

echo "=========================================="
echo "SENTINEL XSS/SQL Popup Testing"
echo "=========================================="
echo "Server: $SERVER_URL"
echo "Client ID: $CLIENT_ID"
echo ""

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored status
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Step 1: Test server connectivity
print_status "Step 1: Testing server connectivity..."
if curl -s "$SERVER_URL/health" > /dev/null 2>&1 || curl -s "$SERVER_URL/" > /dev/null 2>&1; then
    print_success "Server is reachable at $SERVER_URL"
else
    print_error "Cannot reach server at $SERVER_URL"
    print_status "Make sure the backend server is running: cd server && python run_app.py"
    exit 1
fi

# Step 2: Send XSS event (REFLECTED)
print_status "Step 2: Sending XSS event (reflected XSS attack)..."
XSS_RESPONSE=$(curl -s -X POST "$SERVER_URL$API_ENDPOINT" \
    -H "Content-Type: application/json" \
    -d '{
        "client_id": "'$CLIENT_ID'",
        "event": "xss_attack",
        "attack": {
            "type": "reflected_xss",
            "payload": "<script>alert(\"XSS\")</script>",
            "parameter": "search",
            "url": "http://localhost/dvwa/search?q=<script>alert(\"XSS\")</script>"
        },
        "severity": "high",
        "source_ip": "192.168.1.50",
        "description": "Potential reflected XSS attack via search parameter",
        "details": {
            "threat_vector": "web_form",
            "detected_by": "lab_test"
        }
    }')

print_status "XSS Response: $XSS_RESPONSE"
XSS_EVENT_ID=$(echo "$XSS_RESPONSE" | grep -o '"created_attack_event":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
XSS_ALERT_ID=$(echo "$XSS_RESPONSE" | grep -o '"immediate_alert":"[^"]*"' | cut -d'"' -f4 || echo "unknown")

if [ "$XSS_EVENT_ID" != "" ] && [ "$XSS_EVENT_ID" != "unknown" ]; then
    print_success "XSS event created: $XSS_EVENT_ID"
else
    print_warning "XSS event ID not found in response"
fi

if [ "$XSS_ALERT_ID" != "" ] && [ "$XSS_ALERT_ID" != "unknown" ]; then
    print_success "XSS immediate alert created: $XSS_ALERT_ID"
else
    print_warning "XSS alert not created (may be filtered by severity)"
fi

sleep 1

# Step 3: Send SQL Injection event (UNION SELECT)
print_status "Step 3: Sending SQL injection event (UNION SELECT attack)..."
SQL_RESPONSE=$(curl -s -X POST "$SERVER_URL$API_ENDPOINT" \
    -H "Content-Type: application/json" \
    -d '{
        "client_id": "'$CLIENT_ID'",
        "event": "sql_injection",
        "attack": {
            "type": "sql_injection",
            "payload": "1 UNION SELECT user, password FROM admin_users--",
            "parameter": "id",
            "url": "http://localhost/dvwa/login?id=1 UNION SELECT user, password FROM admin_users--"
        },
        "severity": "high",
        "source_ip": "192.168.1.50",
        "description": "SQL injection attempt via UNION SELECT",
        "details": {
            "attack_vector": "union_select",
            "threat_level": "critical_web_attack"
        }
    }')

print_status "SQL Response: $SQL_RESPONSE"
SQL_EVENT_ID=$(echo "$SQL_RESPONSE" | grep -o '"created_attack_event":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
SQL_ALERT_ID=$(echo "$SQL_RESPONSE" | grep -o '"immediate_alert":"[^"]*"' | cut -d'"' -f4 || echo "unknown")

if [ "$SQL_EVENT_ID" != "" ] && [ "$SQL_EVENT_ID" != "unknown" ]; then
    print_success "SQL event created: $SQL_EVENT_ID"
else
    print_warning "SQL event ID not found in response"
fi

if [ "$SQL_ALERT_ID" != "" ] && [ "$SQL_ALERT_ID" != "unknown" ]; then
    print_success "SQL immediate alert created: $SQL_ALERT_ID"
else
    print_warning "SQL alert not created (may be filtered by severity)"
fi

sleep 1

# Step 4: Query alerts endpoint
print_status "Step 4: Checking /api/v1/network/alerts endpoint..."
ALERTS=$(curl -s "$SERVER_URL/api/v1/network/alerts?active_only=false&limit=20")
ALERT_COUNT=$(echo "$ALERTS" | grep -o '"alert_id"' | wc -l)

print_success "Found $ALERT_COUNT total alerts"
if echo "$ALERTS" | grep -q "web_attack_detected"; then
    print_success "✓ Found 'web_attack_detected' alert type"
else
    print_warning "✗ No 'web_attack_detected' alerts found"
fi

# Step 5: Query logs endpoint
print_status "Step 5: Checking /api/v1/dashboard/logs endpoint..."
LOGS=$(curl -s "$SERVER_URL/api/v1/dashboard/logs?limit=50&hours=1")
LOG_COUNT=$(echo "$LOGS" | grep -o '"log_id"' | wc -l)

print_success "Found $LOG_COUNT recent logs"
if echo "$LOGS" | grep -q "network_defense"; then
    print_success "✓ Found 'network_defense' component logs"
else
    print_warning "✗ No 'network_defense' component logs found"
fi

if echo "$LOGS" | grep -q "web_attack"; then
    print_success "✓ Found 'web_attack' references in logs"
else
    print_warning "✗ No web attack references in logs"
fi

# Step 6: Check threats endpoint
print_status "Step 6: Checking /api/v1/dashboard/threats endpoint..."
THREATS=$(curl -s "$SERVER_URL/api/v1/dashboard/threats?hours=1")
THREAT_COUNT=$(echo "$THREATS" | grep -o '"id"' | wc -l)

print_success "Found $THREAT_COUNT threats"
if echo "$THREATS" | grep -qi "xss\|sql"; then
    print_success "✓ Found XSS/SQL threats in threat feed"
else
    print_warning "✗ No XSS/SQL threats in threat feed"
fi

# Step 7: List all incidents
print_status "Step 7: Checking /api/v1/network/incidents endpoint..."
INCIDENTS=$(curl -s "$SERVER_URL/api/v1/network/incidents?hours=1&limit=50")
INCIDENT_COUNT=$(echo "$INCIDENTS" | grep -o '"incident_id"' | wc -l)

print_success "Found $INCIDENT_COUNT incidents"
if echo "$INCIDENTS" | grep -q "web_attack"; then
    print_success "✓ Found web attack incidents"
else
    print_warning "✗ No web attack incidents found yet"
fi

# Summary
echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "XSS Event ID:           $XSS_EVENT_ID"
echo "XSS Alert ID:           $XSS_ALERT_ID"
echo "SQL Event ID:           $SQL_EVENT_ID"
echo "SQL Alert ID:           $SQL_ALERT_ID"
echo "Total Alerts:           $ALERT_COUNT"
echo "Total Logs:             $LOG_COUNT"
echo "Total Threats:          $THREAT_COUNT"
echo "Total Incidents:        $INCIDENT_COUNT"
echo ""

# Step 8: Dashboard check instructions
print_status "Step 8: Dashboard verification"
echo ""
echo "Open the dashboard in your browser and:"
echo "  1. Go to: $SERVER_URL"
echo "  2. Hard refresh the page (Ctrl+Shift+R on Linux/Windows, Cmd+Shift+R on Mac)"
echo "  3. Look for TOAST notifications at the top-right corner (should appear in 3-5 sec)"
echo "  4. Check the 'Threats' section for XSS/SQL entries"
echo "  5. Check the 'Recent System Logs' for network_defense entries"
echo "  6. Look for popup/modal dialog with security prompt"
echo ""

echo -e "${GREEN}========== Testing Complete ==========${NC}"

