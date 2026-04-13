#!/bin/bash

# DVWA Testing with SENTINEL Event Injection
# This script tests DVWA payloads and automatically injects corresponding
# events into SENTINEL so you can see popups and alerts on the dashboard

set -e

# Configuration
DVWA_URL="http://192.168.56.3/dvwa/"
SENTINEL_URL="http://localhost:8000"
DVWA_USER="admin"
DVWA_PASS="password"

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_step() {
    echo -e "${YELLOW}[STEP]${NC} $1"
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

extract_json_value() {
    local json_payload=$1
    local key_path=$2
    python3 - "$json_payload" "$key_path" <<'PY'
import json
import sys

payload = sys.argv[1]
path = sys.argv[2].split('.') if sys.argv[2] else []

try:
    data = json.loads(payload)
    for key in path:
        if isinstance(data, dict):
            data = data.get(key)
        else:
            data = None
            break
    if data is None:
        print("")
    else:
        print(data)
except Exception:
    print("")
PY
}

fetch_json() {
    local url=$1
    curl -fsSL "$url"
}

# Check if DVWA is reachable
check_dvwa() {
    print_step "Checking DVWA accessibility..."
    if curl -fsSL "$DVWA_URL" > /dev/null; then
        print_success "DVWA is reachable at $DVWA_URL"
    else
        print_error "Cannot reach DVWA at $DVWA_URL"
        print_step "Make sure Metasploitable is running and DVWA is accessible"
        exit 1
    fi
}

# Get PHPSESSID for DVWA login
get_dvwa_session() {
    print_step "Getting DVWA session cookie..."
    LOGIN_PAGE=$(curl -fsSL -c /tmp/dvwa_cookies.txt "$DVWA_URL/login.php")
    USER_TOKEN=$(echo "$LOGIN_PAGE" | grep -o 'name="user_token" value="[^"]*"' | sed 's/.*value="//; s/"$//' | head -1)

    if [ -n "$USER_TOKEN" ]; then
        curl -fsSL -b /tmp/dvwa_cookies.txt -c /tmp/dvwa_cookies.txt \
            -d "username=$DVWA_USER&password=$DVWA_PASS&user_token=$USER_TOKEN&Login=Login" \
            "$DVWA_URL/login.php" > /dev/null || true
    fi

    if curl -fsSL -b /tmp/dvwa_cookies.txt "$DVWA_URL/index.php" | grep -qi "logout\|welcome"; then
        print_success "DVWA login verified"
    else
        print_warning "DVWA session cookie stored, but login verification could not be confirmed"
    fi
}

# Inject event into SENTINEL
inject_sentinel_event() {
    local attack_type=$1
    local payload=$2
    local description=$3
    
    print_step "Injecting $attack_type detection event into SENTINEL..."

    JSON_BODY=$(python3 - "$attack_type" "$payload" "$description" <<'PY'
import json
import sys

attack_type, payload, description = sys.argv[1:4]
print(json.dumps({
    "client_id": "dvwa-test-lab",
    "event": attack_type,
    "attack": {
        "type": attack_type,
        "payload": payload,
        "source": "dvwa_test",
    },
    "severity": "high",
    "source_ip": "192.168.1.50",
    "description": description,
    "details": {
        "origin": "dvwa_manual_test",
        "vector": "web_form",
    },
}))
PY
)

    RESPONSE=$(curl -s -X POST "$SENTINEL_URL/api/v1/network/event" \
        -H "Content-Type: application/json" \
        --data-binary "$JSON_BODY")
    
    EVENT_ID=$(extract_json_value "$RESPONSE" "created_attack_event")
    ALERT_ID=$(extract_json_value "$RESPONSE" "immediate_alert")
    
    if [ -n "$EVENT_ID" ] && [ "$EVENT_ID" != "unknown" ]; then
        print_success "Event created: $EVENT_ID (Alert: $ALERT_ID)"
    else
        print_error "Failed to create event"
        echo "$RESPONSE"
    fi
}

# Test 1: Reflected XSS
test_reflected_xss() {
    print_header "Test 1: Reflected XSS via Search Form"
    
    print_step "Sending XSS payload to DVWA..."
    XSS_PAYLOAD='<script>alert("XSS Vulnerability Found")</script>'
    
    curl -sL -b /tmp/dvwa_cookies.txt \
        -G "$DVWA_URL/vulnerabilities/xss_r/" \
        --data-urlencode "name=$XSS_PAYLOAD" > /tmp/dvwa_xss_response.html
    
    if grep -q "script" /tmp/dvwa_xss_response.html; then
        print_success "XSS payload reflected in DVWA response"
    else
        print_error "XSS payload not found in response"
    fi
    
    sleep 1
    
    # Inject SENTINEL event
    inject_sentinel_event "xss_reflected" \
        "$XSS_PAYLOAD" \
        "Reflected XSS detected via DVWA search parameter"
    
    echo ""
}

# Test 2: Stored XSS
test_stored_xss() {
    print_header "Test 2: Stored XSS via Guestbook"
    
    print_step "Submitting stored XSS payload to DVWA guestbook..."
    STORED_XSS='<img src=x onerror="alert(1)">'
    
    curl -sL -b /tmp/dvwa_cookies.txt \
        -d "txtName=TestUser&mtxMessage=$STORED_XSS&btnSign=Sign+Guestbook" \
        "$DVWA_URL/vulnerabilities/xss_s/index.php" > /tmp/dvwa_stored_xss_response.html
    
    if grep -q "TestUser" /tmp/dvwa_stored_xss_response.html; then
        print_success "Stored XSS payload submitted to DVWA"
    fi
    
    sleep 1
    
    # Inject SENTINEL event
    inject_sentinel_event "xss_stored" \
        "$STORED_XSS" \
        "Stored XSS detected in DVWA guestbook"
    
    echo ""
}

# Test 3: SQL Injection - UNION SELECT
test_sql_union() {
    print_header "Test 3: SQL Injection - UNION SELECT"
    
    print_step "Sending SQL injection payload (UNION SELECT) to DVWA..."
    SQL_PAYLOAD="1' UNION SELECT user, password FROM users#"
    
    curl -sL -b /tmp/dvwa_cookies.txt \
        -G "$DVWA_URL/vulnerabilities/sqli/" \
        --data-urlencode "id=$SQL_PAYLOAD" \
        --data-urlencode "Submit=Submit" > /tmp/dvwa_sqli_response.html
    
    if grep -q -i "union\|select" /tmp/dvwa_sqli_response.html || grep -q -i "syntax\|error" /tmp/dvwa_sqli_response.html; then
        print_success "SQL injection payload sent to DVWA"
    fi
    
    sleep 1
    
    # Inject SENTINEL event
    inject_sentinel_event "sql_injection" \
        "$SQL_PAYLOAD" \
        "SQL injection detected via DVWA user ID parameter (UNION SELECT)"
    
    echo ""
}

# Test 4: SQL Injection - Boolean-based
test_sql_boolean() {
    print_header "Test 4: SQL Injection - Boolean-Based"
    
    print_step "Sending boolean-based SQL injection payload..."
    SQL_PAYLOAD="1' OR '1'='1"
    
    curl -sL -b /tmp/dvwa_cookies.txt \
        -G "$DVWA_URL/vulnerabilities/sqli/" \
        --data-urlencode "id=$SQL_PAYLOAD" \
        --data-urlencode "Submit=Submit" > /tmp/dvwa_sqli_bool_response.html
    
    sleep 1
    
    # Inject SENTINEL event
    inject_sentinel_event "sql_injection_boolean" \
        "$SQL_PAYLOAD" \
        "Boolean-based SQL injection detected (OR 1=1 technique)"
    
    echo ""
}

# Test 5: SQL Injection - DROP TABLE
test_sql_drop() {
    print_header "Test 5: SQL Injection - DROP TABLE Detection"
    
    print_step "Testing DROP TABLE payload (read-only simulation)..."
    SQL_PAYLOAD="1'; DROP TABLE users;--"
    
    # This is just for testing SENTINEL detection, NOT actually executed
    print_step "Simulating DROP TABLE injection detection..."
    
    sleep 1
    
    # Inject SENTINEL event
    inject_sentinel_event "sql_injection_drop" \
        "$SQL_PAYLOAD" \
        "Dangerous DROP TABLE injection attempt detected"
    
    echo ""
}

# Function to verify events on dashboard
verify_dashboard() {
    print_header "Verification: Check Dashboard"
    
    echo ""
    echo "Open dashboard at: $SENTINEL_URL"
    echo ""
    echo "Steps to verify:"
    echo "  1. Hard refresh (Ctrl+Shift+R)"
    echo "  2. Look for TOAST notifications (top-right corner)"
    echo "  3. Check 'Incidents' tab for XSS/SQL entries"
    echo "  4. Check 'Recent Logs' → filter for 'network_defense' component"
    echo "  5. Look for security modal popup prompts"
    echo "  6. Check incidents endpoint: $SENTINEL_URL/api/v1/network/incidents?hours=1&limit=20"
    echo "  7. Check alerts endpoint: $SENTINEL_URL/api/v1/network/alerts?active_only=false&limit=20"
    echo ""
    echo "Expected to see:"
    echo "  ✓ 5 security events injected"
    echo "  ✓ Immediate alerts for each web attack"
    echo "  ✓ Toast notifications in dashboard"
    echo "  ✓ Security prompt modal (BLOCK/IGNORE/QUARANTINE)"
    echo ""
}

summarize_endpoint() {
    local label=$1
    local url=$2
    local response
    response=$(fetch_json "$url" || true)
    if [ -z "$response" ]; then
        echo "    ${label}: unavailable"
        return
    fi

    total=$(extract_json_value "$response" "total")
    case "$label" in
        Incidents)
            xss_hits=$(echo "$response" | grep -oi 'xss' | wc -l | tr -d ' ')
            sql_hits=$(echo "$response" | grep -oi 'sql\|sqli' | wc -l | tr -d ' ')
            echo "    ${label}: total=${total:-0}, xss_hits=${xss_hits:-0}, sql_hits=${sql_hits:-0}"
            ;;
        Alerts)
            web_hits=$(echo "$response" | grep -oi 'web_attack_detected' | wc -l | tr -d ' ')
            echo "    ${label}: total=${total:-0}, web_attack_alerts=${web_hits:-0}"
            ;;
        *)
            echo "    ${label}: total=${total:-0}"
            ;;
    esac
}

# Main execution
main() {
    print_header "DVWA + SENTINEL Integration Test"
    
    echo "This script will:"
    echo "  1. Test DVWA with XSS/SQL payloads"
    echo "  2. Automatically inject events into SENTINEL"
    echo "  3. Verify popups and alerts on dashboard"
    echo ""
    
    check_dvwa
    get_dvwa_session
    
    echo ""
    
    # Run all tests
    test_reflected_xss
    test_stored_xss
    test_sql_union
    test_sql_boolean
    test_sql_drop

    echo ""
    print_step "Checking SENTINEL incident and alert endpoints..."
    summarize_endpoint "Incidents" "$SENTINEL_URL/api/v1/network/incidents?hours=1&limit=20"
    summarize_endpoint "Alerts" "$SENTINEL_URL/api/v1/network/alerts?active_only=false&limit=20"
    
    # Verify results
    verify_dashboard
    
    print_success "All tests completed! Check dashboard for alerts and popups."
}

# Run main
main
