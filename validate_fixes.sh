#!/bin/bash
# Validation script for SENTINEL-AI fixes

echo "======================================="
echo "SENTINEL-AI System Validation"
echo "======================================="
echo ""

# Check Python files for remaining verbose prints
echo "✓ Checking for excessive logging..."
VERBOSE_COUNT=$(grep -r "print(" client/sentinel_client*.py 2>/dev/null | grep -v "def \|#" | wc -l)
if [ "$VERBOSE_COUNT" -eq 0 ]; then
    echo "  ✓ No verbose print statements in main files"
else
    echo "  ⚠ Found $VERBOSE_COUNT print statements"
fi

# Check logging configuration
echo "✓ Checking logging configuration..."
if [ -f "client/scanner/logging_config.py" ]; then
    echo "  ✓ logging_config.py exists"
else
    echo "  ✗ logging_config.py missing"
fi

# Check for UUID import in main clients
echo "✓ Checking for UUID client ID generation..."
if grep -q "uuid.uuid4()" client/sentinel_client_enhanced.py client/sentinel_client_v3.py; then
    echo "  ✓ UUID client ID generation implemented"
else
    echo "  ✗ UUID client ID generation missing"
fi

# Check activity logger for website logging
echo "✓ Checking website logging implementation..."
if grep -q "_log_website\|_parse_firefox_history\|_parse_chrome_history" client/scanner/activity_logger.py; then
    echo "  ✓ Website logging methods present"
else
    echo "  ✗ Website logging methods missing"
fi

# Check for database table creation
echo "✓ Checking database schema..."
if grep -q "CREATE TABLE IF NOT EXISTS websites" client/scanner/activity_logger.py; then
    echo "  ✓ Website database table configured"
else
    echo "  ✗ Website table missing"
fi

# Check for error handling improvements
echo "✓ Checking error handling..."
if grep -q "logger.error.*failed" client/sentinel_client_enhanced.py; then
    echo "  ✓ Improved error messages"
else
    echo "  ✗ Error messages not improved"
fi

echo ""
echo "======================================="
echo "Validation Complete"
echo "======================================="
echo ""
echo "Quick Start:"
echo "1. cd /home/kali/Documents/SENTINELAI-main"
echo "2. source .venv/bin/activate"
echo "3. python client/sentinel_client_v3.py"
echo ""
echo "View logs: tail -f sentinel_client_v3.log"
echo "======================================="
