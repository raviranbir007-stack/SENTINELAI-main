#!/usr/bin/env bash
# Comprehensive validation script for SENTINEL-AI fixes

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT_DIR" || exit 1

PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
if [ ! -x "$PYTHON_BIN" ]; then
    PYTHON_BIN="$(command -v python3)"
fi

PASS=0
WARN=0
FAIL=0

ok() { echo "  ✓ $1"; PASS=$((PASS+1)); }
warn() { echo "  ⚠ $1"; WARN=$((WARN+1)); }
bad() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }

echo "======================================="
echo "SENTINEL-AI Comprehensive Validation"
echo "======================================="
echo ""

echo "✓ Checking required files..."
for f in \
    "client/sentinel_client_v3.py" \
    "client/scanner/logging_config.py" \
    "client/scanner/usb_monitor.py" \
    "client/scanner/email_monitor.py" \
    "client/scanner/vulnerability_scanner.py" \
    "client/scanner/behavioral_monitor.py" \
    "client/scanner/dns_monitor.py" \
    "server/app/core/nids_ingestor.py"; do
    [ -f "$f" ] && ok "$f" || bad "$f missing"
done

echo "✓ Checking UUID client ID generation..."
if grep -q "uuid.uuid4()" client/sentinel_client_v3.py; then
    ok "UUID client ID generation implemented"
else
    bad "UUID client ID generation missing"
fi

echo "✓ Checking defense event endpoint usage..."
if grep -q "/api/v1/network/event" client/sentinel_client_v3.py; then
    ok "Client targets /api/v1/network/event"
else
    warn "Client does not target /api/v1/network/event"
fi

echo "✓ Running import smoke test..."
if "$PYTHON_BIN" - <<'PY' >/tmp/sentinel_validate_imports.log 2>&1
import sys
from pathlib import Path

root = Path('.').resolve()
sys.path.insert(0, str((root / 'client').resolve()))
sys.path.insert(0, str((root / 'server').resolve()))

from scanner.usb_monitor import USBMonitor
from scanner.email_monitor import EmailMonitor
from scanner.vulnerability_scanner import VulnerabilityScanner
from scanner.behavioral_monitor import BehavioralMonitor
from scanner.dns_monitor import DNSMonitor
from scanner.network_scanner import NetworkScanner
from scanner.process_scanner import ProcessScanner
from scanner.file_scanner import FileScanner
from scanner.threat_analyzer import ThreatAnalyzer

from app.main import app
paths = {route.path for route in app.routes}
required = {
    '/api/v1/network/event',
    '/api/v1/network/events',
    '/api/v1/network/ingest/nids',
}
missing = sorted(required - paths)
if missing:
    raise RuntimeError(f"Missing API routes: {missing}")

print('IMPORT_SMOKE_OK')
PY
then
    ok "Python import smoke test passed"
else
    bad "Python import smoke test failed (see /tmp/sentinel_validate_imports.log)"
fi

echo ""
echo "======================================="
echo "Validation Summary"
echo "======================================="
echo "  Passed:   $PASS"
echo "  Warnings: $WARN"
echo "  Failed:   $FAIL"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "Result: FAILED"
    exit 1
fi

if [ "$WARN" -gt 0 ]; then
    echo "Result: PASSED with warnings"
else
    echo "Result: PASSED"
fi

echo ""
echo "Quick Start:"
echo "1. cd $ROOT_DIR"
echo "2. source .venv/bin/activate"
echo "3. python client/sentinel_client_v3.py"
echo ""
echo "View logs: tail -f sentinel_client_v3.log"
echo "======================================="
