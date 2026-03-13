#!/bin/bash
# System Verification Script
# Checks if SENTINELAI is properly configured and ready to run

echo "========================================"
echo "🔍 SENTINELAI System Verification"
echo "========================================"
echo ""

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_CMD="python3"
if [ -x "$ROOT_DIR/.venv/bin/python" ]; then
    PYTHON_CMD="$ROOT_DIR/.venv/bin/python"
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

echo "Checking system requirements..."
echo ""

# Check Python
echo -n "Python 3... "
if command -v python3 &> /dev/null; then
    VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
    echo -e "${GREEN}✓${NC} Found ($VERSION)"
else
    echo -e "${RED}✗${NC} Not found"
    ((ERRORS++))
fi

# Check pip
echo -n "pip3... "
if command -v pip3 &> /dev/null; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${RED}✗${NC} Not found"
    ((ERRORS++))
fi

# Check required Python packages
echo ""
echo "Checking Python dependencies..."

check_python_package() {
    echo -n "  $1... "
    if "$PYTHON_CMD" -c "import $1" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Installed"
    else
        echo -e "${RED}✗${NC} Missing"
        ((ERRORS++))
    fi
}

check_python_package "psutil"
check_python_package "scapy"
check_python_package "requests"
check_python_package "fastapi"
check_python_package "uvicorn"

# Optional packages used by extended monitors
echo ""
echo "Checking optional monitor dependencies..."
check_optional_package() {
    echo -n "  $1... "
    if "$PYTHON_CMD" -c "import $1" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Installed"
    else
        echo -e "${YELLOW}⚠${NC} Missing (optional)"
        ((WARNINGS++))
    fi
}

check_optional_package "pyudev"

# Check system tools
echo ""
echo "Checking system tools..."

check_tool() {
    echo -n "  $1... "
    if command -v $1 &> /dev/null; then
        echo -e "${GREEN}✓${NC} Found"
    else
        echo -e "${YELLOW}⚠${NC} Not found (optional)"
        ((WARNINGS++))
    fi
}

check_tool "iptables"
check_tool "ipset"
check_tool "tcpdump"

# Check file structure
echo ""
echo "Checking file structure..."

check_file() {
    echo -n "  $1... "
    if [ -f "$1" ]; then
        echo -e "${GREEN}✓${NC} Exists"
    elif [ -d "$1" ]; then
        echo -e "${GREEN}✓${NC} Exists (directory)"
    else
        echo -e "${RED}✗${NC} Missing"
        ((ERRORS++))
    fi
}

check_file "server/run_server.py"
check_file "client/sentinel_integrated_protection.py"
check_file "client/scanner/intrusion_detector.py"
check_file "client/scanner/prevention_system.py"
check_file "client/scanner/activity_logger.py"

# Check permissions
echo ""
echo "Checking permissions..."

echo -n "  Network capture capability... "
PYTHON_BIN=$(which python3)
PYTHON_REAL=$(readlink -f "$PYTHON_BIN" 2>/dev/null || echo "$PYTHON_BIN")
if getcap "$PYTHON_REAL" 2>/dev/null | grep -q "cap_net_raw"; then
    echo -e "${GREEN}✓${NC} Configured"
else
    echo -e "${YELLOW}⚠${NC} Not configured (will need sudo)"
    ((WARNINGS++))
fi

echo -n "  Root/sudo access... "
if [ "$EUID" -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Running as root"
elif sudo -n true 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Sudo available"
else
    echo -e "${YELLOW}⚠${NC} May need sudo password"
    ((WARNINGS++))
fi

# Check network
echo ""
echo "Checking network..."

echo -n "  Network interfaces... "
IFACES=$(ip -br link | grep -c "UP")
if [ "$IFACES" -gt 0 ]; then
    echo -e "${GREEN}✓${NC} $IFACES interface(s) up"
else
    echo -e "${RED}✗${NC} No interfaces up"
    ((ERRORS++))
fi

echo -n "  Port 8000 availability... "
if command -v ss &> /dev/null; then
    if ss -ltn '( sport = :8000 )' | grep -q LISTEN; then
        echo -e "${YELLOW}⚠${NC} Port in use (LISTEN)"
        ((WARNINGS++))
    else
        echo -e "${GREEN}✓${NC} Available"
    fi
elif lsof -iTCP:8000 -sTCP:LISTEN -n -P &> /dev/null; then
    echo -e "${YELLOW}⚠${NC} Port in use (LISTEN)"
    ((WARNINGS++))
else
    echo -e "${GREEN}✓${NC} Available"
fi

# Check directories
echo ""
echo "Checking directories..."

check_dir() {
    echo -n "  $1... "
    if [ -d "$1" ]; then
        echo -e "${GREEN}✓${NC} Exists"
    else
        echo -e "${YELLOW}⚠${NC} Will be created"
        mkdir -p "$1" 2>/dev/null && echo -e " ${GREEN}✓${NC} Created" || echo -e " ${RED}✗${NC} Failed"
    fi
}

check_dir "logs"
check_dir "/var/log/sentinelai" 2>/dev/null || true
check_dir "/var/lib/sentinelai" 2>/dev/null || true

# Summary
echo ""
echo "========================================"
echo "Summary"
echo "========================================"

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✅ All checks passed!${NC}"
    echo ""
    echo "System is ready to run:"
    echo "  sudo ./run_complete_system.sh"
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠ ${WARNINGS} warning(s)${NC}"
    echo ""
    echo "System should work but may have limited functionality."
    echo "Run setup to fix warnings:"
    echo "  sudo ./setup_complete_system.sh"
else
    echo -e "${RED}❌ ${ERRORS} error(s), ${WARNINGS} warning(s)${NC}"
    echo ""
    echo "System needs setup. Run:"
    echo "  sudo ./setup_complete_system.sh"
    exit 1
fi

echo ""
