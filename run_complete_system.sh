#!/bin/bash
# Run Complete SENTINELAI IDS/IPS/Monitoring System
# Starts all components in proper order

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗    ║
║     ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║    ║
║     ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║    ║
║     ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║    ║
║     ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║    ║
║     ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝    ║
║                                                           ║
║          AI-Powered Security Monitoring System            ║
║      IDS • IPS • Real-time Threat Detection              ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running with proper privileges
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ This script must be run as root or with sudo${NC}"
   echo "Usage: sudo ./run_complete_system.sh"
   exit 1
fi

# Check if dependencies are installed
echo -e "${BLUE}🔍 Checking system dependencies...${NC}"

check_command() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}❌ Required command not found: $1${NC}"
        echo "Please run setup_complete_system.sh first"
        exit 1
    fi
}

check_python_package() {
    if ! python3 -c "import $1" 2>/dev/null; then
        echo -e "${RED}❌ Required Python package not found: $1${NC}"
        echo "Please run setup_complete_system.sh first"
        exit 1
    fi
}

check_command python3
check_command iptables
check_python_package psutil
check_python_package scapy
check_python_package requests

echo -e "${GREEN}✅ All dependencies present${NC}"

# Create log directory
mkdir -p logs
LOG_DIR="logs"
SERVER_LOG="$LOG_DIR/server.log"
CLIENT_LOG="$LOG_DIR/client.log"
SYSTEM_LOG="$LOG_DIR/system.log"

# Function to cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}🛑 Shutting down SENTINELAI...${NC}"
    
    # Kill server
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        echo -e "${GREEN}✓ Server stopped${NC}"
    fi
    
    # Kill client
    if [ ! -z "$CLIENT_PID" ]; then
        kill $CLIENT_PID 2>/dev/null || true
        echo -e "${GREEN}✓ Client stopped${NC}"
    fi
    
    echo -e "${GREEN}✅ SENTINELAI stopped cleanly${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

# Prefer venv Python if available
PYTHON_BIN="python3"
if [ -x "/home/kali/Documents/SENTINELAI-main/.venv/bin/python" ]; then
    PYTHON_BIN="/home/kali/Documents/SENTINELAI-main/.venv/bin/python"
elif [ -x "$PWD/.venv/bin/python" ]; then
    PYTHON_BIN="$PWD/.venv/bin/python"
fi

# Start the server
echo -e "${BLUE}🚀 Starting SENTINELAI Server...${NC}"
cd server
$PYTHON_BIN run_server.py > "../$SERVER_LOG" 2>&1 &
SERVER_PID=$!
cd ..

# Wait for server to start
echo -e "${YELLOW}⏳ Waiting for server to initialize...${NC}"
for i in {1..30}; do
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Server started successfully (PID: $SERVER_PID)${NC}"
        break
    fi
    sleep 1
    if [ $i -eq 30 ]; then
        echo -e "${RED}❌ Server failed to start. Check $SERVER_LOG${NC}"
        cat "$SERVER_LOG"
        exit 1
    fi
done

# Start the integrated client (IDS/IPS/Monitor)
echo -e "${BLUE}🛡️  Starting SENTINELAI Protection Client...${NC}"
cd client
$PYTHON_BIN sentinel_integrated_protection.py &
CLIENT_PID=$!
cd ..

sleep 3

if ps -p $CLIENT_PID > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Protection client started successfully (PID: $CLIENT_PID)${NC}"
else
    echo -e "${RED}❌ Protection client failed to start. Check $CLIENT_LOG${NC}"
    cat "$CLIENT_LOG"
    exit 1
fi

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                           ║${NC}"
echo -e "${GREEN}║  ✅ SENTINELAI is now ACTIVE and PROTECTING your system  ║${NC}"
echo -e "${GREEN}║                                                           ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}📊 System Status:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${GREEN}●${NC} IDS (Intrusion Detection)     : ${GREEN}ACTIVE${NC}"
echo -e "  ${GREEN}●${NC} IPS (Intrusion Prevention)    : ${GREEN}ACTIVE${NC}"
echo -e "  ${GREEN}●${NC} Activity Monitor              : ${GREEN}ACTIVE${NC}"
echo -e "  ${GREEN}●${NC} Real-time Traffic Analysis    : ${GREEN}ACTIVE${NC}"
echo -e "  ${GREEN}●${NC} Threat Detection Engine       : ${GREEN}ACTIVE${NC}"
echo -e "  ${GREEN}●${NC} Prevention & Blocking         : ${GREEN}ACTIVE${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${BLUE}🌐 Server:${NC}"
echo "  Dashboard : http://localhost:8000"
echo "  API       : http://localhost:8000/api/v1"
echo "  Status    : http://localhost:8000/health"
echo ""
echo -e "${BLUE}📂 Logs:${NC}"
echo "  Server    : $SERVER_LOG"
echo "  Client    : client/sentinel_integrated.log"
echo "  System    : $SYSTEM_LOG"
echo ""
echo -e "${YELLOW}📝 Quick Commands:${NC}"
echo "  View logs       : tail -f logs/*.log"
echo "  Check status    : systemctl status sentinelai"
echo "  Stop system     : Press Ctrl+C"
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}System is monitoring... Press Ctrl+C to stop${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Monitor and show real-time status
while true; do
    # Check if processes are still running
    if ! ps -p $SERVER_PID > /dev/null 2>&1; then
        echo -e "${RED}❌ Server process died unexpectedly${NC}"
        cat "$SERVER_LOG"
        exit 1
    fi
    
    if ! ps -p $CLIENT_PID > /dev/null 2>&1; then
        echo -e "${RED}❌ Client process died unexpectedly${NC}"
        cat "$CLIENT_LOG"
        exit 1
    fi
    
    # Show brief activity summary every 30 seconds
    sleep 30
    
    # Get stats
    BLOCKED_IPS=$(iptables -L INPUT -v -n | grep -c "sentinelai" || echo "0")
    ACTIVE_CONNS=$(ss -tn | wc -l)
    
    echo -e "${CYAN}[$(date '+%H:%M:%S')]${NC} Status: ${GREEN}●${NC} Running | Blocked IPs: $BLOCKED_IPS | Active Connections: $ACTIVE_CONNS"
done
