#!/bin/bash
# Complete SENTINELAI IDS/IPS/Monitoring System Setup Script
# Installs all dependencies and configures the system

set -e

echo "======================================"
echo "🛡️  SENTINELAI Complete System Setup"
echo "======================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root/sudo
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ This script must be run as root or with sudo${NC}"
   echo "Usage: sudo ./setup_complete_system.sh"
   exit 1
fi

echo -e "${BLUE}📦 Installing system dependencies...${NC}"

# Update package list
apt-get update

# Install essential system packages
apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    libpcap-dev \
    tcpdump \
    iptables \
    ipset \
    net-tools \
    build-essential \
    libnotify-bin \
    libdbus-1-dev \
    libdbus-glib-1-dev \
    pkg-config \
    python3-dev

echo -e "${GREEN}✅ System dependencies installed${NC}"

echo -e "${BLUE}🐍 Setting up Python environment...${NC}"

INSTALL_DIR=$(pwd)
VENV_DIR="$INSTALL_DIR/.venv"

# Create venv if missing
if [ ! -x "$VENV_DIR/bin/python" ]; then
    echo -e "${YELLOW}⚠️  Virtual environment not found, creating at $VENV_DIR${NC}"
    python3 -m venv "$VENV_DIR"
fi

VENV_PY="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

# Install/upgrade pip inside venv
"$VENV_PY" -m pip install --upgrade pip

# Install Python dependencies from requirements files
echo -e "${BLUE}📦 Installing client dependencies...${NC}"
"$VENV_PIP" install -r "$INSTALL_DIR/client/requirements.txt"

echo -e "${BLUE}📦 Installing server dependencies...${NC}"
"$VENV_PIP" install -r "$INSTALL_DIR/server/requirements.txt"

echo -e "${GREEN}✅ Python dependencies installed${NC}"

echo -e "${BLUE}🔧 Configuring system permissions...${NC}"

# Set capabilities for packet capture (IDS functionality)
if command -v setcap &> /dev/null; then
    PYTHON_BIN="$VENV_DIR/bin/python"
    if [ -x "$PYTHON_BIN" ]; then
        if setcap cap_net_raw,cap_net_admin=eip "$PYTHON_BIN"; then
            echo -e "${GREEN}✅ Network capture capabilities set${NC}"
        else
            echo -e "${YELLOW}⚠️  Could not set capabilities. IDS may need root privileges${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  Python binary not found for setcap. IDS may need root privileges${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  setcap not available, IDS may need root privileges${NC}"
fi

# Create necessary directories
echo -e "${BLUE}📁 Creating system directories...${NC}"
mkdir -p /var/log/sentinelai
mkdir -p /var/lib/sentinelai
mkdir -p /etc/sentinelai
chmod 755 /var/log/sentinelai
chmod 755 /var/lib/sentinelai
chmod 755 /etc/sentinelai

echo -e "${GREEN}✅ System directories created${NC}"

# Backup hosts file
echo -e "${BLUE}💾 Backing up system files...${NC}"
if [ ! -f /etc/hosts.backup ]; then
    cp /etc/hosts /etc/hosts.backup
    echo -e "${GREEN}✅ Hosts file backed up${NC}"
fi

# Create systemd service for autostart
echo -e "${BLUE}⚙️  Creating systemd service...${NC}"

cat > /etc/systemd/system/sentinelai.service << EOF
[Unit]
Description=SENTINELAI Security Monitoring System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/run_complete_system.sh
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo -e "${GREEN}✅ Systemd service created${NC}"

echo -e "${BLUE}🔒 Configuring firewall rules...${NC}"
# Ensure iptables allows the system to function
iptables -I INPUT -i lo -j ACCEPT
iptables -I OUTPUT -o lo -j ACCEPT

# Create ipset for blocked IPs (IPS functionality)
if command -v ipset &> /dev/null; then
    ipset create -exist sentinelai_blocklist hash:ip timeout 3600
    iptables -I INPUT -m set --match-set sentinelai_blocklist src -j DROP
    echo -e "${GREEN}✅ IPS blocklist configured${NC}"
else
    echo -e "${YELLOW}⚠️  ipset not available, IPS blocking may be limited${NC}"
fi

echo ""
echo -e "${GREEN}======================================"
echo "✅ SENTINELAI Setup Complete!"
echo "======================================${NC}"
echo ""
echo -e "${BLUE}📋 System Status:${NC}"
echo "  ✓ IDS (Intrusion Detection System) - Ready"
echo "  ✓ IPS (Intrusion Prevention System) - Ready"
echo "  ✓ Activity Monitoring System - Ready"
echo "  ✓ Real-time Traffic Analysis - Ready"
echo "  ✓ Threat Detection & Prevention - Ready"
echo ""
echo -e "${YELLOW}📝 Next Steps:${NC}"
echo "  1. Configure your settings (optional):"
echo "     Edit: client/config.ini"
echo ""
echo "  2. Start the system:"
echo "     sudo ./run_complete_system.sh"
echo ""
echo "  3. Enable autostart (optional):"
echo "     sudo systemctl enable sentinelai"
echo "     sudo systemctl start sentinelai"
echo ""
echo -e "${BLUE}📚 Documentation:${NC}"
echo "  - Quick Start: QUICK_START.md"
echo "  - Start Monitoring: START_MONITORING.md"
echo "  - Testing Guide: TESTING_GUIDE_DVWA_METASPLOITABLE.md"
echo ""
