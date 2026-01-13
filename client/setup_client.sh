#!/bin/bash
#
# SENTINEL-AI Client Setup Script
# Automated installation and configuration for client deployment
#
# Usage: ./setup_client.sh [SERVER_URL] [API_KEY]
#

set -e  # Exit on error

echo "========================================"
echo "SENTINEL-AI Client Setup"
echo "========================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get server URL and API key from arguments or prompt
if [ -z "$1" ]; then
    read -p "Enter SENTINEL-AI server URL (e.g., http://192.168.1.100:8000): " SERVER_URL
else
    SERVER_URL=$1
fi

if [ -z "$2" ]; then
    read -p "Enter API key: " API_KEY
else
    API_KEY=$2
fi

# Validate inputs
if [ -z "$SERVER_URL" ] || [ -z "$API_KEY" ]; then
    echo -e "${RED}✗ Server URL and API key are required${NC}"
    exit 1
fi

# Step 1: Check Python version
echo "Step 1: Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
    echo -e "${GREEN}✓ Python 3 found: $(python3 --version)${NC}"
    
    # Check if version is 3.8 or higher
    if (( $(echo "$PYTHON_VERSION >= 3.8" | bc -l) )); then
        echo -e "${GREEN}✓ Python version is compatible${NC}"
    else
        echo -e "${RED}✗ Python 3.8+ is required (found $PYTHON_VERSION)${NC}"
        exit 1
    fi
else
    echo -e "${RED}✗ Python 3 not found. Please install Python 3.8+${NC}"
    exit 1
fi
echo ""

# Step 2: Create virtual environment
echo "Step 2: Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${YELLOW}⚠ Virtual environment already exists${NC}"
fi
echo ""

# Step 3: Install dependencies
echo "Step 3: Installing dependencies..."
source venv/bin/activate
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt
pip install psutil watchdog requests aiohttp
echo -e "${GREEN}✓ Dependencies installed${NC}"
echo ""

# Step 4: Create configuration file
echo "Step 4: Creating configuration..."
cat > config.ini << EOF
[server]
url = $SERVER_URL
api_key = $API_KEY

[client]
enable_auto_defense = true
scan_interval = 300
heartbeat_interval = 60
auto_report_attacks = true
auto_block_threats = true

[scanning]
monitor_downloads = true
monitor_network = true
scan_uploads = true
max_file_size = 100

[defense]
use_iptables = true
use_windows_firewall = false
use_hosts_file = true
quarantine_dir = /var/quarantine
EOF

echo -e "${GREEN}✓ Configuration file created (config.ini)${NC}"
echo ""

# Step 5: Test connection to server
echo "Step 5: Testing connection to server..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$SERVER_URL/" || echo "000")
if [ "$HTTP_CODE" -eq 200 ] || [ "$HTTP_CODE" -eq 404 ]; then
    echo -e "${GREEN}✓ Server is reachable${NC}"
else
    echo -e "${YELLOW}⚠ Cannot connect to server (HTTP $HTTP_CODE)${NC}"
    echo "  Make sure the server is running and accessible"
fi
echo ""

# Step 6: Test client registration
echo "Step 6: Testing client registration..."
python3 << PYEOF
import asyncio
import sys
sys.path.insert(0, '.')
from sentinel_client_enhanced import SentinelClient

async def test_registration():
    try:
        client = SentinelClient()
        success = await client.register()
        if success:
            print("✓ Client registered successfully")
            print(f"  Client ID: {client.client_id}")
            return client.client_id
        else:
            print("✗ Registration failed")
            return None
    except Exception as e:
        print(f"✗ Registration error: {e}")
        return None

client_id = asyncio.run(test_registration())
if client_id:
    with open('.client_id', 'w') as f:
        f.write(client_id)
PYEOF

if [ -f ".client_id" ]; then
    CLIENT_ID=$(cat .client_id)
    echo -e "${GREEN}✓ Registration successful${NC}"
else
    echo -e "${YELLOW}⚠ Registration failed - will retry on next start${NC}"
fi
echo ""

# Step 7: Create systemd service (Linux only)
if [ "$(uname)" = "Linux" ]; then
    echo "Step 7: Setting up system service..."
    read -p "Create systemd service for auto-start? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        CURRENT_DIR=$(pwd)
        USER=$(whoami)
        
        sudo tee /etc/systemd/system/sentinelai-client.service > /dev/null << EOF
[Unit]
Description=SENTINEL-AI Client Protection
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$CURRENT_DIR
Environment="PATH=$CURRENT_DIR/venv/bin"
ExecStart=$CURRENT_DIR/venv/bin/python sentinel_client_enhanced.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        
        sudo systemctl daemon-reload
        sudo systemctl enable sentinelai-client.service
        echo -e "${GREEN}✓ Systemd service created${NC}"
        echo "  Start: sudo systemctl start sentinelai-client"
        echo "  Stop:  sudo systemctl stop sentinelai-client"
        echo "  Status: sudo systemctl status sentinelai-client"
    fi
else
    echo "Step 7: Service setup (skipped - not Linux)"
fi
echo ""

# Step 8: Create startup script
echo "Step 8: Creating startup script..."
cat > start_client.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python sentinel_client_enhanced.py
EOF
chmod +x start_client.sh
echo -e "${GREEN}✓ Startup script created (start_client.sh)${NC}"
echo ""

# Create setup summary
cat > CLIENT_SETUP_SUMMARY.txt << EOF
SENTINEL-AI Client Setup Summary
=================================
Date: $(date)
Hostname: $(hostname)
IP Address: $(hostname -I | awk '{print $1}')

Server Configuration:
- Server URL: $SERVER_URL
- Client ID: ${CLIENT_ID:-"Not registered yet"}

Client Configuration:
- Auto-defense: Enabled
- Scan interval: 300 seconds (5 minutes)
- Heartbeat: 60 seconds
- Network monitoring: Enabled
- File monitoring: Enabled

Startup:
- Manual: ./start_client.sh or python sentinel_client_enhanced.py
- Service: sudo systemctl start sentinelai-client (if configured)

Logs:
- sentinel_client.log

Configuration:
- config.ini
EOF

echo "========================================"
echo -e "${GREEN}Client Setup Complete!${NC}"
echo "========================================"
echo ""
echo "📋 Setup summary saved to: CLIENT_SETUP_SUMMARY.txt"
echo ""
echo "🚀 Quick Start:"
echo "   ./start_client.sh"
echo ""
echo "🔧 System Service (if configured):"
echo "   sudo systemctl start sentinelai-client"
echo ""
echo "📊 Check Status:"
echo "   tail -f sentinel_client.log"
echo ""
echo "🌐 Server Dashboard:"
echo "   $SERVER_URL/static/index.html"
echo ""

if [ -f ".client_id" ]; then
    echo "✅ Client ID: $CLIENT_ID"
    echo ""
fi
