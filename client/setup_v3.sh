#!/bin/bash

# SENTINEL-AI v3.0 Setup Script
# Sets up the client with all new features

echo "=============================================="
echo "  SENTINEL-AI v3.0 Client Setup"
echo "=============================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  Warning: This script should be run as root for full functionality"
    echo "   Some features (firewall, hosts file modification) require root"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Install dependencies
echo "📦 Installing dependencies..."
pip3 install -r requirements.txt
pip3 install psutil watchdog

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo "✅ Dependencies installed"
echo ""

# Create config file if not exists
if [ ! -f "config.ini" ]; then
    echo "📝 Creating config file..."
    
    cat > config.ini << 'EOF'
[server]
url = http://localhost:5000
api_key = your-api-key-here

[client]
scan_interval = 300
heartbeat_interval = 60
enable_auto_defense = true

[defense]
enable_auto_quarantine = true
max_alerts = 5
alert_interval = 30
response_timeout = 300

[apis]
virustotal = 
abuseipdb = 
urlscan = 
shodan = 
hybrid_analysis = 

[monitoring]
enable_activity_logging = true
log_websites = true
log_applications = true
log_network_connections = true

[prevention]
auto_block_high_risk = true
auto_block_critical_risk = true
show_warnings = true
EOF
    
    echo "✅ Config file created: config.ini"
    echo "⚠️  Please edit config.ini and add your API keys"
    echo ""
else
    echo "ℹ️  Config file already exists"
    echo ""
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p logs
mkdir -p quarantine
mkdir -p ~/.sentinelai_quarantine

echo "✅ Directories created"
echo ""

# Check system requirements
echo "🔍 Checking system requirements..."

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "   Python version: $python_version"

# Check if iptables is available (Linux only)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if command -v iptables &> /dev/null; then
        echo "   ✓ iptables available"
    else
        echo "   ⚠️  iptables not found (install with: apt install iptables)"
    fi
fi

# Check if notify-send is available (Linux only)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if command -v notify-send &> /dev/null; then
        echo "   ✓ Desktop notifications available"
    else
        echo "   ⚠️  notify-send not found (install with: apt install libnotify-bin)"
    fi
fi

echo ""
echo "=============================================="
echo "  Setup Complete!"
echo "=============================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Edit config.ini and add your API keys:"
echo "   - VirusTotal: https://www.virustotal.com/gui/join-us"
echo "   - AbuseIPDB: https://www.abuseipdb.com/register"
echo "   - URLScan.io: https://urlscan.io/"
echo "   - Shodan: https://account.shodan.io/register"
echo "   - Hybrid Analysis: https://www.hybrid-analysis.com/signup"
echo ""
echo "2. Make sure the SENTINEL-AI server is running:"
echo "   cd ../server && python run_server.py"
echo ""
echo "3. Run the client (requires root/sudo):"
echo "   sudo python3 sentinel_client_v3.py"
echo ""
echo "For detailed documentation, see: ../SENTINEL_V3_FEATURES.md"
echo ""
echo "🛡️  Stay secure!"
echo ""
