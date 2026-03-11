#!/bin/bash

# SENTINEL-AI Enhanced System Setup
# Installs all dependencies and prepares the automated monitoring system

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║     SENTINEL-AI Enhanced Automated Monitoring Setup             ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root for full features
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  Not running as root. Packet capture will be limited."
    echo "   For full features, run: sudo $0"
    echo ""
fi

# Install Python dependencies
echo "📦 Installing Python dependencies..."

# Client dependencies
pip3 install -q scapy psutil requests watchdog

# Server dependencies (if not already installed)
pip3 install -q fastapi uvicorn sqlalchemy aiosqlite httpx

echo "✅ Dependencies installed"
echo ""

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p client/logs
mkdir -p server/logs
mkdir -p reports

echo "✅ Directories created"
echo ""

# Initialize databases
echo "🗄️  Initializing databases..."
cd server
python3 -c "from app.core.activity_database import activity_db; print('Activity database initialized')"
cd ..

echo "✅ Databases initialized"
echo ""

# Display configuration instructions
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                    SETUP COMPLETE                                ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Next Steps:"
echo ""
echo "1️⃣  Configure API Keys (if not already done):"
echo "   cd server"
echo "   python3 check_api_keys.py"
echo ""
echo "2️⃣  Start the SENTINEL-AI Server:"
echo "   cd server"
echo "   python3 run_app.py"
echo "   (Terminal will show real-time activity monitoring)"
echo ""
echo "3️⃣  Start Automated Client (in new terminal):"
echo "   cd client"
echo "   sudo python3 sentinel_automated.py"
echo "   (Use sudo for full packet capture, or run without for limited mode)"
echo ""
echo "4️⃣  Monitor Activity:"
echo "   - Server terminal shows real-time updates every 30 seconds"
echo "   - Activity database: client/activity_monitoring.db"
echo "   - Threat logs: client/threats_detected.json"
echo ""
echo "📊 Key Features Enabled:"
echo "   ✓ Automatic network traffic monitoring"
echo "   ✓ Multi-API corroboration (addresses 79.1% single-source issue)"
echo "   ✓ Comprehensive activity logging"
echo "   ✓ Real-time terminal display"
echo "   ✓ Manual re-analysis capability"
echo ""
echo "📖 For detailed integration instructions, see:"
echo "   cat INTEGRATION_GUIDE.py"
echo ""
echo "✅ Setup complete!"
