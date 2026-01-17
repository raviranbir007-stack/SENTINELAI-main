#!/bin/bash
#
# SENTINEL-AI Server Setup Script
# Automated installation and configuration for server deployment
#
# Usage: ./setup_server.sh
#

set -e  # Exit on error

echo "========================================"
echo "SENTINEL-AI Server Setup"
echo "========================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo -e "${YELLOW}Warning: Running as root. Consider using a dedicated user.${NC}"
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

# Step 3: Activate virtual environment and install dependencies
echo "Step 3: Installing dependencies..."
source venv/bin/activate
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt
pip install aiosqlite reportlab psutil
echo -e "${GREEN}✓ Dependencies installed${NC}"
echo ""

# Step 4: Setup environment configuration
echo "Step 4: Configuring environment..."
if [ ! -f ".env" ]; then
    cat > .env << EOF
# Database Configuration
DATABASE_URL=sqlite+aiosqlite:///./sentinelai.db

# Server Configuration
HOST=0.0.0.0
PORT=8000
DEBUG=false

# Security Keys (CHANGE THESE IN PRODUCTION!)
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
JWT_SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')

# API Keys - Add your keys here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here
URLSCAN_API_KEY=your_urlscan_api_key_here
HYBRID_ANALYSIS_API_KEY=your_hybrid_analysis_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here

# Rate Limiting
MAX_REQUESTS_PER_MINUTE=60

# CORS Origins (comma-separated)
CORS_ORIGINS=http://localhost:3000,http://localhost:8000
EOF
    echo -e "${GREEN}✓ Environment file created (.env)${NC}"
    echo -e "${YELLOW}⚠ IMPORTANT: Edit .env file and add your API keys!${NC}"
else
    echo -e "${YELLOW}⚠ .env file already exists (not overwritten)${NC}"
fi
echo ""

# Step 5: Initialize database
echo "Step 5: Initializing database..."
python migrate_database.py --with-test-data
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Database initialized successfully${NC}"
else
    echo -e "${RED}✗ Database initialization failed${NC}"
    exit 1
fi
echo ""

# Step 6: Create systemd service (optional, Linux only)
echo "Step 6: Setting up system service..."
if [ -f "/etc/systemd/system/sentinelai.service" ]; then
    echo -e "${YELLOW}⚠ Service already exists${NC}"
else
    read -p "Create systemd service for auto-start? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        CURRENT_DIR=$(pwd)
        USER=$(whoami)
        
        sudo tee /etc/systemd/system/sentinelai.service > /dev/null << EOF
[Unit]
Description=SENTINEL-AI Threat Detection Server
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$CURRENT_DIR
Environment="PATH=$CURRENT_DIR/venv/bin"
ExecStart=$CURRENT_DIR/venv/bin/python run_server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        
        sudo systemctl daemon-reload
        sudo systemctl enable sentinelai.service
        echo -e "${GREEN}✓ Systemd service created${NC}"
        echo "  Start: sudo systemctl start sentinelai"
        echo "  Stop:  sudo systemctl stop sentinelai"
        echo "  Status: sudo systemctl status sentinelai"
    fi
fi
echo ""

# Step 7: Configure firewall (optional)
echo "Step 7: Firewall configuration..."
if command -v ufw &> /dev/null; then
    read -p "Configure firewall to allow port 8000? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo ufw allow 8000/tcp
        echo -e "${GREEN}✓ Firewall configured${NC}"
    fi
fi
echo ""

# Step 8: Create admin API key
echo "Step 8: Creating admin API key..."
ADMIN_TOKEN=$(python3 -c "
import sys
sys.path.insert(0, '.')
from app.auth import create_access_token
token = create_access_token({'sub': 'admin', 'admin': True})
print(token)
")
echo ""
echo -e "${GREEN}✓ Admin API Token:${NC}"
echo "  $ADMIN_TOKEN"
echo ""
echo "Save this token! You'll need it for API requests."
echo ""

# Create setup summary
cat > SETUP_SUMMARY.txt << EOF
SENTINEL-AI Server Setup Summary
================================
Date: $(date)

Server Configuration:
- Host: 0.0.0.0
- Port: 8000
- Database: sentinelai.db

Admin Credentials:
- Username: admin
- Password: admin123
- API Token: $ADMIN_TOKEN

Next Steps:
1. Edit .env file and add your API keys
2. Change admin password (username: admin, password: admin123)
3. Start the server: ./start_server.sh or python run_server.py
4. Access API docs: http://localhost:8000/docs
5. Deploy clients to systems you want to protect

Important Files:
- Configuration: .env
- Database: sentinelai.db
- Logs: logs/
- This summary: SETUP_SUMMARY.txt

Client Setup:
Run setup_client.sh on each system you want to protect
EOF

echo "========================================"
echo -e "${GREEN}Server Setup Complete!${NC}"
echo "========================================"
echo ""
echo "📋 Setup summary saved to: SETUP_SUMMARY.txt"
echo ""
echo "⚠️  IMPORTANT: Edit .env file and add your API keys"
echo ""
echo "🚀 Quick Start:"
echo "   1. Edit .env file: nano .env"
echo "   2. Add API keys (VirusTotal, AbuseIPDB, etc.)"
echo "   3. Start server: python run_server.py"
echo "   4. Access API: http://localhost:8000/docs"
echo "   5. Setup clients using setup_client.sh"
echo ""
echo "📚 Documentation:"
echo "   - Full Guide: CLIENT_SETUP_GUIDE.md"
echo "   - Quick Reference: QUICK_REFERENCE.md"
echo "   - Installation Checklist: INSTALLATION_CHECKLIST.md"
echo ""
echo "🔑 Admin Token (save this!):"
echo "   $ADMIN_TOKEN"
echo ""
