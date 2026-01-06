#!/bin/bash

# SENTINEL-AI Server Startup Script with Virtual Environment
# This script ensures all dependencies are installed and starts the server

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================================================"
echo "🛡️  SENTINEL-AI Threat Intelligence Platform"
echo "======================================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}⚠️  Virtual environment not found. Creating...${NC}"
    python3 -m venv venv
    echo -e "${GREEN}✅ Virtual environment created${NC}"
fi

# Activate virtual environment
echo -e "${BLUE}🔄 Activating virtual environment...${NC}"
source venv/bin/activate

# Verify we're using the right Python
PYTHON_PATH=$(which python)
echo -e "${BLUE}Using Python: ${PYTHON_PATH}${NC}"

# Upgrade pip
echo -e "${BLUE}🔄 Upgrading pip...${NC}"
pip install --upgrade pip > /dev/null 2>&1

# Install/upgrade requirements
echo -e "${BLUE}🔄 Installing requirements...${NC}"
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt --upgrade
    echo -e "${GREEN}✅ Requirements installed${NC}"
else
    echo -e "${RED}❌ requirements.txt not found!${NC}"
    exit 1
fi

# Check if Google packages are installed
echo -e "${BLUE}🔍 Checking Google AI packages...${NC}"
if ! python -c "import google.genai" 2>/dev/null; then
    echo -e "${YELLOW}⚠️  Installing Google AI packages...${NC}"
    pip install google-generativeai google-genai --upgrade
    echo -e "${GREEN}✅ Google AI packages installed${NC}"
else
    echo -e "${GREEN}✅ Google AI packages already installed${NC}"
fi

# Verify Google packages one more time
echo -e "${BLUE}🔍 Verifying Google AI installation...${NC}"
python -c "import google.genai; print('✅ google.genai imported successfully')" || {
    echo -e "${RED}❌ Failed to import google.genai${NC}"
    exit 1
}

echo ""
echo "======================================================================"
echo "🚀 Starting SENTINEL-AI Server"
echo "======================================================================"
echo ""
echo -e "${GREEN}Features Enabled:${NC}"
echo "  ✓ Multi-API Threat Detection (VirusTotal, Shodan, AbuseIPDB)"
echo "  ✓ Advanced ML-based Anomaly Detection"
echo "  ✓ AI-Powered Threat Analysis (Gemini)"
echo "  ✓ Real-time Scanning (IP, URL, File, Hash)"
echo "  ✓ Comprehensive PDF Report Generation"
echo "  ✓ Dashboard with Live Metrics"
echo ""
echo -e "${BLUE}Access Points:${NC}"
echo "  📊 Dashboard: http://localhost:8000"
echo "  🔌 API Docs:  http://localhost:8000/docs"
echo "  📖 ReDoc:     http://localhost:8000/redoc"
echo ""
echo "======================================================================"
echo ""

# Set environment variables for optimal performance
export SKIP_GEMINI_STARTUP_TESTS="true"
export PYTHONUNBUFFERED="1"

# Start the server with the venv Python
echo -e "${GREEN}Starting server with virtual environment Python...${NC}"
python run_server.py

# Deactivate virtual environment on exit
deactivate
