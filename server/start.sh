#!/bin/bash

# SENTINEL-AI Production Startup Script
# Combines venv setup, dependency installation, and integrated system startup

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Snapshot root .env before startup so credentials can be recovered if deleted.
"$SCRIPT_DIR/../tools/backup_env.sh"

echo "======================================================================"
echo "🛡️  SENTINEL-AI Threat Intelligence Platform - Production Start"
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

# Ensure fuzzy hashing dependency is available even when build isolation breaks pkg_resources.
if ! python -c "import ssdeep" 2>/dev/null; then
    echo -e "${YELLOW}⚠️  ssdeep missing; retrying with no-build-isolation...${NC}"
    pip install --no-build-isolation ssdeep || {
        echo -e "${RED}❌ Failed to install ssdeep (fuzzy hashing support).${NC}"
        exit 1
    }
    echo -e "${GREEN}✅ ssdeep installed${NC}"
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

# Check if database exists
DB_PATH="../client/activity_logs.db"
if [ -f "$DB_PATH" ]; then
    echo -e "${GREEN}📊 Activity database: Found${NC}"
else
    echo -e "${YELLOW}📊 Activity database: Will be created${NC}"
fi

echo ""
echo "======================================================================"
echo "🚀 Starting SENTINEL-AI Integrated System (Server + Client)"
echo "======================================================================"
echo ""
echo -e "${GREEN}Features Enabled:${NC}"
echo "  ✓ Multi-API Threat Detection (VirusTotal, Shodan, AbuseIPDB)"
echo "  ✓ Advanced ML-based Anomaly Detection"
echo "  ✓ AI-Powered Threat Analysis (Gemini)"
echo "  ✓ Real-time Activity Monitoring"
echo "  ✓ Automatic Threat Blocking & Quarantine"
echo "  ✓ Comprehensive PDF Report Generation"
echo "  ✓ Dashboard with Live Metrics"
echo ""
echo -e "${BLUE}Access Points:${NC}"
echo "  📊 Dashboard: http://localhost:8000"
echo "  🔌 API Docs:  http://localhost:8000/docs"
echo ""
echo "======================================================================"
echo ""

# Set environment variables for optimal performance
export SKIP_GEMINI_STARTUP_TESTS="true"
export SENTINEL_ENABLE_STARTUP_MONITORS="true"
export PYTHONUNBUFFERED="1"

# Start the integrated system with the venv Python
echo -e "${GREEN}Starting integrated system with virtual environment Python...${NC}"
python run_server.py

# Deactivate virtual environment on exit
deactivate
