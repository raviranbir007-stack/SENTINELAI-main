#!/bin/bash

# SENTINEL-AI Quick Setup Script
# This script helps you configure API keys and verify the setup

set -e

echo "=========================================="
echo "SENTINEL-AI Setup Script"
echo "=========================================="
echo ""

# Change to server directory
cd "$(dirname "$0")"

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "⚠️  .env file not found. Creating from template..."
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "✓ Created .env file from .env.example"
        echo ""
        echo "📝 Please edit .env and add your API keys:"
        echo "   nano .env"
        echo ""
        echo "Get FREE API keys from:"
        echo "   VirusTotal: https://www.virustotal.com/gui/join-us"
        echo "   URLScan: https://urlscan.io/user/signup"
        echo "   AbuseIPDB: https://www.abuseipdb.com/register"
        echo ""
        exit 0
    else
        echo "❌ .env.example not found!"
        exit 1
    fi
else
    echo "✓ .env file found"
fi

echo ""
echo "=========================================="
echo "Checking Python Environment"
echo "=========================================="

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "⚠️  Virtual environment not found. Creating..."
    python3 -m venv venv
    echo "✓ Virtual environment created"
fi

# Activate venv
source venv/bin/activate

echo "✓ Python: $(python --version)"
echo ""

echo "=========================================="
echo "Checking Dependencies"
echo "=========================================="

# Check reportlab
if python -c "import reportlab" 2>/dev/null; then
    VERSION=$(python -c "import reportlab; print(reportlab.Version)")
    echo "✓ ReportLab installed: version $VERSION"
else
    echo "⚠️  ReportLab not found. Installing..."
    pip install reportlab
    echo "✓ ReportLab installed"
fi

# Check other key dependencies
for package in fastapi httpx uvicorn; do
    if python -c "import $package" 2>/dev/null; then
        echo "✓ $package installed"
    else
        echo "⚠️  $package not found. Installing from requirements.txt..."
        pip install -r requirements.txt
        break
    fi
done

echo ""
echo "=========================================="
echo "Testing API Configuration"
echo "=========================================="

# Run API test
if [ -f "test_api_config.py" ]; then
    echo "Running API configuration tests..."
    echo ""
    python test_api_config.py
else
    echo "⚠️  test_api_config.py not found"
fi

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. If any APIs failed, edit .env and add API keys"
echo "2. Start the server with: ./venv/bin/python run_server.py"
echo "3. Test malicious URL: curl -X POST http://localhost:8000/api/scan -H 'Content-Type: application/json' -d '{\"target\": \"http://malware.wicar.org/data/eicar.com\"}'"
echo ""
