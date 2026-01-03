#!/bin/bash
# Quick start script for SENTINEL-AI

echo "🛡️  SENTINEL-AI Quick Start"
echo "================================"
echo ""

cd /home/kali/Documents/SENTINELAI-main/server

# Check .env
if [ ! -f ".env" ]; then
    echo "❌ No .env file found!"
    echo "📝 Creating from template..."
    cp .env.example .env
    echo ""
    echo "⚠️  IMPORTANT: Edit .env and add your API keys:"
    echo "   nano .env"
    echo ""
    echo "Get FREE API keys:"
    echo "   • VirusTotal: https://www.virustotal.com/gui/join-us"
    echo "   • URLScan: https://urlscan.io/user/signup"
    echo "   • AbuseIPDB: https://www.abuseipdb.com/register"
    echo ""
    echo "Then run this script again!"
    exit 1
fi

echo "✅ .env file found"
echo ""

# Check if APIs are configured
echo "🔍 Checking API configuration..."
source venv/bin/activate

# Quick check
HAS_VT=$(grep "^VIRUSTOTAL_API_KEY=" .env | grep -v "your_virustotal" | wc -l)
HAS_US=$(grep "^URLSCAN_API_KEY=" .env | grep -v "your_urlscan" | wc -l)
HAS_AB=$(grep "^ABUSEIPDB_API_KEY=" .env | grep -v "your_abuseipdb" | wc -l)

if [ "$HAS_VT" -eq 0 ]; then
    echo "⚠️  VirusTotal API key not configured (HIGHLY RECOMMENDED)"
fi
if [ "$HAS_US" -eq 0 ]; then
    echo "⚠️  URLScan API key not configured (optional)"
fi
if [ "$HAS_AB" -eq 0 ]; then
    echo "⚠️  AbuseIPDB API key not configured (optional)"
fi

if [ "$HAS_VT" -eq 0 ] && [ "$HAS_US" -eq 0 ] && [ "$HAS_AB" -eq 0 ]; then
    echo ""
    echo "❌ No API keys configured!"
    echo "   Edit .env and add at least VirusTotal API key"
    echo "   Then run: ./start.sh"
    exit 1
fi

echo ""
echo "🚀 Starting SENTINEL-AI server..."
echo "================================"
echo ""

# Start server
./venv/bin/python run_server.py
