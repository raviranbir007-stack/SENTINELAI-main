#!/bin/bash

# SENTINEL-AI Integrated Server Startup
# This starts the server with real-time activity monitoring

echo "============================================================"
echo "  🛡️  SENTINEL-AI v3.0 - Integrated System"
echo "============================================================"
echo ""
echo "Features:"
echo "  ✅ Real-time activity monitoring"
echo "  ✅ AI-powered threat analysis (5 APIs + Gemini)"
echo "  ✅ Automatic blocking of threats"
echo "  ✅ Firewall defense against attacks"
echo "  ✅ 5-alert auto-quarantine system"
echo ""
echo "============================================================"
echo ""

# Check if running as root (needed for blocking)
if [ "$EUID" -eq 0 ]; then 
    echo "✅ Running as root (blocking enabled)"
else
    echo "⚠️  Not running as root - blocking features may not work"
    echo "   Run with: sudo bash start_integrated.sh"
    echo ""
fi

# Navigate to server directory
cd "$(dirname "$0")"

echo "📂 Working directory: $(pwd)"
echo ""

# Check Python version
echo "🐍 Python version:"
python3 --version
echo ""

# Check if database exists
DB_PATH="../client/activity_logs.db"
if [ -f "$DB_PATH" ]; then
    echo "📊 Activity database: Found"
else
    echo "📊 Activity database: Will be created"
fi
echo ""

# Start server
echo "🚀 Starting SENTINEL-AI server..."
echo "============================================================"
echo ""
echo "📺 SERVER OUTPUT:"
echo "   All activities will be displayed below"
echo "   Press Ctrl+C to stop"
echo ""
echo "============================================================"
echo ""

# Run server
python3 run_app.py
