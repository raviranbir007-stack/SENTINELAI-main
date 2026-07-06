#!/bin/bash
# Quick Start - SENTINEL-AI Integrated System

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

clear
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║           SENTINEL-AI v3.0 - Quick Start                        ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "🎯 What This System Does:"
echo "   ✅ Monitors ALL your activities (websites, apps, connections)"
echo "   ✅ Analyzes each activity with AI (5 APIs + Gemini + ML)"
echo "   ✅ Shows SAFE/UNSAFE feedback in terminal"
echo "   ✅ Blocks threats automatically"
echo "   ✅ Defends against outside attacks"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📋 Ready to start? Choose an option:"
echo ""
echo "   1) Start with activity monitoring (Recommended)"
echo "   2) Start without sudo (limited blocking)"
echo "   3) View documentation"
echo "   4) Check database logs"
echo "   5) Exit"
echo ""
read -p "Enter choice [1-5]: " choice

case $choice in
    1)
        echo ""
        echo "🚀 Starting SENTINEL-AI with full monitoring..."
        echo ""
        cd "$PROJECT_ROOT/server"
        sudo bash start_integrated.sh
        ;;
    2)
        echo ""
        echo "⚠️  Starting without sudo (blocking disabled)..."
        echo ""
        cd "$PROJECT_ROOT/server"
        python3 run_app.py
        ;;
    3)
        echo ""
        echo "📖 Documentation files:"
        echo ""
        echo "   • SYSTEM_READY.md - Complete guide"
        echo "   • INTEGRATED_SYSTEM_GUIDE.md - Detailed documentation"
        echo "   • READY_TO_USE.md - Quick reference"
        echo ""
        read -p "Press Enter to continue..."
        ;;
    4)
        echo ""
        cd "$PROJECT_ROOT/client"
        if [ -f "activity_logs.db" ]; then
            echo "📊 Activity Database Statistics:"
            echo ""
            echo "Websites visited:"
            sqlite3 activity_logs.db "SELECT COUNT(*) FROM websites;" 2>/dev/null || echo "0"
            echo ""
            echo "Applications launched:"
            sqlite3 activity_logs.db "SELECT COUNT(*) FROM applications;" 2>/dev/null || echo "0"
            echo ""
            echo "Network connections:"
            sqlite3 activity_logs.db "SELECT COUNT(*) FROM network_connections;" 2>/dev/null || echo "0"
            echo ""
            echo "Recent websites:"
            sqlite3 activity_logs.db "SELECT datetime(timestamp), domain, risk_level FROM websites ORDER BY timestamp DESC LIMIT 5;" 2>/dev/null
        else
            echo "⚠️  No database found yet. Start the server first!"
        fi
        echo ""
        read -p "Press Enter to continue..."
        ;;
    5)
        echo ""
        echo "👋 Goodbye!"
        exit 0
        ;;
    *)
        echo ""
        echo "❌ Invalid choice. Please run again."
        exit 1
        ;;
esac
