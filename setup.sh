#!/bin/bash
# SENTINEL-AI Unified Setup Script
# Handles setup for server, client, or complete system

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --server     Setup server components only"
    echo "  --client     Setup client components only"
    echo "  --monitoring Setup enhanced monitoring features"
    echo "  --help       Show this help message"
    echo ""
    echo "If no options provided, performs complete system setup"
    echo ""
    echo "Examples:"
    echo "  $0              # Complete setup"
    echo "  $0 --server     # Server only"
    echo "  $0 --client     # Client only"
}

# Parse arguments
SETUP_TYPE="complete"

while [[ $# -gt 0 ]]; do
    case $1 in
        --server)
            SETUP_TYPE="server"
            shift
            ;;
        --client)
            SETUP_TYPE="client"
            shift
            ;;
        --monitoring)
            SETUP_TYPE="monitoring"
            shift
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_usage
            exit 1
            ;;
    esac
done

echo "======================================"
echo "🛡️  SENTINEL-AI Setup Script"
echo "======================================"
echo "Setup Type: $SETUP_TYPE"
echo ""

case $SETUP_TYPE in
    "complete")
        echo -e "${BLUE}🔧 Performing complete system setup...${NC}"
        echo ""

        # Check if running as root for complete setup
        if [[ $EUID -ne 0 ]]; then
            echo -e "${RED}❌ Complete setup requires root privileges${NC}"
            echo "Run: sudo $0"
            exit 1
        fi

        # Run system-level setup
        if [ -f "setup_complete_system.sh" ]; then
            echo -e "${BLUE}📦 Installing system dependencies...${NC}"
            bash setup_complete_system.sh
        fi

        # Setup server
        if [ -f "server/setup_server.sh" ]; then
            echo -e "${BLUE}🖥️  Setting up server...${NC}"
            cd server
            bash setup_server.sh
            cd ..
        fi

        # Setup client
        if [ -f "client/setup_v3.sh" ]; then
            echo -e "${BLUE}💻 Setting up client...${NC}"
            cd client
            bash setup_v3.sh
            cd ..
        fi

        # Setup monitoring
        if [ -f "setup_enhanced_monitoring.sh" ]; then
            echo -e "${BLUE}📊 Setting up enhanced monitoring...${NC}"
            bash setup_enhanced_monitoring.sh
        fi
        ;;

    "server")
        echo -e "${BLUE}🖥️  Setting up server components...${NC}"
        cd server
        if [ -f "setup_server.sh" ]; then
            bash setup_server.sh
        else
            echo -e "${RED}❌ Server setup script not found${NC}"
            exit 1
        fi
        cd ..
        ;;

    "client")
        echo -e "${BLUE}💻 Setting up client components...${NC}"
        cd client
        if [ -f "setup_v3.sh" ]; then
            bash setup_v3.sh
        else
            echo -e "${RED}❌ Client setup script not found${NC}"
            exit 1
        fi
        cd ..
        ;;

    "monitoring")
        echo -e "${BLUE}📊 Setting up enhanced monitoring...${NC}"
        if [ -f "setup_enhanced_monitoring.sh" ]; then
            bash setup_enhanced_monitoring.sh
        else
            echo -e "${RED}❌ Monitoring setup script not found${NC}"
            exit 1
        fi
        ;;
esac

echo ""
echo -e "${GREEN}✅ Setup completed successfully!${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
case $SETUP_TYPE in
    "complete")
        echo "  1. Start the system: ./START.sh"
        echo "  2. Access dashboard: http://localhost:8000"
        ;;
    "server")
        echo "  1. Start server: cd server && ./start.sh"
        echo "  2. Access dashboard: http://localhost:8000"
        ;;
    "client")
        echo "  1. Start client: cd client && python3 sentinel_client_v3.py"
        ;;
    "monitoring")
        echo "  1. Restart the system to enable monitoring features"
        ;;
esac