#!/bin/bash
# Quick restart script for SentinelAI

echo "🔄 Restarting SentinelAI..."

# Kill existing servers
sudo pkill -f run_server.py
sudo pkill -f "python.*run_server"
sleep 2

# Clear port if still occupied
PORT_PID=$(sudo lsof -ti:8000)
if [ ! -z "$PORT_PID" ]; then
    echo "🔓 Clearing port 8000..."
    sudo kill -9 $PORT_PID
    sleep 1
fi

# Start fresh
echo "🚀 Starting SentinelAI..."
cd ~/Documents/SENTINELAI-main/server
sudo python run_server.py
