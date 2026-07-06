#!/bin/bash
# SENTINEL-AI Simple Server Launcher
# This script starts the FastAPI server properly

cd "$(dirname "$0")"

# Activate virtual environment
source .venv/bin/activate

# Snapshot credentials before startup so .env can be restored if files are lost.
./tools/backup_env.sh

# Set Python path
export PYTHONPATH="$PWD/server:$PYTHONPATH"
## Start client in background so local host acts as both admin/server and a client
echo "⚙️  Launching local client in background (client logs: client/sentinel_client_v3.log)"
export SENTINEL_FORCE_CLIENT_MODE=1
nohup python3 client/sentinel_client_v3.py >> client/sentinel_client_v3.log 2>&1 &
CLIENT_PID=$!
echo "Client started (PID: $CLIENT_PID)"

# Start server
echo "🚀 Starting SENTINEL-AI Server..."
python -c "
import sys
sys.path.insert(0, 'server')
from server.app.main import app
import uvicorn
print('SENTINEL-AI server starting on http://localhost:8000')
uvicorn.run(app, host='0.0.0.0', port=8000, log_level='info')
"