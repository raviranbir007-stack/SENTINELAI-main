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