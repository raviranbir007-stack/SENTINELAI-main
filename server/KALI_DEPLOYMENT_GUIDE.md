# SENTINEL-AI Kali Linux Deployment Guide

## Overview
This guide provides complete instructions for deploying SENTINEL-AI on Kali Linux with all threat detection features enabled.

## Prerequisites

### System Requirements
- Kali Linux 2024.1+ or Ubuntu 22.04+
- Python 3.9+
- 4GB RAM minimum (8GB recommended)
- 500MB free disk space
- Network connectivity for API services

### Required API Keys
You'll need the following to enable all threat detection features:

1. **VirusTotal API Key**
   - Sign up: https://www.virustotal.com/gui/home/upload
   - Get API key from account settings

2. **AbuseIPDB API Key**
   - Sign up: https://www.abuseipdb.com/
   - Available in account settings

3. **Shodan API Key**
   - Sign up: https://account.shodan.io/
   - Available in account settings

4. **URLScan API Key**
   - Sign up: https://urlscan.io/
   - Available in account settings

5. **Hybrid Analysis API Key** (optional)
   - Sign up: https://www.hybrid-analysis.com/
   - Get API key from settings

6. **Gemini API Key** (for AI-powered report generation)
   - Get from: https://ai.google.dev/
   - Set environment variable: `GEMINI_API_KEY`

## Installation Steps

### 1. Clone and Setup
```bash
# Navigate to project directory
cd /path/to/SENITELAI/server

# Install dependencies
pip install -r requirements.txt

# Ensure ReportLab is installed (for PDF generation)
pip install reportlab

# Ensure google-generativeai is installed (for Gemini integration)
pip install google-generativeai
```

### 2. Configure Environment Variables

Create `.env` file in the server directory:

```bash
# .env file
ENVIRONMENT=production
DEBUG=False
PROJECT_NAME=SENTINEL-AI
VERSION=1.0.0
API_V1_PREFIX=/api/v1

# Database (SQLite for development)
DATABASE_URL=sqlite:///./sentinel_ai.db

# API Keys (Required for threat detection)
VIRUSTOTAL_API_KEY=your_virustotal_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
SHODAN_API_KEY=your_shodan_key_here
URLSCAN_API_KEY=your_urlscan_key_here
HYBRID_ANALYSIS_API_KEY=your_hybrid_analysis_key_here
GEMINI_API_KEY=your_gemini_api_key_here

# Server Config
HOST=0.0.0.0
PORT=8000
```

### 3. Initialize Database

```bash
# The database will be created automatically on first run
# Or run initialization script if available
python -c "from app.database import init_db; import asyncio; asyncio.run(init_db())"
```

## Running on Kali Linux

### Method 1: Using run_server.py (Recommended)

```bash
# Start the server with Kali-optimized settings
python run_server.py

# Output will show:
# ============================================================
# SENTINEL-AI Server - Kali Linux Optimized Mode
# ============================================================
# Features Enabled:
#   ✓ Threat Detection with Multi-API Integration
#   ✓ Network Vulnerability Scanning (Shodan)
#   ✓ IP Reputation Analysis (AbuseIPDB)
#   ✓ File Hash Analysis (VirusTotal)
#   ✓ ...
# ============================================================
```

### Method 2: Using Production Mode

```bash
# Run in production mode
ENVIRONMENT=production python run_server.py
```

### Method 3: Using Gunicorn (Recommended for Production)

```bash
# Install Gunicorn
pip install gunicorn

# Run with Gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 --access-logfile - app.main:app
```

## Testing Threat Detection

### Test 1: IP Threat Detection
```bash
# Scan a suspicious IP
curl -X POST "http://localhost:8000/api/v1/threats/scan-ip" \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "192.168.1.50"}'
```

### Test 2: Get Threats with Time Range
```bash
# Get threats from last 24 hours
curl "http://localhost:8000/api/v1/threats?time_range=24h"

# Get threats from last 7 days
curl "http://localhost:8000/api/v1/threats?time_range=7d"

# Get threats from last 30 days
curl "http://localhost:8000/api/v1/threats?time_range=30d"
```

### Test 3: Get Threat Details
```bash
curl "http://localhost:8000/api/v1/threats/THR001"
```

### Test 4: Generate PDF Report
```bash
# Generate report for a threat
curl -X POST "http://localhost:8000/api/v1/reports/generate?threat_id=THR001"

# This returns:
# {
#   "report_id": "RPT001",
#   "threat_id": "THR001",
#   "status": "generated",
#   "download_url": "/api/v1/reports/download/RPT001"
# }
```

### Test 5: Download Report PDF
```bash
curl "http://localhost:8000/api/v1/reports/download/RPT001" \
  -o "Threat_Report_RPT001.pdf"

# File will be saved as PDF with threat analysis, API findings, and recommendations
```

### Test 6: Dashboard Statistics
```bash
# Get dashboard summary
curl "http://localhost:8000/api/v1/dashboard/summary?time_range=24h"

# Get dashboard threats
curl "http://localhost:8000/api/v1/dashboard/threats?time_range=7d"

# Get dashboard stats
curl "http://localhost:8000/api/v1/dashboard/stats?time_range=30d"
```

## Attack Simulation Scenario (Kali → Victim)

### Setup
1. **Kali Linux (Attacker)**
   - Run any network tool (nmap, metasploit, etc.)
   - Target the victim's IP

2. **Victim Kali Linux (Defender)**
   - SENTINEL-AI running and listening on 0.0.0.0:8000
   - Network scanner active

### Expected Results
1. **Threat Detection**: Attack is detected and recorded
2. **Threat Display**: Shows in `/api/v1/threats` endpoint with:
   - Source: Attacker's IP
   - Type: Network scan, port scan, etc.
   - Severity: Based on attack intensity
   - Location: If available from IP geolocation

3. **Report Generation**: User can generate PDF report showing:
   - Attack details
   - Shodan findings about attacker's IP
   - AbuseIPDB reputation
   - AI analysis recommendations
   - Mitigation steps

## API Response Examples

### Threats List with Time Range
```json
{
  "time_range": "24h",
  "start_date": "2024-12-25T10:30:00",
  "end_date": "2024-12-26T10:30:00",
  "total_threats": 6,
  "threats": [
    {
      "threat_id": "THR001",
      "name": "Suspicious Process Activity",
      "type": "Process Injection",
      "severity": "critical",
      "source": "192.168.1.50",
      "location": "Bangalore, India",
      "timestamp": "2024-12-26T09:30:00",
      "status": "active",
      "detected_by": "Network Scanner"
    }
  ]
}
```

### Threat Details
```json
{
  "threat_id": "THR001",
  "name": "Suspicious Process Activity",
  "type": "Process Injection",
  "severity": "critical",
  "source": "192.168.1.50",
  "location": "Bangalore, India",
  "api_sources": ["Shodan", "AbuseIPDB"],
  "confidence_score": 95,
  "details": {
    "process_name": "Process_monitor.exe",
    "target_ports": [80, 443, 8080],
    "connection_attempts": 45
  }
}
```

### Generated Report Metadata
```json
{
  "report_id": "RPT001",
  "threat_id": "THR001",
  "status": "generated",
  "file_size": 245760,
  "generated_at": "2024-12-26T10:35:00",
  "download_url": "/api/v1/reports/download/RPT001"
}
```

## Troubleshooting

### Issue: API keys not working
**Solution**: 
- Verify `.env` file exists in server directory
- Check API key validity on provider websites
- Ensure environment variables are loaded: `set -a; source .env; set +a`

### Issue: Database connection error
**Solution**:
- Delete `sentinel_ai.db` to reset database
- Run: `python -c "from app.database import init_db; import asyncio; asyncio.run(init_db())"`

### Issue: Port 8000 already in use
**Solution**:
```bash
# Find process using port 8000
lsof -i :8000

# Kill the process
kill -9 <PID>

# Or use different port
python run_server.py --port 8001
```

### Issue: Reports not generating
**Solution**:
- Ensure reportlab is installed: `pip install reportlab`
- Check Gemini API key is valid
- Check server logs for detailed error messages

## Performance Optimization

### For High-Traffic Scenarios

1. **Use Gunicorn with multiple workers**:
```bash
gunicorn -w 8 -b 0.0.0.0:8000 app.main:app
```

2. **Enable caching**:
```bash
# Add Redis for caching (optional)
pip install redis
```

3. **Use PostgreSQL instead of SQLite**:
```bash
# Install PostgreSQL adapter
pip install psycopg2-binary

# Update DATABASE_URL in .env
DATABASE_URL=postgresql://user:password@localhost/sentinel_ai
```

## Security Best Practices

1. **Run behind reverse proxy** (Nginx/Apache):
   - Adds SSL/TLS encryption
   - Load balancing
   - Request filtering

2. **Use firewall rules**:
```bash
# Allow only trusted networks
ufw allow from 192.168.1.0/24 to any port 8000
```

3. **Secure API keys**:
   - Never commit `.env` to git
   - Use environment-specific secrets management
   - Rotate keys regularly

4. **Enable authentication**:
   - Implement JWT tokens
   - Use the `/api/v1/auth` endpoints

## Monitoring and Logging

### View Server Logs
```bash
# Real-time logs
tail -f ./logs/sentinel_ai.log

# Search for errors
grep ERROR ./logs/sentinel_ai.log

# View API activity
tail -f ./logs/api_activity.log
```

### Health Check
```bash
# Check if server is running
curl http://localhost:8000/api/v1/health

# Expected response:
# {"status": "healthy", "service": "SENTINEL-AI API"}
```

## Systemd Service (Optional)

Create `/etc/systemd/system/sentinel-ai.service`:

```ini
[Unit]
Description=SENTINEL-AI Threat Detection System
After=network.target

[Service]
Type=simple
User=kali
WorkingDirectory=/path/to/SENITELAI/server
Environment="PATH=/usr/bin:/usr/local/bin"
ExecStart=/usr/bin/python3 run_server.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable sentinel-ai
sudo systemctl start sentinel-ai
sudo systemctl status sentinel-ai
```

## Next Steps

1. **Configure Frontend**: Implement the dashboard UI components as per FRONTEND_IMPLEMENTATION_GUIDE.md
2. **Add Authentication**: Implement user login and API token management
3. **Database Persistence**: Switch from mock data to real database storage
4. **Real-time Alerts**: Implement WebSocket connections for live threat alerts
5. **Integration**: Connect with actual threat detection scanners and engines

## Support and Resources

- API Documentation: http://localhost:8000/api/docs
- OpenAPI Schema: http://localhost:8000/api/openapi.json
- Project Repository: See README.md
- Issue Tracker: Check GitHub issues

---

**Last Updated**: December 26, 2024
**Version**: 1.0.0
