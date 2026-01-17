# SENTINEL-AI Client Setup and Usage Guide

## 🚀 Overview

SENTINEL-AI is a comprehensive threat detection and defense system that provides:

- **Real-time Threat Scanning**: Files, URLs, IPs, domains, and file hashes
- **Network-Wide Monitoring**: Track attacks across all client installations
- **Automated Defense**: Block malicious IPs and domains automatically
- **Comprehensive Reporting**: Generate reports for 24 hours, 7 days, or 30 days
- **Multi-Client Support**: Monitor multiple systems across your network

## 📋 Prerequisites

### Server Requirements
- Python 3.8+
- PostgreSQL or SQLite database
- API Keys for threat intelligence services:
  - VirusTotal
  - AbuseIPDB
  - Shodan
  - URLScan.io
  - Hybrid Analysis
  - Google Gemini (for AI-powered reports)

### Client Requirements
- Python 3.8+
- Network connectivity to the SENTINEL-AI server
- Administrator/root privileges (for defense actions)

## 🔧 Installation

### Step 1: Server Installation

```bash
# Clone the repository
cd server

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env

# Edit .env and add your API keys
nano .env

# Initialize the database
python -c "
from app.database import init_db
import asyncio
asyncio.run(init_db())
"

# Start the server
python run_server.py
```

### Step 2: Client Installation

On each system you want to monitor:

```bash
# Clone the repository
cd client

# Install dependencies
pip install -r requirements.txt

# Configure client
cp config.ini.example config.ini

# Edit config.ini with your server details
nano config.ini
```

Update `config.ini`:
```ini
[server]
url = https://your-sentinel-server.com
api_key = your_api_key_here

[client]
enable_auto_defense = true
scan_interval = 300
heartbeat_interval = 60
```

## 🎯 How It Works

### 1. Client Registration

When you first run the client, it automatically registers with the server:

```python
from sentinel_client import SentinelClient

client = SentinelClient(server_url="https://your-server.com")
await client.register()
```

The server tracks:
- Hostname and IP address
- Operating system details
- Network segment
- Installation date and version
- Last seen timestamp

### 2. Continuous Monitoring

The client continuously monitors your system and reports to the central server:

```python
# Start continuous monitoring
await client.start_monitoring()
```

This includes:
- File scans (downloads, suspicious files)
- Network connections (outgoing connections to suspicious IPs)
- URL access monitoring
- Process monitoring

### 3. Attack Detection

When a threat is detected:

1. **Local Analysis**: Client performs initial threat assessment
2. **Server Reporting**: Attack details sent to central server
3. **Threat Intelligence**: Server queries multiple threat databases
4. **Network Correlation**: Server checks if same threat affects other clients
5. **Automated Response**: Defense mechanisms automatically activated

### 4. Defense Mechanisms

SENTINEL-AI automatically:

- **Blocks Malicious IPs**: Adds firewall rules to block attacking IPs
- **Blocks Dangerous Domains**: Updates DNS/hosts file to block domains
- **Quarantines Files**: Moves suspicious files to quarantine
- **Alerts Administrators**: Sends notifications for critical threats
- **Updates All Clients**: Propagates blocks to all network clients

## 📊 Generating Reports

### Single Interval Report (24h, 7d, or 30d)

**Via API:**
```bash
curl -X GET "https://your-server.com/api/v1/advanced-reports/interval/24h?format=pdf" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -o security_report_24h.pdf
```

**Via Python:**
```python
import requests

response = requests.get(
    "https://your-server.com/api/v1/advanced-reports/interval/7d",
    params={"format": "json", "target_type": "ip"},
    headers={"Authorization": "Bearer YOUR_TOKEN"}
)

report = response.json()
print(f"Total scans: {report['statistics']['total_scans']}")
```

### Comprehensive Multi-Interval Report

Generate a report covering all time intervals at once:

**Via API:**
```bash
curl -X POST "https://your-server.com/api/v1/advanced-reports/generate-comprehensive" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "intervals": ["24h", "7d", "30d"],
    "include_files": true,
    "include_urls": true,
    "include_ips": true,
    "include_domains": true,
    "include_attacks": true,
    "include_defense_actions": true,
    "format": "pdf"
  }' \
  -o comprehensive_report.pdf
```

**Via Python:**
```python
import requests

response = requests.post(
    "https://your-server.com/api/v1/advanced-reports/generate-comprehensive",
    headers={"Authorization": "Bearer YOUR_TOKEN"},
    json={
        "intervals": ["24h", "7d", "30d"],
        "include_files": True,
        "include_urls": True,
        "include_ips": True,
        "include_domains": True,
        "include_attacks": True,
        "include_defense_actions": True,
        "client_id": "CLIENT_ABC123",  # Optional: filter by specific client
        "format": "pdf"
    }
)

with open("comprehensive_report.pdf", "wb") as f:
    f.write(response.content)
```

### Report Contents

Each report includes:

**Statistics Section:**
- Total scans performed
- Breakdown by type (files, URLs, IPs, domains, hashes)
- Threat counts (safe, suspicious, malicious)
- Attack events detected
- Defense actions taken

**Detailed Sections:**
- Top threats detected (sorted by severity)
- Attack timeline
- Source IPs and domains of attacks
- Defense actions log
- Affected systems list

**AI Analysis:** (if Gemini API enabled)
- Executive summary
- Trend analysis
- Recommendations
- Risk assessment

## 🛡️ Using Defense Features

### Manual Defense Actions

**Block an IP Address:**
```bash
curl -X POST "https://your-server.com/api/v1/network/defense/action" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "block_ip",
    "target": "192.168.1.100",
    "client_id": "CLIENT_ABC123",
    "details": {"reason": "Manual block - repeated attacks"}
  }'
```

**Block a Domain:**
```bash
curl -X POST "https://your-server.com/api/v1/network/defense/action" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "block_domain",
    "target": "malicious-site.com",
    "details": {"reason": "Known phishing domain"}
  }'
```

### Viewing Attack Events

**List Recent Attacks:**
```bash
curl -X GET "https://your-server.com/api/v1/network/attacks?hours=24&severity=high" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:**
```json
{
  "total": 5,
  "attacks": [
    {
      "event_id": "ATK_A1B2C3D4E5F6",
      "attack_type": "port_scan",
      "source_ip": "203.0.113.42",
      "severity": "high",
      "status": "blocked",
      "blocked": true,
      "detected_at": "2026-01-13T10:30:00Z"
    }
  ]
}
```

### Network-Wide Alerts

```bash
curl -X GET "https://your-server.com/api/v1/network/alerts?active_only=true" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 🔍 Scanning Targets

### Scan a File

**Upload and scan:**
```bash
curl -X POST "https://your-server.com/api/v1/scan/file" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@suspicious_file.exe" \
  -F "include_report=true" \
  -F "client_id=CLIENT_ABC123"
```

### Scan a URL

```python
import requests

response = requests.post(
    "https://your-server.com/api/v1/scan/url",
    headers={"Authorization": "Bearer YOUR_TOKEN"},
    json={
        "target": "https://suspicious-website.com",
        "include_report": True,
        "client_id": "CLIENT_ABC123"
    }
)

result = response.json()
print(f"Threat Level: {result['threat_level']}")
print(f"Confidence: {result['confidence']}")
```

### Scan an IP Address

```bash
curl -X POST "https://your-server.com/api/v1/scan/ip" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.100",
    "include_report": true,
    "client_id": "CLIENT_ABC123"
  }'
```

### Universal Scan (Auto-detect Type)

```bash
curl -X POST "https://your-server.com/api/v1/scan/scan" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "google.com",
    "include_report": false,
    "client_id": "CLIENT_ABC123"
  }'
```

## 📊 Dashboard and Monitoring

### View All Clients

```bash
curl -X GET "https://your-server.com/api/v1/network/clients" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Client Heartbeat (Keep-Alive)

Clients should send heartbeats every minute:

```python
import asyncio
import requests

async def send_heartbeat():
    while True:
        requests.post(
            f"{server_url}/api/v1/network/client/heartbeat",
            params={"client_id": client_id},
            headers={"Authorization": f"Bearer {token}"}
        )
        await asyncio.sleep(60)
```

## 🎛️ Configuration Options

### Client Configuration

`config.ini`:
```ini
[server]
url = https://sentinel-server.com
api_key = YOUR_API_KEY

[client]
# Enable automatic defense actions
enable_auto_defense = true

# Scan interval in seconds (300 = 5 minutes)
scan_interval = 300

# Heartbeat interval in seconds
heartbeat_interval = 60

# Auto-report attacks to server
auto_report_attacks = true

# Block high-severity threats automatically
auto_block_threats = true

[scanning]
# Monitor file downloads
monitor_downloads = true

# Monitor network connections
monitor_network = true

# Scan uploaded files
scan_uploads = true

# Maximum file size to scan (MB)
max_file_size = 100

[defense]
# Use iptables for IP blocking (Linux)
use_iptables = true

# Use Windows Firewall (Windows)
use_windows_firewall = true

# Update hosts file for domain blocking
use_hosts_file = true

# Quarantine directory
quarantine_dir = /var/quarantine
```

### Server Configuration

`server/.env`:
```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost/sentinelai

# API Keys
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
URLSCAN_API_KEY=your_key_here
HYBRID_ANALYSIS_API_KEY=your_key_here
GEMINI_API_KEY=your_key_here

# Security
SECRET_KEY=your_secret_key_here
JWT_SECRET=your_jwt_secret_here

# Server
DEBUG=false
HOST=0.0.0.0
PORT=8000

# Rate Limiting
MAX_REQUESTS_PER_MINUTE=60
```

## 🔐 Security Best Practices

1. **Use HTTPS**: Always use HTTPS for server communication
2. **API Key Rotation**: Rotate API keys regularly
3. **Access Control**: Implement role-based access control
4. **Network Segmentation**: Deploy server in secure network segment
5. **Regular Updates**: Keep all components updated
6. **Backup**: Regular database backups
7. **Monitoring**: Monitor server logs for anomalies
8. **Firewall**: Restrict server access to known client IPs

## 🚨 Troubleshooting

### Client Can't Connect to Server

1. Check network connectivity
2. Verify server URL in config.ini
3. Check firewall rules
4. Verify API key is valid

### Scans Not Appearing in Reports

1. Check database connection
2. Verify client_id is being sent
3. Check server logs for errors
4. Ensure database tables are created

### Defense Actions Not Working

1. Check client has admin/root privileges
2. Verify defense mechanisms are enabled in config
3. Check logs for error messages
4. Test firewall rules manually

## 📞 Support

For issues or questions:
- Check logs: `/var/log/sentinelai/`
- Review documentation: [docs/](docs/)
- GitHub Issues: [SENTINELAI Issues](https://github.com/raviranbir007-stack/SENTINELAI-main/issues)

## 📝 License

This project is licensed under the MIT License.

---

**SENTINEL-AI** - Advanced Threat Detection and Defense System
