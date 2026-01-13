# SENTINEL-AI Quick Reference Guide

## 🚀 Getting Started (5 Minutes)

### 1. Initialize Database
```bash
cd server
python migrate_database.py --with-test-data
```

### 2. Start Server
```bash
python run_server.py
```

### 3. Run Client (on each system you want to protect)
```bash
cd client
python sentinel_client_enhanced.py
```

---

## 📊 Generate Reports

### Get 24-Hour Report (PDF)
```bash
curl -X GET "http://localhost:8000/api/v1/advanced-reports/interval/24h?format=pdf" \
  -o report_24h.pdf
```

### Get 7-Day Report (JSON)
```bash
curl -X GET "http://localhost:8000/api/v1/advanced-reports/interval/7d?format=json"
```

### Get 30-Day Report (PDF)
```bash
curl -X GET "http://localhost:8000/api/v1/advanced-reports/interval/30d?format=pdf" \
  -o report_30d.pdf
```

### Generate Comprehensive Report (All Intervals)
```bash
curl -X POST "http://localhost:8000/api/v1/advanced-reports/generate-comprehensive" \
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

### Filter Report by Client
```bash
curl -X POST "http://localhost:8000/api/v1/advanced-reports/generate-comprehensive" \
  -H "Content-Type: application/json" \
  -d '{
    "intervals": ["24h"],
    "client_id": "CLIENT_ABC123",
    "format": "pdf"
  }' \
  -o client_report.pdf
```

---

## 🛡️ Network Monitoring

### List All Clients
```bash
curl -X GET "http://localhost:8000/api/v1/network/clients"
```

### List Active Attacks
```bash
curl -X GET "http://localhost:8000/api/v1/network/attacks?hours=24"
```

### List High-Severity Attacks
```bash
curl -X GET "http://localhost:8000/api/v1/network/attacks?hours=24&severity=high"
```

### List Network Alerts
```bash
curl -X GET "http://localhost:8000/api/v1/network/alerts?active_only=true"
```

---

## 🔍 Scanning

### Scan a File
```bash
curl -X POST "http://localhost:8000/api/v1/scan/file" \
  -F "file=@suspicious.exe" \
  -F "include_report=true" \
  -F "client_id=CLIENT_ABC123"
```

### Scan a URL
```bash
curl -X POST "http://localhost:8000/api/v1/scan/url" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://suspicious-site.com",
    "include_report": false,
    "client_id": "CLIENT_ABC123"
  }'
```

### Scan an IP
```bash
curl -X POST "http://localhost:8000/api/v1/scan/ip" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "203.0.113.42",
    "client_id": "CLIENT_ABC123"
  }'
```

### Scan a Domain
```bash
curl -X POST "http://localhost:8000/api/v1/scan/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "malicious-domain.com",
    "client_id": "CLIENT_ABC123"
  }'
```

---

## 🛡️ Defense Actions

### Block an IP Address
```bash
curl -X POST "http://localhost:8000/api/v1/network/defense/action" \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "block_ip",
    "target": "203.0.113.42",
    "client_id": "CLIENT_ABC123"
  }'
```

### Block a Domain
```bash
curl -X POST "http://localhost:8000/api/v1/network/defense/action" \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "block_domain",
    "target": "malicious-site.com"
  }'
```

---

## 📈 Python Client Examples

### Basic Client Usage
```python
from sentinel_client_enhanced import SentinelClient
import asyncio

async def main():
    client = SentinelClient()
    
    # Register with server
    await client.register()
    
    # Scan a file
    result = await client.scan_file(Path("suspicious.exe"))
    print(f"Threat Level: {result.get('threat_level')}")
    
    # Scan a URL
    result = await client.scan_url("https://suspicious-site.com")
    
    # Scan an IP
    result = await client.scan_ip("203.0.113.42")
    
    # Report an attack
    await client.report_attack(
        attack_type="port_scan",
        source_ip="203.0.113.42",
        severity="high"
    )
    
    # Start continuous monitoring
    await client.start_monitoring()

asyncio.run(main())
```

### Block Threats Manually
```python
# Block an IP
await client.block_ip("203.0.113.42")

# Block a domain
await client.block_domain("malicious-site.com")
```

---

## 🔧 Configuration

### Server Environment Variables (.env)
```bash
DATABASE_URL=sqlite+aiosqlite:///./sentinelai.db
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
SHODAN_API_KEY=your_key
URLSCAN_API_KEY=your_key
GEMINI_API_KEY=your_key
```

### Client Configuration (config.ini)
```ini
[server]
url = http://your-server:8000
api_key = your_api_key

[client]
enable_auto_defense = true
scan_interval = 300
heartbeat_interval = 60
auto_block_threats = true

[defense]
use_iptables = true
use_windows_firewall = true
use_hosts_file = true
```

---

## 📊 Report Contents

Each report includes:

**Statistics**:
- Total scans by type (files, URLs, IPs, domains, hashes)
- Threat counts (safe, suspicious, malicious)
- Attack events
- Defense actions taken

**Detailed Data**:
- Top threats by severity
- Attack timeline
- Source IPs and domains
- Defense actions log
- Affected systems

**Time Intervals**:
- 24 hours
- 7 days
- 30 days

---

## 🎯 Common Use Cases

### Daily Security Report
```bash
# Generate daily report every morning
0 8 * * * curl -X GET "http://server:8000/api/v1/advanced-reports/interval/24h?format=pdf" -o /reports/daily_$(date +\%Y\%m\%d).pdf
```

### Weekly Security Review
```bash
# Generate weekly report every Monday
0 8 * * 1 curl -X GET "http://server:8000/api/v1/advanced-reports/interval/7d?format=pdf" -o /reports/weekly_$(date +\%Y\%m\%d).pdf
```

### Monthly Compliance Report
```bash
# Generate monthly report on 1st of each month
0 8 1 * * curl -X GET "http://server:8000/api/v1/advanced-reports/interval/30d?format=pdf" -o /reports/monthly_$(date +\%Y\%m).pdf
```

### Monitor Specific Client
```bash
# Get all activity for a specific client
curl -X POST "http://server:8000/api/v1/advanced-reports/generate-comprehensive" \
  -H "Content-Type: application/json" \
  -d '{"intervals": ["7d"], "client_id": "CLIENT_ABC123", "format": "json"}'
```

---

## 🐛 Troubleshooting

### Database Not Initialized
```bash
cd server
python migrate_database.py
```

### Client Can't Connect
1. Check server is running: `curl http://localhost:8000/`
2. Check firewall: `sudo ufw allow 8000`
3. Verify config.ini has correct server URL

### Reports Show No Data
1. Check database: `sqlite3 sentinelai.db "SELECT COUNT(*) FROM scan_history;"`
2. Ensure scans include client_id
3. Verify time intervals are correct

### Defense Actions Not Working
1. Check client has admin privileges
2. Verify firewall/iptables permissions
3. Check logs: `tail -f sentinel_client.log`

---

## 📞 Quick Help

**Database**: `server/migrate_database.py --verify-only`
**Server**: `server/run_server.py`
**Client**: `client/sentinel_client_enhanced.py`
**Logs**: `sentinel_client.log` or `server/logs/`
**API Docs**: `http://localhost:8000/docs`

---

## 🎉 Features at a Glance

✅ Multi-interval reporting (24h/7d/30d)
✅ Generate all reports at once
✅ Network-wide monitoring
✅ Automated defense (IP/domain blocking)
✅ Client tracking and registration
✅ Attack detection and reporting
✅ Structured scan history
✅ PDF and JSON output
✅ AI-powered analysis
✅ Real-time threat blocking

---

**SENTINEL-AI v2.0** - Your Complete Security Solution
