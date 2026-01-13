# SENTINEL-AI Installation Checklist

## ✅ Pre-Installation

- [ ] Python 3.8+ installed
- [ ] pip package manager available
- [ ] Network connectivity between server and clients
- [ ] Firewall rules configured (port 8000 open)
- [ ] API keys obtained:
  - [ ] VirusTotal
  - [ ] AbuseIPDB  
  - [ ] Shodan
  - [ ] URLScan.io
  - [ ] Hybrid Analysis
  - [ ] Google Gemini (optional, for AI reports)

---

## 🖥️ Server Installation

### Step 1: Setup Server

- [ ] Navigate to server directory: `cd server`
- [ ] Install dependencies: `pip install -r requirements.txt`
- [ ] Install additional packages: `pip install aiosqlite reportlab`
- [ ] Copy environment file: `cp .env.example .env`
- [ ] Edit .env and add API keys

### Step 2: Initialize Database

- [ ] Run migration: `python migrate_database.py --with-test-data`
- [ ] Verify tables created: `python migrate_database.py --verify-only`
- [ ] Check database file exists: `ls sentinelai.db`

### Step 3: Start Server

- [ ] Start server: `python run_server.py`
- [ ] Verify server running: `curl http://localhost:8000/`
- [ ] Check API docs: Open `http://localhost:8000/docs` in browser
- [ ] Test basic endpoint: `curl http://localhost:8000/api/v1/scan/history`

---

## 💻 Client Installation (Repeat for each system)

### Step 1: Setup Client

- [ ] Navigate to client directory: `cd client`
- [ ] Install dependencies: `pip install -r requirements.txt`
- [ ] Install additional packages: `pip install psutil watchdog`
- [ ] Copy config file: `cp config.ini.example config.ini`
- [ ] Edit config.ini with server URL and API key

### Step 2: Configure Client

Edit `config.ini`:

```ini
[server]
url = http://YOUR_SERVER_IP:8000  # ← Change this
api_key = YOUR_API_KEY            # ← Change this

[client]
enable_auto_defense = true
scan_interval = 300
heartbeat_interval = 60
auto_block_threats = true

[defense]
use_iptables = true              # Linux only
use_windows_firewall = true       # Windows only
use_hosts_file = true
```

- [ ] Server URL updated
- [ ] API key added
- [ ] Defense settings configured for your OS

### Step 3: Run Client

- [ ] Start client: `python sentinel_client_enhanced.py`
- [ ] Verify registration: Check for "Registration successful" message
- [ ] Note client ID from output
- [ ] Verify heartbeat: Check logs for "Heartbeat sent successfully"
- [ ] Check client appears in server: `curl http://server:8000/api/v1/network/clients`

---

## 🔍 Post-Installation Verification

### Test Scanning

- [ ] Scan a safe URL:
  ```bash
  curl -X POST "http://localhost:8000/api/v1/scan/url" \
    -H "Content-Type: application/json" \
    -d '{"target": "https://google.com"}'
  ```

- [ ] Scan an IP:
  ```bash
  curl -X POST "http://localhost:8000/api/v1/scan/ip" \
    -H "Content-Type: application/json" \
    -d '{"target": "8.8.8.8"}'
  ```

- [ ] Verify scan stored: `sqlite3 server/sentinelai.db "SELECT * FROM scan_history;"`

### Test Reporting

- [ ] Generate 24h report (JSON):
  ```bash
  curl -X GET "http://localhost:8000/api/v1/advanced-reports/interval/24h?format=json"
  ```

- [ ] Generate comprehensive report (PDF):
  ```bash
  curl -X POST "http://localhost:8000/api/v1/advanced-reports/generate-comprehensive" \
    -H "Content-Type: application/json" \
    -d '{"intervals": ["24h"], "format": "pdf"}' \
    -o test_report.pdf
  ```

- [ ] Open PDF and verify it contains data

### Test Network Monitoring

- [ ] List clients:
  ```bash
  curl -X GET "http://localhost:8000/api/v1/network/clients"
  ```
  
- [ ] Verify your client appears in the list
- [ ] Check last_seen timestamp is recent

### Test Defense System

- [ ] Report a test attack:
  ```bash
  curl -X POST "http://localhost:8000/api/v1/network/attack/report" \
    -H "Content-Type: application/json" \
    -d '{
      "client_id": "YOUR_CLIENT_ID",
      "attack_type": "test_attack",
      "source_ip": "203.0.113.42",
      "severity": "low"
    }'
  ```

- [ ] List attacks:
  ```bash
  curl -X GET "http://localhost:8000/api/v1/network/attacks"
  ```

- [ ] Verify attack appears in list

---

## 🔐 Security Configuration

### Server Security

- [ ] Change default admin password (username: admin, default: admin123)
- [ ] Generate strong JWT secret key
- [ ] Configure HTTPS (use reverse proxy like nginx)
- [ ] Set up firewall rules (restrict access to known IPs)
- [ ] Enable rate limiting
- [ ] Set up log rotation
- [ ] Configure database backups

### Client Security

- [ ] Run client with appropriate privileges (sudo on Linux for iptables)
- [ ] Secure config.ini file permissions: `chmod 600 config.ini`
- [ ] Verify API key is not exposed in logs
- [ ] Set up client auto-start (systemd service or Windows service)
- [ ] Configure log rotation

---

## 📊 Optional Features

### Email Notifications

- [ ] Install email package: `pip install aiosmtplib`
- [ ] Configure SMTP settings in .env
- [ ] Test email notifications

### Database Backup

- [ ] Set up automated backups:
  ```bash
  # Add to crontab
  0 2 * * * cp /path/to/sentinelai.db /path/to/backups/sentinelai_$(date +\%Y\%m\%d).db
  ```

### Automated Reporting

- [ ] Schedule daily reports:
  ```bash
  # Add to crontab
  0 8 * * * curl -X GET "http://server:8000/api/v1/advanced-reports/interval/24h?format=pdf" -o /reports/daily_$(date +\%Y\%m\%d).pdf
  ```

- [ ] Schedule weekly reports
- [ ] Schedule monthly reports

### Dashboard Setup

- [ ] Open web dashboard: `http://localhost:8000/static/index.html`
- [ ] Configure dashboard refresh interval
- [ ] Add dashboard to bookmarks

---

## 🧪 Testing Checklist

### Functional Tests

- [ ] File scan works
- [ ] URL scan works
- [ ] IP scan works
- [ ] Domain scan works
- [ ] Hash scan works
- [ ] Reports generate (24h, 7d, 30d)
- [ ] Comprehensive reports work
- [ ] PDF reports download correctly
- [ ] JSON reports have correct structure

### Client Tests

- [ ] Client registers successfully
- [ ] Heartbeat works
- [ ] Network monitoring detects connections
- [ ] File monitoring works
- [ ] Auto-defense blocks IPs
- [ ] Auto-defense blocks domains

### Network Tests

- [ ] Multiple clients can register
- [ ] Clients appear in client list
- [ ] Attacks are detected across network
- [ ] Network alerts generate correctly
- [ ] Defense actions propagate to clients

---

## 📝 Documentation Review

- [ ] Read [CLIENT_SETUP_GUIDE.md](CLIENT_SETUP_GUIDE.md)
- [ ] Read [ENHANCEMENTS_SUMMARY.md](ENHANCEMENTS_SUMMARY.md)
- [ ] Read [QUICK_REFERENCE.md](QUICK_REFERENCE.md)
- [ ] Bookmark API documentation: `http://localhost:8000/docs`

---

## 🎯 Production Deployment

### Before Going Live

- [ ] All tests passing
- [ ] API keys configured and tested
- [ ] Database backed up
- [ ] HTTPS configured
- [ ] Firewall rules in place
- [ ] Admin password changed
- [ ] Log rotation configured
- [ ] Monitoring alerts set up
- [ ] Documentation distributed to team
- [ ] Training completed for administrators

### Go-Live Checklist

- [ ] Deploy server to production host
- [ ] Deploy clients to all systems
- [ ] Verify all clients register
- [ ] Generate test report
- [ ] Monitor logs for errors
- [ ] Test emergency procedures
- [ ] Notify team of deployment

---

## 🐛 Troubleshooting Resources

If you encounter issues:

1. **Check Logs**:
   - Server: `server/logs/` or console output
   - Client: `sentinel_client.log`

2. **Verify Database**:
   ```bash
   python server/migrate_database.py --verify-only
   ```

3. **Test Connectivity**:
   ```bash
   curl http://server:8000/
   ```

4. **Check API Keys**:
   - Verify they're in .env file
   - Test each service individually

5. **Review Documentation**:
   - [CLIENT_SETUP_GUIDE.md](CLIENT_SETUP_GUIDE.md)
   - [QUICK_REFERENCE.md](QUICK_REFERENCE.md)

---

## ✅ Installation Complete!

Once all items are checked:

🎉 **Congratulations!** Your SENTINEL-AI system is fully installed and operational!

### Next Steps:

1. **Monitor**: Watch the dashboard for threats
2. **Review Reports**: Generate daily/weekly reports
3. **Tune Settings**: Adjust sensitivity based on your environment
4. **Train Team**: Ensure everyone knows how to use the system
5. **Stay Updated**: Check for updates regularly

---

**Support**: Check logs and documentation for troubleshooting
**Documentation**: See CLIENT_SETUP_GUIDE.md for detailed usage
**Quick Help**: See QUICK_REFERENCE.md for common commands

---

**SENTINEL-AI v2.0** - Installation Complete! 🛡️
