# 🚀 SENTINEL-AI Quick Deployment Guide
## Get Your Clients Protected in 5 Minutes!

---

## For YOU (Server Setup - One Time)

### 1. Setup Server (2 minutes)

```bash
cd server
./setup_server.sh
```

**Then:**
1. Edit `.env` - Add your API keys
2. Start server: `./start_server.sh`
3. Get admin token from `SETUP_SUMMARY.txt`

**Server URL:** `http://YOUR_IP:8000`

---

## For YOUR CLIENTS (Each System)

### Option A: One-Line Install (Easiest)

Give your client this command:

```bash
curl -O http://YOUR_SERVER_IP:8000/client/setup_client.sh && \
chmod +x setup_client.sh && \
./setup_client.sh http://YOUR_SERVER_IP:8000 YOUR_API_KEY
```

### Option B: Manual Install

**1. Copy files to client:**
```bash
scp -r client/ user@client-system:~/sentinelai/
```

**2. Run setup on client system:**
```bash
cd ~/sentinelai
./setup_client.sh http://YOUR_SERVER_IP:8000 YOUR_API_KEY
```

**3. Start protection:**
```bash
./start_client.sh
```

**Done!** ✅ Client is now protected.

---

## Verify It's Working

### Check All Clients

```bash
curl http://YOUR_SERVER:8000/api/v1/network/clients
```

Should show all connected clients with their last seen time.

### Generate Report

```bash
# 24-hour report for all clients
curl -X GET "http://YOUR_SERVER:8000/api/v1/advanced-reports/interval/24h?format=pdf" -o daily_report.pdf

# Comprehensive report (24h + 7d + 30d)
curl -X POST "http://YOUR_SERVER:8000/api/v1/advanced-reports/generate-comprehensive" \
  -H "Content-Type: application/json" \
  -d '{"intervals": ["24h","7d","30d"], "format": "pdf"}' -o full_report.pdf
```

### View Dashboard

Open in browser: `http://YOUR_SERVER:8000/static/index.html`

---

## What Each Client Gets

✅ **Automatic Protection:**
- Scans files, URLs, IPs automatically
- Blocks malicious IPs/domains
- Reports attacks to your server

✅ **Continuous Monitoring:**
- Network connections
- File downloads
- Suspicious activity

✅ **Auto-Defense:**
- High-severity threats blocked instantly
- All actions logged
- Network-wide coordination

---

## Client Requirements

- Python 3.8+
- Internet access to your server
- Admin/sudo privileges (for defense)

---

## Distribution Methods

### Method 1: Email Package

**Create package:**
```bash
cd client
tar -czf sentinelai-client.tar.gz *
```

**Email to client with instructions:**
```
1. Extract: tar -xzf sentinelai-client.tar.gz
2. Run: cd sentinelai-client && ./setup_client.sh SERVER_URL API_KEY
3. Done!
```

### Method 2: USB Drive

Copy `client/` folder to USB → Give to client → Run setup

### Method 3: Remote Install

```bash
# SSH to client system
ssh user@client-system

# Download and install
curl -O http://YOUR_SERVER/client/setup_client.sh
chmod +x setup_client.sh
./setup_client.sh http://YOUR_SERVER:8000 API_KEY
```

---

## Enterprise: Deploy to 100+ Systems

### Using Ansible

```yaml
# deploy.yml
- hosts: all
  tasks:
    - copy: src=client/ dest=/opt/sentinelai/
    - shell: cd /opt/sentinelai && ./setup_client.sh http://SERVER:8000 {{ api_key }}
```

```bash
ansible-playbook -i inventory deploy.yml
```

### Using Group Policy (Windows)

Create MSI installer or startup script with setup command.

---

## Monitoring

### Real-Time Status

```bash
# List all clients
curl http://SERVER:8000/api/v1/network/clients

# Recent attacks
curl http://SERVER:8000/api/v1/network/attacks?hours=24

# Active alerts
curl http://SERVER:8000/api/v1/network/alerts
```

### Daily Reports

Add to cron:
```bash
0 8 * * * curl http://SERVER:8000/api/v1/advanced-reports/interval/24h?format=pdf -o /reports/daily_$(date +\%Y\%m\%d).pdf
```

---

## Troubleshooting

### Client Won't Connect

```bash
# Test server reachability
curl http://YOUR_SERVER:8000/

# Check firewall
sudo ufw allow 8000/tcp

# Check client logs
tail -f sentinel_client.log
```

### Client Not in Server List

```bash
# Re-register
cd client
python3 -c "
from sentinel_client_enhanced import SentinelClient
import asyncio
asyncio.run(SentinelClient().register())
"
```

### Defense Not Working

```bash
# Start with sudo (Linux)
sudo ./start_client.sh

# Or configure sudoers
echo "$USER ALL=(ALL) NOPASSWD: /sbin/iptables" | sudo tee -a /etc/sudoers
```

---

## Support for Clients

**Give your clients:**

1. **Server URL:** `http://YOUR_IP:8000`
2. **API Key:** `[from SETUP_SUMMARY.txt]`
3. **Installation Command:** `./setup_client.sh SERVER_URL API_KEY`
4. **Support Email/Phone:** Your contact

**Files to Share:**
- `setup_client.sh` (installer)
- `CLIENT_DEPLOYMENT_GUIDE.md` (full guide)
- `QUICK_REFERENCE.md` (commands)

---

## Summary

### Server (You):
```bash
cd server
./setup_server.sh          # One time
./start_server.sh          # Start server
```

### Client (Your Clients):
```bash
./setup_client.sh SERVER_URL API_KEY    # Install
./start_client.sh                        # Start protection
```

### Monitor:
- Dashboard: `http://SERVER:8000/static/index.html`
- API: `http://SERVER:8000/docs`
- Reports: Use curl commands above

---

## 🎉 That's It!

You're now protecting all your clients' systems with SENTINEL-AI!

**Questions?** See:
- Full Guide: `CLIENT_DEPLOYMENT_GUIDE.md`
- Quick Reference: `QUICK_REFERENCE.md`
- Setup Guide: `CLIENT_SETUP_GUIDE.md`

---

**SENTINEL-AI** - Simple Setup, Powerful Protection 🛡️
