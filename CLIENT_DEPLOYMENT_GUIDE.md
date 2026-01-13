# SENTINEL-AI Client Deployment Guide
## Quick Setup for Your Clients

This guide shows how to quickly deploy SENTINEL-AI to your clients' systems.

---

## 🚀 For System Administrators (You)

### 1. Server Setup (One Time - Your Side)

**Run the automated setup:**
```bash
cd server
chmod +x setup_server.sh
./setup_server.sh
```

This will:
- ✅ Install all dependencies
- ✅ Create database
- ✅ Generate admin credentials
- ✅ Create configuration files
- ✅ Set up system service (optional)

**After setup:**
1. Edit `.env` file and add your API keys
2. Start server: `./start_server.sh`
3. Get your admin token from `SETUP_SUMMARY.txt`

**Server will be running at:** `http://YOUR_IP:8000`

---

## 👥 For Your Clients (Their Systems)

### Option 1: Automated Setup (Recommended)

**Give your client this simple command:**

```bash
# Download and run client setup
curl -O http://YOUR_SERVER_IP:8000/setup_client.sh
chmod +x setup_client.sh
./setup_client.sh
```

**Or provide them with:**
1. The `setup_client.sh` script
2. Your server URL
3. An API key

**Run setup:**
```bash
chmod +x setup_client.sh
./setup_client.sh http://YOUR_SERVER_IP:8000 YOUR_API_KEY
```

That's it! The client is now protected.

---

### Option 2: Manual Setup (Step by Step)

If your client prefers manual setup:

**1. Install Python 3.8+**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip python3-venv

# CentOS/RHEL
sudo yum install python3 python3-pip

# macOS
brew install python3

# Windows
# Download from python.org
```

**2. Copy client files**
```bash
# Copy the entire client directory to the client's system
scp -r client/ user@client-system:~/sentinelai-client/
```

**3. Run setup on client system**
```bash
cd ~/sentinelai-client
chmod +x setup_client.sh
./setup_client.sh http://YOUR_SERVER_IP:8000 YOUR_API_KEY
```

**4. Start monitoring**
```bash
./start_client.sh
```

---

## 📦 Package Distribution Options

### Option A: Create Installation Package

**Create a client package to distribute:**

```bash
# On your machine
cd client
tar -czf sentinelai-client.tar.gz *.py *.sh requirements.txt

# Send to client
scp sentinelai-client.tar.gz client@system:/tmp/

# Client extracts and runs
cd /opt
sudo tar -xzf /tmp/sentinelai-client.tar.gz
cd sentinelai-client
sudo ./setup_client.sh http://YOUR_SERVER:8000 API_KEY
```

### Option B: Docker Deployment

**Create Docker image (coming soon):**
```bash
docker pull sentinelai/client:latest
docker run -d \
  -e SERVER_URL=http://YOUR_SERVER:8000 \
  -e API_KEY=YOUR_KEY \
  --name sentinelai-client \
  sentinelai/client:latest
```

---

## 🔑 Client API Key Management

### Generate Client API Keys

**From server:**
```bash
# Generate a new API key for a client
python3 << EOF
import sys
sys.path.insert(0, 'server')
from app.auth import create_access_token
token = create_access_token({'sub': 'client_name', 'admin': False})
print(f"API Key: {token}")
EOF
```

**Or via API:**
```bash
curl -X POST "http://YOUR_SERVER:8000/api/v1/auth/token" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

---

## 📋 Client Installation Checklist

### Pre-Installation (Client System Requirements)

- [ ] Python 3.8 or higher installed
- [ ] Internet access to server
- [ ] Admin/sudo privileges (for firewall rules)
- [ ] Port access to server (default: 8000)

### Installation Steps

- [ ] Copy client files to system
- [ ] Run `setup_client.sh` with server URL and API key
- [ ] Verify registration successful
- [ ] Start client: `./start_client.sh`
- [ ] Check logs: `tail -f sentinel_client.log`
- [ ] Verify in server: `curl http://SERVER:8000/api/v1/network/clients`

### Post-Installation

- [ ] Client appears in server dashboard
- [ ] Heartbeat is working (check "last seen")
- [ ] Test scan: Client scans a test file/URL
- [ ] Defense is working: Check blocked IPs list
- [ ] Set up auto-start (systemd service)

---

## 🖥️ Platform-Specific Instructions

### Linux (Ubuntu/Debian)

```bash
# Install dependencies
sudo apt update
sudo apt install python3 python3-pip python3-venv iptables

# Setup client
./setup_client.sh http://SERVER:8000 API_KEY

# Start as service
sudo systemctl start sentinelai-client
sudo systemctl enable sentinelai-client
```

### Linux (CentOS/RHEL)

```bash
# Install dependencies
sudo yum install python3 python3-pip iptables

# Setup client
./setup_client.sh http://SERVER:8000 API_KEY

# Start as service
sudo systemctl start sentinelai-client
sudo systemctl enable sentinelai-client
```

### macOS

```bash
# Install dependencies
brew install python3

# Setup client
./setup_client.sh http://SERVER:8000 API_KEY

# Start client
./start_client.sh

# Auto-start on login (create LaunchAgent)
# See CLIENT_SETUP_GUIDE.md for details
```

### Windows

```powershell
# Install Python 3.8+ from python.org

# Setup client
python setup_client.py http://SERVER:8000 API_KEY

# Start client
python sentinel_client_enhanced.py

# Or create Windows Service
# See CLIENT_SETUP_GUIDE.md for details
```

---

## 📊 Monitoring Your Clients

### Check All Connected Clients

```bash
curl http://YOUR_SERVER:8000/api/v1/network/clients
```

**Response:**
```json
{
  "total": 5,
  "clients": [
    {
      "client_id": "CLIENT_ABC123",
      "hostname": "workstation-01",
      "ip_address": "192.168.1.100",
      "os_type": "Linux",
      "last_seen": "2026-01-13T10:30:00Z",
      "protection_enabled": true
    }
  ]
}
```

### Generate Client Report

```bash
# Get report for specific client
curl -X POST "http://YOUR_SERVER:8000/api/v1/advanced-reports/generate-comprehensive" \
  -H "Content-Type: application/json" \
  -d '{
    "intervals": ["24h", "7d"],
    "client_id": "CLIENT_ABC123",
    "format": "pdf"
  }' -o client_report.pdf
```

---

## 🛡️ Defense Configuration

### Configure Auto-Defense

Edit `config.ini` on client:

```ini
[client]
enable_auto_defense = true          # Enable automatic defense
auto_block_threats = true           # Block high-severity threats automatically

[defense]
use_iptables = true                 # Linux: Use iptables for IP blocking
use_windows_firewall = false        # Windows: Use Windows Firewall
use_hosts_file = true               # Block domains via hosts file
```

### Test Defense System

```bash
# Manually block an IP (test)
curl -X POST "http://SERVER:8000/api/v1/network/defense/action" \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "block_ip",
    "target": "203.0.113.42",
    "client_id": "CLIENT_ABC123"
  }'

# Verify on client
sudo iptables -L | grep 203.0.113.42
```

---

## 📱 Client Dashboard Access

Give your clients access to view their system status:

**Dashboard URL:**
```
http://YOUR_SERVER:8000/static/index.html
```

They can:
- View their scan history
- See detected threats
- Check blocked IPs/domains
- Generate reports

---

## 🔧 Troubleshooting for Clients

### Client Can't Connect to Server

**Check network connectivity:**
```bash
ping YOUR_SERVER_IP
curl http://YOUR_SERVER_IP:8000/
```

**Check firewall:**
```bash
# Client side
telnet YOUR_SERVER_IP 8000

# Server side
sudo ufw allow 8000/tcp
```

### Client Not Showing in Server

**Check registration:**
```bash
# On client
cat .client_id

# If empty, re-register
python3 << EOF
import asyncio
from sentinel_client_enhanced import SentinelClient
asyncio.run(SentinelClient().register())
EOF
```

### Defense Actions Not Working

**Check permissions:**
```bash
# Linux - need sudo for iptables
sudo ./start_client.sh

# Or add user to sudoers for iptables
sudo visudo
# Add: username ALL=(ALL) NOPASSWD: /sbin/iptables
```

---

## 📞 Support for Your Clients

**Provide your clients with:**

1. **Quick Start Card:**
   - Server URL
   - API Key
   - Installation command
   - Support contact

2. **Log Location:**
   - `sentinel_client.log`

3. **Commands to Share:**
   ```bash
   # Check status
   tail -f sentinel_client.log
   
   # Restart client
   ./start_client.sh
   
   # Check connection
   curl http://YOUR_SERVER:8000/api/v1/network/clients
   ```

4. **Support Ticket Template:**
   ```
   System: [OS and version]
   Client ID: [from .client_id file]
   Issue: [description]
   Logs: [paste last 20 lines of sentinel_client.log]
   ```

---

## 🎯 Enterprise Deployment

### Deploy to Multiple Clients at Once

**Using Ansible (example):**

```yaml
# ansible-playbook deploy-sentinelai.yml

- name: Deploy SENTINEL-AI Client
  hosts: all_clients
  vars:
    server_url: "http://YOUR_SERVER:8000"
    api_key: "YOUR_API_KEY"
  tasks:
    - name: Copy client files
      copy:
        src: client/
        dest: /opt/sentinelai-client/
    
    - name: Run setup script
      shell: |
        cd /opt/sentinelai-client
        ./setup_client.sh {{ server_url }} {{ api_key }}
    
    - name: Start service
      systemd:
        name: sentinelai-client
        state: started
        enabled: yes
```

### Using Configuration Management

**Puppet, Chef, Salt:** Similar deployment patterns available.

---

## ✅ Success Checklist

After deploying to a client:

- [ ] Client shows in server's client list
- [ ] "Last seen" timestamp updates every ~60 seconds
- [ ] Client can perform scans
- [ ] Threats are detected and reported
- [ ] Defense actions work (blocked IPs/domains)
- [ ] Reports include client data
- [ ] Client logs show no errors
- [ ] Auto-start configured (if desired)

---

## 🎉 You're Ready!

Your clients are now protected by SENTINEL-AI!

**Next steps:**
1. Monitor dashboard for all clients
2. Generate regular reports
3. Review alerts and attacks
4. Update clients as needed

**For questions:** See CLIENT_SETUP_GUIDE.md or QUICK_REFERENCE.md

---

**SENTINEL-AI** - Protecting Your Clients' Systems 24/7 🛡️
