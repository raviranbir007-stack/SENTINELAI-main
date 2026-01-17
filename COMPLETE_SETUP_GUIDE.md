# 🚀 SentinelAI Complete Setup & Usage Guide

## 📋 System Capabilities

Your SentinelAI system now provides **enterprise-grade real-time protection** with:

### 🛡️ Real-Time Protection
- ✅ Network connection monitoring
- ✅ File system monitoring  
- ✅ Process monitoring
- ✅ URL/Domain checking
- ✅ IP reputation analysis

### ⚠️  5-Warning Notification System
- ✅ Progressive desktop notifications
- ✅ 10-second intervals between warnings
- ✅ User has 50 seconds to respond
- ✅ Automatic quarantine after 5th warning
- ✅ Critical alerts with sound (system-dependent)

### 🔒 Automatic Defense Actions
- ✅ IP blocking (firewall rules)
- ✅ Domain blocking (hosts file)
- ✅ File quarantine (safe isolation)
- ✅ Process termination
- ✅ Network isolation

### 🤖 AI-Powered Intelligence
- ✅ **5 Threat Intelligence APIs**:
  1. VirusTotal (malware detection)
  2. AbuseIPDB (IP reputation)
  3. Shodan (network vulnerabilities)
  4. URLScan (web threats)
  5. Hybrid Analysis (sandbox analysis)
  
- ✅ **Gemini AI Integration**:
  - Threat prediction (0-100% likelihood)
  - Attack pattern analysis
  - Defense strategy generation
  - Learning from historical data

---

## 🔧 Installation & Setup

### Prerequisites

```bash
# System requirements
- Python 3.9 or higher
- 4GB RAM minimum
- Linux, Windows, or macOS
- Admin/sudo privileges (for firewall control)

# For notifications
- Linux: libnotify-dev
- Windows: win10toast
- macOS: pync
```

### Step 1: Install Server Dependencies

```bash
cd /home/kali/Documents/SENTINELAI-main/server

# Install Python packages
pip3 install -r requirements.txt

# Install additional AI packages
pip3 install google-generativeai aiohttp
```

### Step 2: Install Client Dependencies

```bash
cd /home/kali/Documents/SENTINELAI-main/client

# Install base packages
pip3 install psutil requests aiohttp

# Install notification libraries
# For Linux:
sudo apt-get install libnotify-dev
pip3 install notify2

# For Windows:
pip3 install win10toast

# For macOS:
pip3 install pync
```

### Step 3: Configure API Keys

Create `server/config.ini`:
```ini
[APIs]
virustotal_api_key = YOUR_VIRUSTOTAL_KEY
abuseipdb_api_key = YOUR_ABUSEIPDB_KEY
shodan_api_key = YOUR_SHODAN_KEY
urlscan_api_key = YOUR_URLSCAN_KEY
hybrid_analysis_api_key = YOUR_HYBRID_KEY

[Gemini]
api_key = YOUR_GEMINI_API_KEY
model = gemini-2.0-flash-exp
```

### Step 4: Start the Server

```bash
cd /home/kali/Documents/SENTINELAI-main/server
python3 run_server.py

# You should see:
# 🚀 Starting SENTINEL-AI Application...
# ✅ Application startup complete
# 📊 System Status: online
# INFO: Uvicorn running on http://0.0.0.0:8000
```

### Step 5: Start Real-Time Protection

```bash
cd /home/kali/Documents/SENTINELAI-main/client
python3 sentinel_realtime_protection.py --server http://localhost:8000

# You should see:
# ============================================================
# 🛡️  SENTINEL-AI REAL-TIME PROTECTION STARTED
# ============================================================
# Client ID: CLIENT_XXXXXXXXXXXX
# Server: http://localhost:8000
# Warning System: 5 warnings before auto-quarantine
# ============================================================
# 🔍 Starting network connection monitoring...
# 📁 Monitoring directories: ['/home/user/Downloads', '/home/user/Desktop']
# 🔄 Starting periodic system scans...
```

### Step 6: Verify Protection is Active

You should receive a desktop notification:
```
🛡️  SentinelAI Protection Active
Real-time threat detection enabled
Client: CLIENT_XXXXXXXXXXXX
```

---

## 🎯 Usage Guide

### Automatic Protection

Once started, SentinelAI automatically:

1. **Monitors Network Connections**
   - Scans every new connection
   - Checks IP reputation
   - Detects suspicious activity

2. **Watches File System**
   - Monitors Downloads folder
   - Scans new files
   - Quarantines malware

3. **Analyzes Processes**
   - Detects suspicious processes
   - Monitors resource usage
   - Alerts on anomalies

### Manual Scanning

You can also scan specific targets:

```python
from sentinel_realtime_protection import RealTimeDefenseSystem

# Create instance
system = RealTimeDefenseSystem("http://localhost:8000")

# Scan an IP
await system.scan_target("8.8.8.8", "ip")

# Scan a URL
await system.scan_target("https://example.com", "url")

# Scan a file
await system.scan_target("/path/to/file.exe", "file")
```

---

## ⚠️  Warning System Flow

### Example: Malicious IP Detection

**Warning #1** (at 0 seconds)
```
⚠️  THREAT DETECTED (1/5)
Target: 192.168.1.100
Threat Level: SUSPICIOUS
Confidence: 75.3%
Type: IP
4 warnings remaining before automatic quarantine!
```

**Warning #2** (at 10 seconds)
```
⚠️  THREAT DETECTED (2/5)
Target: 192.168.1.100  
Threat Level: SUSPICIOUS
Confidence: 78.1%
Type: IP
3 warnings remaining before automatic quarantine!
```

**Warnings #3, #4, #5** continue every 10 seconds...

**After 5th Warning** (at 50 seconds)
```
🚨 AUTOMATIC QUARANTINE
Maximum warnings reached!
Automatically quarantining: 192.168.1.100

Action: Blocking and isolating threat
Status: In progress...
```

**Quarantine Complete**
```
✅ SUCCESS - Quarantine Complete
Threat neutralized: 192.168.1.100

Actions taken:
• Blocked IP: 192.168.1.100
• Updated firewall rules
• Notified server
• Logged incident

Your system is now protected.
```

---

## 🔧 Configuration Options

### Monitoring Intervals

Edit in `sentinel_realtime_protection.py`:

```python
# Network monitoring interval (seconds)
network_check_interval = 30  # Check every 30 seconds

# File monitoring interval (seconds)
file_check_interval = 10  # Check every 10 seconds

# System scan interval (seconds)
system_scan_interval = 300  # Full scan every 5 minutes

# Warning interval (seconds)
warning_interval = 10  # 10 seconds between warnings
```

### Monitoring Directories

Add custom directories to monitor:

```python
watch_dirs = [
    "/home/user/Downloads",
    "/home/user/Desktop",
    "/home/user/Documents",  # Add custom directories
    "/var/www/uploads",
]
```

### Threat Thresholds

Adjust detection sensitivity:

```python
# Threat score thresholds
MALICIOUS_THRESHOLD = 0.8  # 80% or higher = malicious
SUSPICIOUS_THRESHOLD = 0.4  # 40-79% = suspicious
SAFE_THRESHOLD = 0.2       # Below 20% = safe
```

---

## 📊 View Protection Statistics

### Real-Time Dashboard

Access the web dashboard:
```
http://localhost:8000/static/index.html
```

Features:
- Live threat feed
- API status monitoring
- Recent scans
- Defense actions taken
- Generate reports (24h, 7d, 30d)

### Client Statistics

View stats in the terminal where the client is running:

```
📊 PROTECTION STATISTICS
══════════════════════════════════════════
Attacks Detected: 15
Attacks Blocked: 15
Files Quarantined: 3
IPs Blocked: 8
Domains Blocked: 4
Warnings Issued: 75
══════════════════════════════════════════
```

---

## 🧪 Testing Your Setup

### Test 1: EICAR Test File

Download the EICAR test file (harmless but detected as malware):

```bash
wget http://www.eicar.org/download/eicar.com.txt
```

**Expected**: 
- 5 warnings issued
- File automatically quarantined
- Desktop notifications appear

### Test 2: Port Scan Detection

From another machine, scan your system:

```bash
nmap -sS your-system-ip
```

**Expected**:
- Scanner IP detected as suspicious
- 5 warnings issued
- IP automatically blocked
- Scanner cannot complete scan

### Test 3: Malicious URL

Try accessing a known malicious domain (test domain, not real):

```bash
curl http://malware-test-domain.com
```

**Expected**:
- URL analyzed via URLScan + VirusTotal
- Domain blocked via hosts file
- Desktop notification shows blocking

---

## 🔍 AI Threat Prediction

### Test AI Prediction

```bash
curl -X POST "http://localhost:8000/api/v1/ai-prediction/ai/predict-threat" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.100",
    "target_type": "ip"
  }'
```

**Response**:
```json
{
  "target": "192.168.1.100",
  "prediction": {
    "attack_likelihood": 85,
    "predicted_attack_types": ["DDoS", "Port Scan"],
    "recommended_actions": [
      "Block IP immediately",
      "Monitor for 24 hours",
      "Check for network-wide attacks"
    ],
    "risk_timeline": "immediate",
    "confidence": 0.92,
    "reasoning": "High abuse confidence score, multiple attack attempts"
  },
  "defense_strategy": {
    "immediate_actions": [
      {"action": "block_ip", "target": "192.168.1.100", "priority": 5, "effectiveness": 95}
    ],
    "estimated_risk_reduction": 90
  }
}
```

---

## 🛠️ Troubleshooting

### Issue: Notifications Not Appearing

**Linux**:
```bash
# Check if notify-send works
notify-send "Test" "This is a test notification"

# If not working, install:
sudo apt-get install libnotify-bin
pip3 install notify2
```

**Windows**:
```bash
pip3 install win10toast
```

### Issue: Firewall Rules Not Applied

**Linux** - Check permissions:
```bash
# Client needs sudo access
sudo visudo
# Add: username ALL=(ALL) NOPASSWD: /sbin/iptables
```

**Windows** - Run as Administrator:
```bash
# Right-click terminal → Run as Administrator
python sentinel_realtime_protection.py
```

### Issue: API Rate Limits

If you see API errors:
```
1. Check API key validity
2. Verify rate limits not exceeded
3. Wait and retry
4. Consider upgrading API plans
```

---

## 📈 Performance Optimization

### For High-Traffic Environments

```python
# Increase check intervals
network_check_interval = 60  # From 30 to 60 seconds
file_check_interval = 30      # From 10 to 30 seconds

# Cache API results
use_api_cache = True
cache_duration = 300  # 5 minutes
```

### For Low-Resource Systems

```python
# Disable heavy monitoring
enable_process_monitoring = False
enable_network_monitoring = True  # Keep essential
enable_file_monitoring = True     # Keep essential
```

---

## 🎯 Next Steps

1. **Test with DVWA** - See TESTING_GUIDE_DVWA_METASPLOITABLE.md
2. **Test with Metasploitable** - Run real attacks
3. **Monitor Dashboard** - Watch live threat feed
4. **Review Reports** - Generate 24h/7d/30d reports
5. **Fine-tune** - Adjust thresholds based on your environment

---

## ✅ Your System is Now Fully Protected!

**What You Have**:
- ✅ Real-time attack detection
- ✅ 5-warning notification system
- ✅ Automatic quarantine
- ✅ IP/Domain blocking
- ✅ 5 threat intelligence APIs
- ✅ AI-powered prediction
- ✅ Comprehensive reports
- ✅ Web dashboard
- ✅ Desktop notifications
- ✅ Enterprise-grade security

**All features from your proposal are implemented and working!** 🎉

---

For questions or issues, check the logs:
- Server: `server/logs/app.log`
- Client: `client/sentinel_realtime.log`
