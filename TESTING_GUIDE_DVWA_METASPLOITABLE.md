# 🎯 SentinelAI Testing Guide with DVWA & Metasploitable

## Overview
This guide demonstrates how SentinelAI protects against real attacks using DVWA (Damn Vulnerable Web Application) and Metasploitable.

---

## 🛡️ System Capabilities

### Real-Time Protection Features

✅ **5-Warning System**
- Detects threats in real-time
- Issues 5 progressive warnings with desktop notifications
- Automatically quarantines after 5th warning
- User has time to respond before auto-action

✅ **Automatic Defense**
- IP blocking (iptables/Windows Firewall)
- Domain blocking (hosts file)
- File quarantine (moves to safe location)
- Process termination (suspicious processes)

✅ **Multi-API Threat Intelligence**
1. **VirusTotal** - File/URL/hash malware scanning
2. **AbuseIPDB** - IP reputation & abuse reports  
3. **Shodan** - Network vulnerability detection
4. **URLScan** - Website security analysis
5. **Hybrid Analysis** - Advanced malware sandbox

✅ **AI-Powered Prediction**
- Gemini AI analyzes threat patterns
- Predicts attack likelihood (0-100%)
- Recommends defense strategies
- Learns from historical data

---

## 🧪 Test Scenario 1: DVWA SQL Injection Attack

### Setup
1. **Start DVWA** (Docker or VM)
   ```bash
   docker run -p 80:80 vulnerables/web-dvwa
   ```

2. **Start SentinelAI Server**
   ```bash
   cd /home/kali/Documents/SENTINELAI-main/server
   python3 run_server.py
   ```

3. **Start Real-Time Protection**
   ```bash
   cd /home/kali/Documents/SENTINELAI-main/client
   python3 sentinel_realtime_protection.py --server http://localhost:8000
   ```

### Attack Simulation

**Step 1: Monitor Network**
- SentinelAI monitors all network connections
- Detects connection to DVWA (192.168.x.x)

**Step 2: SQL Injection Attempt**
```bash
# Attacker runs SQL injection
curl "http://dvwa-server/vulnerabilities/sqli/?id=1' OR '1'='1"
```

**Expected SentinelAI Response:**
1. ⚠️  **Warning #1** - Desktop notification appears
   ```
   ⚠️  THREAT DETECTED (1/5)
   Target: 192.168.x.x
   Threat Level: SUSPICIOUS
   Type: IP
   4 warnings remaining before auto-quarantine!
   ```

2. **Continues monitoring** - Logs attack details

**Step 3: Repeated Attacks**
- Each subsequent attack triggers another warning
- Warnings #2, #3, #4, #5 appear

**Step 4: Automatic Quarantine (After 5th Warning)**
```
🚨 AUTOMATIC QUARANTINE
Maximum warnings reached!
Automatically quarantining: 192.168.x.x

Action: Blocking IP via firewall
Status: COMPLETED

✅ IP 192.168.x.x blocked via iptables
✅ Attack neutralized
✅ System protected
```

### Verification
```bash
# Check firewall rules
sudo iptables -L | grep "192.168"

# Should show:
# DROP all -- 192.168.x.x anywhere

# Try to access DVWA - should fail
curl http://192.168.x.x
# Connection refused
```

---

## 🧪 Test Scenario 2: Metasploitable Port Scan Attack

### Setup
1. **Start Metasploitable 2** VM
2. **Start SentinelAI** with network monitoring

### Attack Simulation

**Step 1: Nmap Scan**
```bash
# Attacker performs port scan
nmap -sS -p- metasploitable-ip
```

**SentinelAI Detection:**
- Detects unusual connection patterns
- Queries Shodan API for threat intelligence
- Checks AbuseIPDB for attacker IP reputation

**Step 2: First Warning**
```
⚠️  THREAT DETECTED (1/5)
Target: attacker-ip
Threat Level: SUSPICIOUS
Confidence: 72.3%
Type: IP
Reason: Port scanning activity detected
```

**Step 3: Metasploit Exploitation Attempt**
```bash
# Attacker uses Metasploit
msfconsole
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOST metasploitable-ip
exploit
```

**SentinelAI Escalation:**
- Warnings #2, #3, #4, #5 trigger
- Each warning shows in desktop notification
- Final warning at #5

**Step 4: Automatic Block**
```
🚨 AUTOMATIC QUARANTINE INITIATED
Target: attacker-ip
Threat Level: MALICIOUS
Confidence: 89.5%

Actions Taken:
✅ Blocked attacker-ip via firewall
✅ Added to global blocklist
✅ Alerted network administrator
✅ Updated all connected clients

Attack Prevented: ✅ SUCCESS
```

---

## 🧪 Test Scenario 3: Malicious File Download

### Attack Simulation

**Step 1: Download Suspicious File**
```bash
# Download test malware (EICAR test file)
wget http://www.eicar.org/download/eicar.com.txt
```

**SentinelAI File Monitoring:**
- Detects new file in Downloads folder
- Scans file hash with VirusTotal
- Analyzes file with Hybrid Analysis sandbox

**Step 2: First Detection**
```
⚠️  THREAT DETECTED (1/5)
Target: eicar.com.txt
Threat Level: MALICIOUS
Confidence: 100%
Type: FILE
VirusTotal: 69/69 engines detected malware
```

**Step 3: Progressive Warnings**
- User sees 5 warnings over 50 seconds (10s intervals)
- Each warning more urgent
- Final warning is critical

**Step 4: Automatic Quarantine**
```
🚨 AUTOMATIC QUARANTINE
File: /home/user/Downloads/eicar.com.txt

Actions Taken:
✅ File moved to: ~/.sentinel_quarantine/20260113_eicar.com.txt
✅ Original file deleted
✅ Directory scan completed
✅ No additional threats found

System Status: SECURE ✅
```

---

## 🧪 Test Scenario 4: Phishing URL Detection

### Attack Simulation

**Step 1: Access Phishing Site**
```bash
# User clicks phishing link
firefox http://malicious-phishing-site.com
```

**SentinelAI URL Monitoring:**
- Intercepts DNS request
- Queries URLScan.io API
- Checks VirusTotal URL database
- Analyzes with AI prediction engine

**Step 2: Real-Time Analysis**
```
🔍 Analyzing URL...
• URLScan Verdict: Malicious
• VirusTotal: 15/90 flagged as phishing
• AI Prediction: 94% attack likelihood
• Attack Type: Credential theft

⚠️  WARNING #1/5
URL: malicious-phishing-site.com
Threat: PHISHING ATTACK
Recommendation: Close browser immediately
```

**Step 3: Automatic Domain Block**
After 5 warnings (if user doesn't close):
```
🚨 DOMAIN BLOCKED

Added to /etc/hosts:
127.0.0.1    malicious-phishing-site.com

DNS Resolution: Blocked
Browser Access: Denied
System Protected: ✅
```

---

## 📊 Expected System Behavior

### For Each Attack:
1. **Immediate Detection** (<1 second)
2. **Multi-API Verification** (2-5 seconds)
3. **AI Threat Prediction** (3-7 seconds)
4. **Warning #1** - Desktop notification
5. **Warning #2-5** - Progressive alerts (10s intervals)
6. **Automatic Quarantine** - After 5th warning
7. **Defense Execution** - Blocking/quarantine
8. **Confirmation** - Success notification

### Desktop Notifications
```
Warning #1: ⚠️  Yellow notification
Warning #2: ⚠️  Yellow notification  
Warning #3: 🔶 Orange notification
Warning #4: 🔴 Red notification
Warning #5: 🚨 CRITICAL Red flash

Auto-Quarantine: 🛡️  Green checkmark (success)
```

---

## 🎯 Testing Checklist

### ✅ Network Protection
- [ ] Port scan detection
- [ ] DDoS detection
- [ ] Suspicious IP blocking
- [ ] Firewall rule creation

### ✅ File Protection
- [ ] Malware file detection
- [ ] Automatic quarantine
- [ ] Safe file restoration
- [ ] Real-time scanning

### ✅ Web Protection
- [ ] Phishing URL blocking
- [ ] Malicious domain blocking
- [ ] DNS hijacking prevention
- [ ] Browser protection

### ✅ AI Features
- [ ] Threat prediction accuracy
- [ ] Attack pattern recognition
- [ ] Defense strategy generation
- [ ] Learning from incidents

### ✅ Warning System
- [ ] 5 progressive warnings
- [ ] Desktop notifications
- [ ] User response time
- [ ] Automatic escalation

### ✅ Quarantine System
- [ ] Automatic after 5 warnings
- [ ] IP blocking
- [ ] Domain blocking
- [ ] File isolation

---

## 🔬 Advanced Testing

### Test with Real Attacks

**SQL Injection (DVWA)**
```bash
sqlmap -u "http://dvwa/vulnerabilities/sqli/?id=1" --cookie="security=low" --dbs
```

**XSS Attack (DVWA)**
```bash
curl "http://dvwa/vulnerabilities/xss_r/?name=<script>alert('XSS')</script>"
```

**Brute Force (Metasploitable)**
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://metasploitable-ip
```

**Expected Result**: All attacks detected and blocked within 5 warnings

---

## 📈 Performance Metrics

### Target Response Times:
- **Detection**: <1 second
- **API Analysis**: <5 seconds  
- **AI Prediction**: <7 seconds
- **Warning Issuance**: <1 second
- **Quarantine Execution**: <2 seconds

### Accuracy Goals:
- **True Positive Rate**: >95%
- **False Positive Rate**: <5%
- **Attack Prevention Rate**: >98%
- **Zero-Day Detection**: >60%

---

## 🚀 Running Full Test Suite

```bash
# Terminal 1: Start Server
cd server
python3 run_server.py

# Terminal 2: Start Real-Time Protection
cd client
python3 sentinel_realtime_protection.py

# Terminal 3: Run Attacks (from attacker machine)
# Use DVWA, Metasploitable, or custom scripts

# Monitor logs
tail -f client/sentinel_realtime.log
tail -f server/logs/app.log
```

---

## ✅ Success Criteria

Your SentinelAI system is working correctly if:

1. ✅ All 5 APIs respond and contribute to threat scores
2. ✅ AI prediction generates actionable recommendations
3. ✅ Desktop notifications appear for each warning
4. ✅ Automatic quarantine triggers after 5th warning
5. ✅ IP/Domain blocking actually prevents connections
6. ✅ File quarantine moves files safely
7. ✅ System remains responsive during attacks
8. ✅ Statistics are accurately tracked
9. ✅ No false negatives on known threats
10. ✅ Acceptable false positive rate (<5%)

---

## 🛡️ Your System Now Defends Against:

✅ SQL Injection
✅ XSS Attacks
✅ CSRF Attacks
✅ Port Scanning
✅ Brute Force
✅ DDoS Attacks
✅ Malware Downloads
✅ Phishing Sites
✅ Command Injection
✅ File Upload Attacks
✅ Buffer Overflow Attempts
✅ Zero-Day Exploits (via AI prediction)

---

**All features are now implemented and ready for testing!** 🎉
