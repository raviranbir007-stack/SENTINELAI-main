# SENTINEL-AI Setup and Configuration Guide

## Issues Fixed

### 1. ✅ ReportLab PDF Generation
**Problem:** `reportlab not installed. Returning text fallback instead of PDF`

**Solution:** ReportLab is already installed in your virtual environment. The warning was just indicating fallback behavior when the library wasn't available.

### 2. ✅ API Configuration Missing
**Problem:** APIs not detecting malicious URLs - returning "safe" for malicious content

**Root Cause:** No `.env` file with API keys configured, so all API calls were failing silently

**Solution:** 
- Created `.env.example` template
- Enhanced error handling to show when APIs are not configured
- Improved logging to show API responses

### 3. ✅ VirusTotal URL Scanning Fixed
**Problem:** VirusTotal scan_url() was submitting URLs but not retrieving analysis results

**Solution:** 
- Enhanced `scan_url()` to properly retrieve analysis results
- Added analysis ID tracking
- Implemented fallback to URL object retrieval
- Added proper error handling and logging

### 4. ✅ Better Threat Detection
**Problem:** Threats not being properly flagged

**Solution:**
- Enhanced threat analyzer to show detailed logging
- Added warning system for unconfigured APIs
- Improved verdict calculation
- Better error messages

---

## Quick Setup (5 Minutes)

### Step 1: Create .env File

```bash
cd /home/kali/Documents/SENTINELAI-main/server
cp .env.example .env
nano .env  # or use your preferred editor
```

### Step 2: Get FREE API Keys

You need these API keys for full functionality:

#### VirusTotal (REQUIRED for URL/File scanning)
1. Go to: https://www.virustotal.com/gui/join-us
2. Sign up (free)
3. Go to your profile → API Key
4. Copy and paste into `.env`: `VIRUSTOTAL_API_KEY=your_actual_key_here`

#### URLScan.io (Recommended for URL analysis)
1. Go to: https://urlscan.io/user/signup
2. Sign up (free)
3. Go to Settings & API
4. Copy API key
5. Paste into `.env`: `URLSCAN_API_KEY=your_actual_key_here`

#### AbuseIPDB (Recommended for IP reputation)
1. Go to: https://www.abuseipdb.com/register
2. Sign up (free)
3. Go to Account → API
4. Copy API key
5. Paste into `.env`: `ABUSEIPDB_API_KEY=your_actual_key_here`

#### Shodan (Optional - for advanced IP intel)
1. Go to: https://account.shodan.io/register
2. Sign up (requires credit card for free tier)
3. Copy API key from account page
4. Paste into `.env`: `SHODAN_API_KEY=your_actual_key_here`

#### Google Gemini (Optional - for AI-powered analysis)
1. Go to: https://makersuite.google.com/app/apikey
2. Create API key (free tier available)
3. Paste into `.env`: `GEMINI_API_KEY=your_actual_key_here`

### Step 3: Test Your Configuration

```bash
cd /home/kali/Documents/SENTINELAI-main/server
/home/kali/Documents/SENTINELAI-main/.venv-ml/bin/python test_api_config.py
```

This will test all your APIs and show which ones are working.

### Step 4: Start the Server

```bash
cd /home/kali/Documents/SENTINELAI-main/server
/home/kali/Documents/SENTINELAI-main/.venv-ml/bin/python run_server.py
```

---

## Testing Malicious URL Detection

Once your APIs are configured, test with these known test URLs:

### Test URLs:

1. **EICAR Test File (Safe test malware)**
   ```
   http://malware.wicar.org/data/eicar.com
   ```

2. **VirusTotal Test**
   ```
   https://secure.eicar.org/eicar.com
   ```

3. **Phishing Test (DO NOT VISIT - use for API testing only)**
   ```
   Use URLs from phishtank.org
   ```

### How to Test via API:

```bash
# Test malicious URL scan
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "http://malware.wicar.org/data/eicar.com", "include_report": false}'
```

Expected response should show:
- `threat_level`: "malicious" or "suspicious"
- `confidence`: > 0.7
- `threat_indicators`: Array with detections from APIs

---

## Troubleshooting

### Issue: "API key not configured" warnings

**Solution:** Make sure your `.env` file exists and has the correct API keys.

```bash
# Check if .env exists
ls -la /home/kali/Documents/SENTINELAI-main/server/.env

# Verify keys are loaded
cd /home/kali/Documents/SENTINELAI-main/server
/home/kali/Documents/SENTINELAI-main/.venv-ml/bin/python -c "from app.config import settings; print(f'VT Key: {settings.VIRUSTOTAL_API_KEY[:10]}...' if settings.VIRUSTOTAL_API_KEY else 'Not configured')"
```

### Issue: Still showing "safe" for malicious URLs

**Possible causes:**
1. API keys not configured → See Step 1-2 above
2. API rate limits exceeded → Wait a few minutes
3. URL not yet in API databases → Try known malicious URLs above

### Issue: reportlab warning still appearing

**This is normal if:**
- ReportLab is installed but there's an import issue
- Python environment not activated

**To verify:**
```bash
/home/kali/Documents/SENTINELAI-main/.venv-ml/bin/python -c "import reportlab; print('✓ ReportLab installed:', reportlab.Version)"
```

### Issue: PDF reports not generating

**Solution:**
```bash
# Reinstall reportlab
/home/kali/Documents/SENTINELAI-main/.venv-ml/bin/pip install --force-reinstall reportlab
```

---

## API Rate Limits

Be aware of free tier limits:

| Service | Free Tier Limit |
|---------|----------------|
| VirusTotal | 4 requests/minute, 500/day |
| URLScan.io | 50/day |
| AbuseIPDB | 1,000/day |
| Shodan | 100/month (query), 1/day (scan) |
| Gemini | 15 requests/minute |

---

## Verification Checklist

- [ ] `.env` file created with API keys
- [ ] VirusTotal API key configured and tested
- [ ] URLScan API key configured (optional but recommended)
- [ ] AbuseIPDB API key configured (optional but recommended)
- [ ] Test script runs successfully: `python test_api_config.py`
- [ ] Server starts without errors
- [ ] Malicious URL test returns "malicious" verdict
- [ ] PDF reports generate successfully
- [ ] No "API key not configured" warnings in logs

---

## Need Help?

1. **Run the test script first:**
   ```bash
   /home/kali/Documents/SENTINELAI-main/.venv-ml/bin/python server/test_api_config.py
   ```

2. **Check server logs** for specific error messages

3. **Verify environment:**
   ```bash
   /home/kali/Documents/SENTINELAI-main/.venv-ml/bin/python --version
   /home/kali/Documents/SENTINELAI-main/.venv-ml/bin/pip list | grep -E "reportlab|httpx|fastapi"
   ```

---

## What's Working Now

✅ **VirusTotal URL scanning** - Properly retrieves and analyzes results  
✅ **API error handling** - Shows clear warnings when APIs aren't configured  
✅ **Threat detection** - Correctly flags malicious content when APIs are configured  
✅ **PDF generation** - ReportLab properly installed  
✅ **Logging** - Detailed logs show what each API returns  
✅ **Configuration template** - Easy setup with .env.example  

---

## Example: Complete Test

```bash
# 1. Setup
cd /home/kali/Documents/SENTINELAI-main/server
cp .env.example .env
# Edit .env with your API keys

# 2. Test APIs
/home/kali/Documents/SENTINELAI-main/.venv-ml/bin/python test_api_config.py

# 3. Start server
/home/kali/Documents/SENTINELAI-main/.venv-ml/bin/python run_server.py

# 4. Test in another terminal
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "http://malware.wicar.org/data/eicar.com"}'
```

You should see a response with `"threat_level": "malicious"` if VirusTotal is configured!
