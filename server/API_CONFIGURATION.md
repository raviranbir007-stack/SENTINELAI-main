# API Configuration Guide

This guide helps you set up and configure the threat detection APIs for SENTINEL-AI.

## Table of Contents

1. [VirusTotal](#virustotal)
2. [AbuseIPDB](#abuseipdb)
3. [Shodan](#shodan)
4. [Hybrid Analysis](#hybrid-analysis)
5. [URLScan.io](#urlscanio)
6. [Google Gemini (Optional)](#google-gemini-optional)
7. [Verification](#verification)

---

## VirusTotal

### Overview
VirusTotal scans URLs, files, and domains using 90+ antivirus engines and URL analysis services.

### Get API Key
1. Visit: https://www.virustotal.com/
2. Click "Sign in" (top right)
3. Create account or login with existing account
4. Click your username → "Settings"
5. Left sidebar → "API key"
6. Copy the API key under "API key"

### Configuration
```env
VIRUSTOTAL_API_KEY=your_api_key_here
```

### Usage
- **Files**: SHA256, SHA1, or MD5 hash
- **URLs**: Full HTTP/HTTPS URL
- **Domains**: Domain name

### Limits
- **Free**: 4 requests/minute, 600 requests/day
- **Premium**: 600 requests/minute, unlimited daily

### API Documentation
https://developers.virustotal.com/reference/

---

## AbuseIPDB

### Overview
AbuseIPDB is a database of IP addresses involved in malicious activity including DDoS attacks, hacking, phishing, etc.

### Get API Key
1. Visit: https://www.abuseipdb.com/
2. Click "Register" (top right)
3. Complete registration
4. Click your username → "Account Settings"
5. Left sidebar → "API"
6. Click "Create Key"
7. Give it a name and create
8. Copy the API Key

### Configuration
```env
ABUSEIPDB_API_KEY=your_api_key_here
```

### Usage
- Check IP addresses for abuse reports
- Get confidence scores of malicious activity

### Limits
- **Free**: 1,000 requests/day
- **Premium**: 150,000 requests/day

### API Documentation
https://docs.abuseipdb.com/

---

## Shodan

### Overview
Shodan searches for internet-connected devices, reveals exposed services, open ports, and vulnerabilities.

### Get API Key
1. Visit: https://www.shodan.io/
2. Click "Sign up" (top right)
3. Complete registration
4. Click your username → "My Account"
5. Left sidebar → "API"
6. Copy your API key under "API key"

### Configuration
```env
SHODAN_API_KEY=your_api_key_here
```

### Usage
- Scan IP addresses for open ports
- Discover exposed services
- Find known vulnerabilities

### Limits
- **Free**: 1 request/month (query-based)
- **Starter**: $49/month - 100 requests/month
- **Professional**: $199/month - unlimited

### API Documentation
https://developer.shodan.io/

---

## Hybrid Analysis

### Overview
Hybrid Analysis is a malware analysis platform that analyzes files in a sandboxed environment and provides threat intelligence.

### Get API Key
1. Visit: https://www.hybrid-analysis.com/
2. Click "Sign up" (top right)
3. Complete registration with email verification
4. Click your profile → "Settings"
5. Left sidebar → "API"
6. Click "Create API Key"
7. Give it a name and create
8. Copy the Secret Key and API Key

### Configuration
```env
HYBRIDANALYSIS_API_KEY=your_api_key_here
```

### Usage
- Analyze file hashes
- Get malware verdicts and threat scores
- Retrieve detonation reports

### Limits
- **Free**: 50 requests/day
- **Premium**: Higher limits

### API Documentation
https://www.hybrid-analysis.com/apikeys

---

## URLScan.io

### Overview
URLScan.io scans URLs and provides security analysis including screenshots, JavaScript analysis, and threat detection.

### Get API Key
1. Visit: https://urlscan.io/
2. Click "Free account" (top right)
3. Complete registration
4. Click your username → "Settings"
5. Left sidebar → "API"
6. Click "Create API Key"
7. Copy the API Key

### Configuration
```env
URLSCAN_API_KEY=your_api_key_here
```

### Usage
- Scan URLs for threats
- Get classification information
- Retrieve scan results and reports

### Limits
- **Free**: 100 scans/day
- **Plus**: Higher limits

### API Documentation
https://urlscan.io/api/

---

## Google Gemini (Optional)

### Overview
Google Gemini provides AI-powered analysis for generating comprehensive threat reports.

### Get API Key
1. Visit: https://ai.google.dev/
2. Click "Get API key" (top right)
3. Create new project or select existing
4. Click "Create API Key in Google Cloud Console"
5. Copy the generated API key

### Configuration
```env
GEMINI_API_KEY=your_api_key_here
```

### Enable Gemini Integration
The system automatically uses Gemini if:
1. `GEMINI_API_KEY` is set in environment
2. `google-generativeai` package is installed
3. `reportlab` package is installed for PDF generation

### Features
- AI-generated threat analysis
- Professional report generation
- Smart recommendations

### Limits
- **Free**: 60 requests/minute
- **Premium**: Higher limits with payment

### API Documentation
https://ai.google.dev/docs/

---

## Verification

### Method 1: Using curl

Test each API with curl:

```bash
# VirusTotal
curl -X GET "https://www.virustotal.com/api/v3/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
  -H "x-apikey: YOUR_VIRUSTOTAL_API_KEY"

# AbuseIPDB
curl -X GET "https://api.abuseipdb.com/api/v2/check" \
  -H "Key: YOUR_ABUSEIPDB_API_KEY" \
  -H "Accept: application/json" \
  -d "ipAddress=8.8.8.8&maxAgeInDays=90"

# Shodan
curl -X GET "https://api.shodan.io/shodan/host/8.8.8.8?key=YOUR_SHODAN_API_KEY"

# Hybrid Analysis
curl -X GET "https://www.hybrid-analysis.com/api/v2/search/hash?hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
  -H "api-key: YOUR_HYBRIDANALYSIS_API_KEY" \
  -H "user-agent: Hybrid Analysis"

# URLScan.io
curl -X POST "https://urlscan.io/api/v1/scan/" \
  -H "API-Key: YOUR_URLSCAN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

### Method 2: Using SENTINEL-AI Test Script

```bash
# Run the test suite
python test_threat_detection.py
```

### Method 3: Using the API Endpoint

```bash
curl -X POST http://localhost:8000/api/v1/scan/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "8.8.8.8",
    "include_report": false
  }'
```

---

## Troubleshooting

### Issue: "API key not configured"
**Solution**: Ensure `.env` file exists with correct key names

### Issue: "Invalid API key"
**Solution**: 
- Verify key is correctly copied
- Check for extra spaces or special characters
- Regenerate key if expired

### Issue: "Rate limit exceeded"
**Solution**: 
- Wait before making more requests
- Consider upgrading to higher tier
- Implement request queuing

### Issue: "Service unavailable"
**Solution**: 
- Check API status page
- Verify internet connection
- Try again later

---

## Best Practices

1. **Security**
   - Never commit `.env` file to version control
   - Use environment variables in production
   - Rotate API keys periodically

2. **Rate Limiting**
   - Implement exponential backoff
   - Cache results when possible
   - Monitor API usage

3. **Redundancy**
   - Have backup API keys
   - Use multiple services for verification
   - Implement fallback mechanisms

4. **Monitoring**
   - Log all API calls
   - Monitor error rates
   - Alert on unusual activity

---

## Cost Estimation

| Service | Free Tier | Cost/Month | Best For |
|---------|-----------|------------|----------|
| **VirusTotal** | 4 req/min | $0-99 | Files & URLs |
| **AbuseIPDB** | 1k/day | $0-99 | IP Reputation |
| **Shodan** | Limited | $49+ | Port Scanning |
| **Hybrid Analysis** | 50/day | $0-999 | Malware Analysis |
| **URLScan** | 100/day | $0+ | URL Analysis |
| **Gemini** | 60 req/min | Free tier | AI Analysis |

**Recommended**: Start with free tiers, upgrade as usage grows.

---

## Support

For issues with specific APIs:
- VirusTotal: https://support.virustotal.com/
- AbuseIPDB: https://www.abuseipdb.com/contact
- Shodan: https://www.shodan.io/
- Hybrid Analysis: https://www.hybrid-analysis.com/
- URLScan: https://urlscan.io/
- Gemini: https://ai.google.dev/docs

---

**Last Updated**: January 2025
