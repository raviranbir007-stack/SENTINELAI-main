# External API Integration Guide

## Overview
SENTINEL-AI integrates with 5 external threat intelligence APIs to provide comprehensive threat analysis. Each API serves a specific purpose in the threat detection pipeline.

## API Summary

| API | Purpose | Input Types | Key Features |
|-----|---------|-------------|--------------|
| **VirusTotal** | File & URL scanning | File hashes, URLs | 70+ antivirus engines, community reputation |
| **AbuseIPDB** | IP reputation | IP addresses | Abuse reports, confidence scoring |
| **Shodan** | Network reconnaissance | IP addresses | Open ports, services, vulnerabilities |
| **Hybrid Analysis** | Malware sandbox | File hashes | Behavioral analysis, threat scoring |
| **URLScan.io** | URL analysis | URLs | Screenshot, DOM analysis, threat detection |

---

## 1. VirusTotal API

### Purpose
Scans files and URLs using 70+ antivirus engines and threat intelligence sources.

### Endpoints Used
- **File Scan**: `GET /files/{hash}` - Get analysis by file hash (MD5/SHA1/SHA256)
- **URL Scan**: `POST /urls` - Submit URL for scanning

### What It Does
1. **File Analysis**:
   - Checks file hash against virus signature databases
   - Returns detection counts: malicious, suspicious, clean
   - Provides vendor-specific detection names
   
2. **URL Analysis**:
   - Submits URL for multi-engine scanning
   - Checks for phishing, malware, suspicious content
   - Returns reputation and detection statistics

### Integration in SENTINEL-AI
```python
# Used in: app/services/virus_total.py
# Called by: threat_analyzer for URLs and file hashes

# File hash scanning
result = await VirusTotalService.scan_file(file_hash)
# Returns: {data: {attributes: {last_analysis_stats: {...}}}}

# URL scanning  
result = await VirusTotalService.scan_url(url)
# Returns: Scan ID and analysis results
```

### Response Format
```json
{
  "data": {
    "attributes": {
      "last_analysis_stats": {
        "malicious": 0,
        "suspicious": 0,
        "undetected": 61,
        "harmless": 0
      }
    }
  }
}
```

### API Key Configuration
```bash
VIRUSTOTAL_API_KEY=your_api_key_here
```

### Rate Limits
- Free tier: 4 requests/minute
- Public API: 500 requests/day

---

## 2. AbuseIPDB API

### Purpose
Checks IP addresses against a database of reported abusive activity.

### Endpoints Used
- **Check IP**: `GET /check?ipAddress={ip}&maxAgeInDays=90`

### What It Does
1. Queries database for abuse reports on specific IP
2. Returns abuse confidence score (0-100%)
3. Provides report count, categories, and ISP information
4. Checks last 90 days of abuse history

### Integration in SENTINEL-AI
```python
# Used in: app/services/abuseipdb.py
# Called by: threat_analyzer for IP address analysis

result = await AbuseIPDBService.check_ip(ip_address)
# Returns: {data: {abuseConfidenceScore, totalReports, ...}}
```

### Threat Classification
- **Score > 75%**: Critical threat (likely compromised/malicious)
- **Score 25-75%**: Medium threat (suspicious activity)
- **Score < 25%**: Low/no threat

### Response Format
```json
{
  "data": {
    "ipAddress": "8.8.8.8",
    "abuseConfidenceScore": 0,
    "totalReports": 142,
    "countryCode": "US",
    "isp": "Google LLC",
    "usageType": "Data Center/Web Hosting/Transit"
  }
}
```

### API Key Configuration
```bash
ABUSEIPDB_API_KEY=your_api_key_here
```

### Rate Limits
- Free tier: 1,000 requests/day
- Paid tiers: Up to 100,000 requests/day

---

## 3. Shodan API

### Purpose
Network intelligence platform that scans the internet for exposed services and vulnerabilities.

### Endpoints Used
- **Host Lookup**: `GET /shodan/host/{ip}`

### What It Does
1. Returns all open ports and services for an IP
2. Identifies software versions and banners
3. Lists known vulnerabilities (CVEs)
4. Provides organization and geolocation data

### Integration in SENTINEL-AI
```python
# Used in: app/services/shodan.py
# Called by: threat_analyzer for IP address reconnaissance

result = await ShodanService.search_ip(ip_address)
# Returns: {org, hostnames, ports, vulns, ...}
```

### Threat Indicators
- **Critical**: CVEs with "critical" severity found
- **Medium**: Any vulnerabilities present
- **Low**: >10 open ports (excessive exposure)

### Response Format
```json
{
  "org": "Google LLC",
  "hostnames": ["dns.google"],
  "ports": [443, 53],
  "vulns": [],
  "country_name": "United States",
  "data": [
    {
      "port": 443,
      "transport": "tcp",
      "product": "Google",
      "version": "2.0"
    }
  ]
}
```

### API Key Configuration
```bash
SHODAN_API_KEY=your_api_key_here
```

### Rate Limits
- Free tier: 1 request/second, 100 API scan credits/month
- Paid tiers: Unlimited queries

---

## 4. Hybrid Analysis API

### Purpose
Cloud-based malware sandbox that performs behavioral analysis of files.

### Endpoints Used
- **Hash Search**: `GET /search/hash?hash={hash}`

### What It Does
1. Searches for previous sandbox analysis of file hash
2. Returns behavioral analysis results
3. Provides threat score (0-100)
4. Shows malicious behaviors detected during execution

### Integration in SENTINEL-AI
```python
# Used in: app/services/hybrid_analysis.py
# Called by: threat_analyzer for file hash analysis

result = await HybridAnalysisService.search_hash(file_hash)
# Returns: {results: [{verdict, threat_score, ...}]}
```

### Verdict Classifications
- **malicious**: Confirmed malware (threat_score > 75)
- **suspicious**: Potentially harmful behavior (threat_score 50-75)
- **no specific threat**: Clean or unknown

### Response Format
```json
{
  "results": [
    {
      "verdict": "malicious",
      "threat_score": 85,
      "job_id": "...",
      "sha256": "...",
      "analysis_start_time": "2025-01-01T00:00:00"
    }
  ]
}
```

### API Key Configuration
```bash
HYBRID_ANALYSIS_API_KEY=your_api_key_here
```

### Rate Limits
- Free tier: Limited submissions
- Enterprise: Custom limits

---

## 5. URLScan.io API

### Purpose
Service that analyzes websites for malicious content, phishing, and security threats.

### Endpoints Used
- **Submit Scan**: `POST /scan/` - Submit URL for analysis
- **Get Results**: `GET /result/{uuid}/` - Retrieve scan results

### What It Does
1. **Submission Phase**:
   - Takes screenshot of website
   - Renders page in sandbox browser
   - Analyzes JavaScript execution
   - Returns scan UUID

2. **Results Phase** (after ~10-30 seconds):
   - Full DOM tree analysis
   - Network requests made by page
   - Security classifications (phishing, malware)
   - IP addresses and domains contacted

### Integration in SENTINEL-AI
```python
# Used in: app/services/urlscan.py
# Called by: threat_analyzer for URL analysis

# Submit scan
result = await URLScanService.scan_url(url)
# Returns: {uuid, api, result}

# Get results (after delay)
results = await URLScanService.get_results(uuid)
# Returns: Full analysis including classifications
```

### Threat Detection
- **Phishing**: Site impersonates legitimate service
- **Malware**: Site serves malicious downloads
- **Suspicious**: Anomalous behavior detected

### Response Format
```json
{
  "uuid": "019b6549-17e5-7344-b24b-461bf70e428c",
  "result": "https://urlscan.io/result/019b6549-17e5-7344-b24b-461bf70e428c/",
  "api": "https://urlscan.io/api/v1/result/019b6549-17e5-7344-b24b-461bf70e428c/"
}
```

### Special Notes
- **Domain Blocking**: Popular domains (google.com, facebook.com) may be blocked to prevent abuse
- **Scan Delay**: Results not immediately available (10-30 seconds)
- **Public Visibility**: Scans are public by default

### API Key Configuration
```bash
URLSCAN_API_KEY=your_api_key_here
```

### Rate Limits
- Free tier: Limited scans/day
- Paid tiers: Higher limits and private scans

---

## API Orchestration

### How SENTINEL-AI Uses These APIs

```
Input Detection
     ↓
┌────┴────┐
│ IP      │ → AbuseIPDB (abuse check) + Shodan (reconnaissance)
│ URL     │ → VirusTotal (scan) + URLScan (analysis)
│ Hash    │ → VirusTotal (lookup) + Hybrid Analysis (sandbox)
│ Domain  │ → Convert to URL → Same as URL analysis
└─────────┘
     ↓
Threat Analysis
     ↓
Verdict Calculation
```

### Verdict Calculation Logic

The system aggregates results from all APIs to determine final verdict:

```python
def _calculate_verdict(result):
    threats = result["threat_indicators"]
    
    # Check for critical threats
    critical = [t for t in threats if t["severity"] == "critical"]
    if critical:
        return "malicious", confidence=0.9
    
    # Check for medium threats
    medium = [t for t in threats if t["severity"] == "medium"]
    if medium:
        return "suspicious", confidence=0.6
    
    # Low or no threats
    return "clean", confidence=0.7
```

---

## Error Handling

### Common Error Scenarios

1. **API Key Not Configured**
   ```json
   {"error": "API key not configured"}
   ```
   **Solution**: Set API key in `.env` file

2. **Rate Limit Exceeded**
   ```json
   {"error": "API error: 429"}
   ```
   **Solution**: Wait or upgrade API tier

3. **Timeout**
   ```json
   {"error": "API timeout"}
   ```
   **Solution**: Request queued, will retry

4. **Invalid Input**
   ```json
   {"error": "API error: 400"}
   ```
   **Solution**: Check input format

### Graceful Degradation

SENTINEL-AI continues analysis even if some APIs fail:

```python
# If VirusTotal fails, still check AbuseIPDB
# If all external APIs fail, use local ML models
# Always return a verdict with confidence score
```

---

## Testing APIs

### Run Comprehensive Test
```bash
PYTHONPATH=server .venv/bin/python test_all_apis.py
```

### Test Individual API
```bash
# Test VirusTotal
curl -X POST http://127.0.0.1:8000/api/v1/scan/hash \
  -H "Content-Type: application/json" \
  -d '{"target":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}'

# Test AbuseIPDB + Shodan
curl -X POST http://127.0.0.1:8000/api/v1/scan/ip \
  -H "Content-Type: application/json" \
  -d '{"target":"8.8.8.8"}'

# Test VirusTotal + URLScan
curl -X POST http://127.0.0.1:8000/api/v1/scan/url \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.org"}'
```

---

## API Key Management

### Getting API Keys

1. **VirusTotal**: https://www.virustotal.com/gui/join-us
2. **AbuseIPDB**: https://www.abuseipdb.com/register
3. **Shodan**: https://account.shodan.io/register
4. **Hybrid Analysis**: https://www.hybrid-analysis.com/signup
5. **URLScan.io**: https://urlscan.io/user/signup

### Configuration

Create `.env` file in server directory:

```bash
# External API Keys
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
HYBRID_ANALYSIS_API_KEY=your_key_here
URLSCAN_API_KEY=your_key_here
```

### Security Best Practices

1. **Never commit `.env` files** - Use `.env.example` as template
2. **Rotate keys regularly** - Every 90 days recommended
3. **Use environment variables** - Don't hardcode in source
4. **Monitor usage** - Check API dashboards for abuse
5. **Set up alerts** - Get notified of rate limit issues

---

## Performance Optimization

### Parallel API Calls

SENTINEL-AI calls multiple APIs in parallel:

```python
# IP analysis calls both APIs simultaneously
abuseipdb_task = asyncio.create_task(abuseipdb.check_ip(ip))
shodan_task = asyncio.create_task(shodan.search_ip(ip))

results = await asyncio.gather(abuseipdb_task, shodan_task)
```

### Caching

Consider implementing caching for frequently scanned targets:

```python
# Cache results for 5 minutes to avoid duplicate API calls
@cache(ttl=300)
async def scan_ip(ip):
    return await threat_analyzer.analyze(ip)
```

---

## Monitoring & Troubleshooting

### Check API Status
```bash
# View application logs
tail -f logs/sentinel.log | grep -E "(VirusTotal|AbuseIPDB|Shodan|Hybrid|URLScan)"
```

### Common Issues

1. **All APIs returning errors**: Check internet connectivity
2. **Specific API failing**: Verify API key, check service status
3. **Slow responses**: Normal for URLScan (scan takes time)
4. **Empty results**: Not all hashes/IPs have existing data

---

## Summary

All 5 APIs are integrated and working:

- ✅ **VirusTotal**: File hash and URL scanning
- ✅ **AbuseIPDB**: IP abuse reputation checking
- ✅ **Shodan**: Network reconnaissance and vulnerability detection
- ✅ **Hybrid Analysis**: Malware behavioral analysis
- ✅ **URLScan.io**: Website threat analysis

Each API provides unique threat intelligence that contributes to SENTINEL-AI's comprehensive threat detection capabilities.
