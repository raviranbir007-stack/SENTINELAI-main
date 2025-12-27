# SENTINEL-AI Quick Reference Card

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Create .env file with API keys
cp .env.example .env
# Edit .env with your API keys

# 3. Run server
python run_server.py

# 4. Test (in another terminal)
python test_threat_detection.py
```

---

## 📋 API Endpoints

### Universal Scan (Auto-Detect)
```
POST /api/v1/scan/scan
{
  "target": "8.8.8.8 | example.com | https://example.com | hash",
  "include_report": true
}
```

### IP Scan
```
POST /api/v1/scan/ip
{
  "target": "8.8.8.8",
  "include_report": true
}
```

### URL Scan
```
POST /api/v1/scan/url
{
  "target": "https://example.com",
  "include_report": true
}
```

### File Hash Scan
```
POST /api/v1/scan/hash
{
  "target": "a1b2c3d4e5f6...",
  "include_report": true
}
```

### File Upload Scan
```
POST /api/v1/scan/file
Content-Type: multipart/form-data
file: [binary]
include_report: true
```

---

## 🔑 Required API Keys

| API | Purpose | Free Tier | Link |
|-----|---------|-----------|------|
| **VirusTotal** | File/URL scanning | 4 req/min | https://virustotal.com |
| **AbuseIPDB** | IP reputation | 1k/day | https://abuseipdb.com |
| **Shodan** | Port scanning | Limited | https://shodan.io |
| **Hybrid Analysis** | Malware analysis | 50/day | https://hybrid-analysis.com |
| **URLScan.io** | URL analysis | 100/day | https://urlscan.io |
| **Gemini** | AI reports (optional) | Free tier | https://ai.google.dev |

---

## 📊 Threat Levels

| Level | Meaning | Action |
|-------|---------|--------|
| **CLEAN** | Safe | No action needed |
| **SUSPICIOUS** | Warning | Review and proceed carefully |
| **MALICIOUS** | Dangerous | Avoid or take action |

---

## 🛠️ Configuration Files

### .env (Environment Variables)
```env
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
SHODAN_API_KEY=your_key
HYBRIDANALYSIS_API_KEY=your_key
URLSCAN_API_KEY=your_key
GEMINI_API_KEY=your_key  # Optional
```

### requirements.txt
```
fastapi==0.104.1
uvicorn==0.24.0
httpx==0.25.1
google-generativeai==0.3.0
reportlab==4.0.9
python-dotenv==1.0.0
```

---

## 💡 Common Tasks

### Test with curl
```bash
curl -X POST http://localhost:8000/api/v1/scan/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "8.8.8.8", "include_report": false}'
```

### Run tests
```bash
python test_threat_detection.py
```

### Check server status
```bash
curl http://localhost:8000/api/v1/scan/results/test
```

### Download PDF report
```python
import base64
pdf_hex = response_json['report']['data']
pdf_bytes = bytes.fromhex(pdf_hex)
with open('report.pdf', 'wb') as f:
    f.write(pdf_bytes)
```

---

## 🔍 Input Types Detected

| Type | Examples | APIs Used |
|------|----------|-----------|
| **IP** | 8.8.8.8, ::1 | AbuseIPDB, Shodan |
| **URL** | https://example.com | VirusTotal, URLScan |
| **Domain** | example.com | VirusTotal, URLScan |
| **Hash** | a1b2c3d4... (SHA256) | VirusTotal, Hybrid Analysis |

---

## 📁 Project Structure

```
server/
├── app/
│   ├── core/
│   │   ├── input_detector.py     (Type detection)
│   │   ├── threat_analyzer.py    (Main logic)
│   │   └── report_generator.py   (PDF generation)
│   ├── services/                 (API clients)
│   │   ├── shodan.py
│   │   ├── virus_total.py
│   │   ├── abuseipdb.py
│   │   ├── urlscan.py
│   │   └── hybrid_analysis.py
│   └── api/v1/endpoints/
│       └── scan.py               (REST endpoints)
├── .env.example
├── requirements.txt
├── IMPLEMENTATION_GUIDE.md
├── API_CONFIGURATION.md
├── IMPLEMENTATION_SUMMARY.md
└── test_threat_detection.py
```

---

## 🚨 Troubleshooting

| Issue | Solution |
|-------|----------|
| "API key not configured" | Set keys in .env file, restart server |
| "Connection refused" | Ensure server is running on port 8000 |
| "Timeout" | Check internet, verify API status |
| "Invalid response" | Check API key validity, review logs |
| "PDF not generated" | Install: `pip install reportlab google-generativeai` |

---

## 📚 Documentation

- **Full Guide**: `IMPLEMENTATION_GUIDE.md`
- **API Setup**: `API_CONFIGURATION.md`
- **Summary**: `IMPLEMENTATION_SUMMARY.md`
- **Tests**: `test_threat_detection.py`

---

## 🔐 Security Tips

1. ✅ Never commit `.env` file
2. ✅ Rotate API keys periodically
3. ✅ Use environment variables in production
4. ✅ Monitor API usage
5. ✅ Implement rate limiting
6. ✅ Use HTTPS in production

---

## ⚡ Performance

- Scan time: 3-15 seconds
- Parallel API calls via async/await
- Automatic timeout: 30 seconds per API
- Result caching: 300 seconds (configurable)

---

## 📞 Quick Support

### Check Logs
```bash
# View error messages
tail -f /path/to/logs
```

### Test Connectivity
```bash
# Test API connectivity
curl -I http://localhost:8000/api/v1/scan/results/test
```

### Validate Configuration
```python
from app.config import settings
print(settings.VIRUSTOTAL_API_KEY)  # Should not be empty
```

---

## 🎯 Next Steps

1. Copy `.env.example` to `.env`
2. Add API keys from each service
3. Run `python run_server.py`
4. Test with `python test_threat_detection.py`
5. Integrate with your frontend UI
6. Monitor API usage and quota

---

## 📝 Example Response

```json
{
  "scan_id": "SCAN_1234567890",
  "target": "8.8.8.8",
  "detected_type": "ip",
  "threat_level": "suspicious",
  "confidence": 0.65,
  "threats_detected": 2,
  "timestamp": "2025-01-15T10:30:45"
}
```

---

**Version**: 1.0.0 | **Status**: Production Ready | **Last Updated**: January 2025
