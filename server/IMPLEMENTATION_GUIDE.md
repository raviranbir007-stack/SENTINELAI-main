# SENTINEL-AI Backend Implementation Guide

## Overview

The SENTINEL-AI backend now implements a comprehensive threat detection and analysis system using multiple security APIs. The system automatically detects input types and routes requests to appropriate threat detection APIs.

## Architecture

### Components

#### 1. **Input Type Detector** (`app/core/input_detector.py`)
Automatically identifies input type:
- **IPv4/IPv6**: IP addresses
- **URLs**: HTTP/HTTPS URLs
- **Domains**: Domain names
- **File Hashes**: MD5, SHA1, SHA256 hashes
- **Unknown**: Unrecognized format

#### 2. **Threat Analyzer** (`app/core/threat_analyzer.py`)
Orchestrates threat detection:
- Routes to correct APIs based on input type
- Handles API responses and errors
- Aggregates findings from multiple sources
- Calculates final threat verdict

#### 3. **Report Generator** (`app/core/report_generator.py`)
Creates professional PDF reports:
- Uses Google Gemini API for AI analysis
- Generates comprehensive threat reports
- Falls back to templated analysis if Gemini unavailable
- Returns PDF in downloadable format

#### 4. **API Services** (`app/services/`)
Enhanced service modules:
- `shodan.py` - IP reconnaissance and vulnerability detection
- `virus_total.py` - File and URL malware detection
- `abuseipdb.py` - IP abuse detection
- `urlscan.py` - URL analysis and phishing detection
- `hybrid_analysis.py` - File analysis and malware research

### API Routing by Input Type

| Input Type | APIs Used | Purpose |
|-----------|-----------|---------|
| **IP Address** | AbuseIPDB, Shodan | Attack detection, vulnerability discovery |
| **URL** | VirusTotal, URLScan.io | Phishing, malware, unsafe sites |
| **Domain** | VirusTotal, URLScan.io | Domain reputation, security threats |
| **File Hash** | VirusTotal, Hybrid Analysis | Malware detection, file analysis |

## Threat Verdict Calculation

The system returns one of three verdicts:

### CLEAN (Safe)
- No threats detected across all APIs
- Confidence: 90%+

### SUSPICIOUS (Warning)
- Multiple medium-severity threats detected
- OR at least one medium threat + supporting evidence
- Confidence: 40-60%

### MALICIOUS (Dangerous)
- One or more critical threats detected
- High confidence from security databases
- Confidence: 70%+

## API Endpoints

### 1. Universal Scan (Recommended)
```
POST /api/v1/scan/scan
Content-Type: application/json

{
    "target": "192.168.1.1 | example.com | https://example.com | a1b2c3d4e5...",
    "include_report": true
}
```

**Response:**
```json
{
    "scan_id": "SCAN_1234567890",
    "target": "192.168.1.1",
    "detected_type": "ip",
    "status": "complete",
    "threat_level": "suspicious",
    "confidence": 0.65,
    "threats_detected": 2,
    "analysis": {
        "input": "192.168.1.1",
        "input_type": "ip",
        "verdict": "suspicious",
        "confidence": 0.65,
        "threat_indicators": [...],
        "api_results": {...}
    },
    "report": {
        "format": "pdf",
        "size": 15234,
        "data": "hex_encoded_pdf_data"
    },
    "timestamp": "2025-01-15T10:30:45.123456"
}
```

### 2. IP Scan
```
POST /api/v1/scan/ip
{
    "target": "192.168.1.1",
    "include_report": false
}
```

### 3. URL Scan
```
POST /api/v1/scan/url
{
    "target": "https://example.com",
    "include_report": false
}
```

### 4. File Hash Scan
```
POST /api/v1/scan/hash
{
    "target": "a1b2c3d4e5f6...",
    "include_report": false
}
```

### 5. File Upload Scan
```
POST /api/v1/scan/file
Content-Type: multipart/form-data

file: [binary_file]
include_report: true
```

## Setup Instructions

### 1. Install Dependencies

```bash
# Core dependencies
pip install fastapi uvicorn httpx pydantic

# AI Report Generation
pip install google-generativeai reportlab

# Optional: For production
pip install python-multipart aiofiles
```

### 2. Configure Environment Variables

Create a `.env` file in the `server/` directory:

```env
# Threat Detection APIs
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
SHODAN_API_KEY=your_shodan_key
HYBRIDANALYSIS_API_KEY=your_hybrid_analysis_key
URLSCAN_API_KEY=your_urlscan_key

# AI Report Generation
GEMINI_API_KEY=your_google_gemini_key

# Other settings
SECRET_KEY=your-secret-key
DATABASE_URL=sqlite:///./test.db
```

### 3. Obtain API Keys

#### VirusTotal
1. Visit https://www.virustotal.com
2. Register or login
3. Go to Settings → API key
4. Copy your API key

#### AbuseIPDB
1. Visit https://www.abuseipdb.com
2. Register or login
3. Go to Account → API
4. Copy your API key

#### Shodan
1. Visit https://www.shodan.io
2. Register or login
3. Go to Account → API
4. Copy your API key

#### Hybrid Analysis
1. Visit https://www.hybrid-analysis.com
2. Register or login
3. Go to Settings → API → API Key
4. Copy your API key

#### URLScan.io
1. Visit https://urlscan.io
2. Register or login
3. Go to Settings → API
4. Copy your API key

#### Google Gemini (Optional for AI Reports)
1. Visit https://ai.google.dev
2. Click "Get API key"
3. Create a new API key
4. Copy the key

### 4. Run the Server

```bash
cd server
python run_server.py
```

The server will start on `http://localhost:8000`

## Usage Examples

### Example 1: Scan an IP Address

```bash
curl -X POST http://localhost:8000/api/v1/scan/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "8.8.8.8",
    "include_report": true
  }'
```

### Example 2: Scan a URL

```bash
curl -X POST http://localhost:8000/api/v1/scan/url \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "include_report": true
  }'
```

### Example 3: Upload and Scan a File

```bash
curl -X POST http://localhost:8000/api/v1/scan/file \
  -F "file=@/path/to/file.exe" \
  -F "include_report=true"
```

### Example 4: Scan a File Hash

```bash
curl -X POST http://localhost:8000/api/v1/scan/hash \
  -H "Content-Type: application/json" \
  -d '{
    "target": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "include_report": true
  }'
```

## Response Format

All scan endpoints return a consistent format:

```json
{
    "scan_id": "unique_scan_identifier",
    "target": "scanned_input",
    "detected_type": "ip|url|domain|file_hash",
    "status": "complete|in_progress|failed",
    "threat_level": "clean|suspicious|malicious",
    "confidence": 0.0-1.0,
    "threats_detected": 0-n,
    "analysis": {
        "input": "original_input",
        "input_type": "detected_type",
        "timestamp": "ISO8601_timestamp",
        "verdict": "clean|suspicious|malicious",
        "confidence": 0.0-1.0,
        "summary": "human_readable_summary",
        "threat_indicators": [
            {
                "source": "API_name",
                "severity": "critical|medium|low",
                "indicator": "threat_description"
            }
        ],
        "api_results": {
            "apis_called": ["API1", "API2"],
            "api_name": { "raw_response": "..." }
        }
    },
    "report": {
        "format": "pdf",
        "size": 12345,
        "data": "hex_encoded_pdf"
    },
    "timestamp": "ISO8601_timestamp"
}
```

## Error Handling

The system handles various error scenarios:

1. **Invalid Input**: Returns 400 Bad Request with details
2. **API Unavailable**: Continues with available APIs, marks as unavailable
3. **File Too Large**: Returns 413 Payload Too Large
4. **Server Error**: Returns 500 Internal Server Error

## Logging

Logs are written to the console and can be configured in `app/config.py`:

```python
import logging
logger = logging.getLogger(__name__)
logger.info("Information message")
logger.warning("Warning message")
logger.error("Error message")
```

## Performance Considerations

### Async Operations
- All API calls are async (non-blocking)
- Multiple APIs can be called in parallel
- Typical scan time: 3-15 seconds depending on API response times

### Rate Limiting
- Default: 60 requests per minute (configurable)
- Set via `RATE_LIMIT_PER_MINUTE` environment variable
- Implement token bucket algorithm for fairness

### Caching
- API responses cached for `API_CACHE_TTL` seconds (default: 300)
- Reduces API quota usage
- Set via `API_CACHE_TTL` environment variable

## Security Best Practices

1. **API Keys**: Store in `.env`, never commit to version control
2. **HTTPS**: Use HTTPS in production
3. **Rate Limiting**: Implement API rate limiting
4. **Input Validation**: All inputs are validated before processing
5. **Error Messages**: Don't expose sensitive details in error responses

## Troubleshooting

### "API key not configured" Error
- Ensure `.env` file exists in `server/` directory
- Check environment variable names match exactly
- Restart the server after updating `.env`

### "Timeout" Error
- Check internet connection
- Verify API endpoint URLs are correct
- Increase timeout value if needed
- Check API service status

### "Invalid API Response" Error
- Verify API key is valid
- Check API quota/rate limits
- Ensure input format is correct
- Check API documentation for response changes

## Future Enhancements

1. **Database Integration**: Store scan results for history
2. **Scan Scheduling**: Schedule periodic scans
3. **Webhooks**: Send results to external systems
4. **Custom Rules**: User-defined threat detection rules
5. **Machine Learning**: Train models on historical data
6. **Dashboard**: Web UI for scan management
7. **Multi-language Support**: Reports in multiple languages

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review API documentation
3. Check system logs
4. Contact support team

---

**Version**: 1.0.0  
**Last Updated**: January 2025  
**Maintained by**: SENTINEL-AI Team
