# SENTINEL-AI Development Notes

## Development Environment Setup

### Virtual Environment
```bash
# Create virtualenv
python3 -m venv .venv

# Activate
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows

# Deactivate
deactivate
```

### Dependencies

#### Core Dependencies (Minimal Mode)
- **FastAPI**: Web framework
- **Uvicorn**: ASGI server
- **Pydantic**: Data validation
- **SQLAlchemy**: ORM
- **Google GenAI**: AI analysis (optional)
- **ReportLab**: PDF generation
- **Requests/HTTPX**: HTTP clients
- **Python-dotenv**: Environment management

#### ML Dependencies (Optional)
- **NumPy**: Not required in minimal mode
- ML models work with rule-based fallbacks

### Installation Order

1. **Base Installation**
   ```bash
   pip install -r server/requirements.txt
   ```

2. **Verify Installation**
   ```bash
   PYTHONPATH=. .venv/bin/python tools/check_imports.py
   ```

3. **Optional: Install ML Dependencies** (only if storage permits)
   ```bash
   pip install numpy pandas scikit-learn
   ```

## Architecture

### Backend Structure
```
server/
├── app/
│   ├── main.py              # FastAPI application entry point
│   ├── config.py            # Configuration management
│   ├── gemini_config.py     # Gemini AI configuration
│   ├── gemini_integration.py # Gemini AI integration
│   ├── ml_models.py         # Local ML models (minimal mode)
│   ├── anomaly_detector.py  # Anomaly detection
│   │
│   ├── api/v1/              # API v1 endpoints
│   │   ├── endpoints/
│   │   │   ├── auth.py      # Authentication
│   │   │   ├── scan.py      # Scan operations
│   │   │   ├── threats.py   # Threat management
│   │   │   ├── dashboard.py # Dashboard data
│   │   │   └── reports.py   # Report generation
│   │
│   ├── core/                # Core business logic
│   │   ├── scanner.py
│   │   ├── threat_analyzer.py
│   │   ├── report_generator.py
│   │   ├── input_detector.py
│   │   └── notifier.py
│   │
│   ├── services/            # External API integrations
│   │   ├── virus_total.py
│   │   ├── abuseipdb.py
│   │   ├── shodan.py
│   │   ├── hybrid_analysis.py
│   │   └── urlscan.py
│   │
│   └── static/              # Frontend files
│       ├── index.html
│       ├── js/
│       │   ├── api.js       # API client
│       │   └── dashboard.js # Dashboard logic
│       └── css/
```

### Frontend Structure
- **Framework**: Vanilla JavaScript (no build step required)
- **Styling**: CSS with custom properties
- **API Communication**: Fetch API
- **Dashboard**: Real-time updates via polling

## API Endpoints

### Health & Status
- `GET /api/v1/health` - Health check
- `GET /api/v1/config/gemini` - Gemini configuration status

### Scanning
- `POST /api/v1/scan/file` - Scan uploaded file
- `POST /api/v1/scan/url` - Scan URL
  - Body: `{"target": "https://example.com"}`
- `POST /api/v1/scan/ip` - Scan IP address
  - Body: `{"target": "8.8.8.8"}`
- `POST /api/v1/scan/hash` - Scan file hash
  - Body: `{"target": "sha256_hash"}`
- `POST /api/v1/scan/scan` - Universal scan (auto-detect type)
  - Body: `{"target": "auto_detected_input"}`
- `GET /api/v1/scan/results/{scan_id}` - Get scan results

### Dashboard
- `GET /api/v1/dashboard/summary` - Dashboard summary
- `GET /api/v1/dashboard/threats` - Recent threats
- `GET /api/v1/dashboard/stats` - Statistics

### Threats
- `GET /api/v1/threats` - List all threats
- `GET /api/v1/threats/{threat_id}` - Threat details
- `POST /api/v1/threats/scan-ip` - Quick IP scan
- `POST /api/v1/threats/{threat_id}/respond` - Respond to threat

### Reports
- `POST /api/v1/reports/generate` - Generate report
- `GET /api/v1/reports/download/{report_id}` - Download PDF report

## Configuration

### Environment Variables

#### Required
```bash
# API Keys
GEMINI_API_KEY=your_gemini_key
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
SHODAN_API_KEY=your_shodan_key
HYBRID_ANALYSIS_API_KEY=your_hybrid_key
URLSCAN_API_KEY=your_urlscan_key
```

#### Optional
```bash
# Gemini Configuration
GEMINI_MODEL=gemini-1.5-pro
GEMINI_TEMPERATURE=0.7
GEMINI_MAX_TOKENS=1000
GEMINI_ENABLED=true
GEMINI_MAX_ATTEMPTS=4

# Circuit Breaker
GEMINI_CIRCUIT_THRESHOLD=6
GEMINI_CIRCUIT_OPEN_SECONDS=300

# Server
API_PORT=8000
HOST=0.0.0.0
DEBUG=false
```

## Development Workflow

### Running the Server

#### Development Mode (with auto-reload)
```bash
PYTHONPATH=server .venv/bin/uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

#### Production Mode
```bash
PYTHONPATH=server .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Testing

#### Run All Tests
```bash
.venv/bin/python -m pytest
```

#### Run Specific Tests
```bash
# Test imports
PYTHONPATH=. .venv/bin/python tools/check_imports.py

# Test report generation
PYTHONPATH=. .venv/bin/python tools/test_report.py

# Test endpoints
PYTHONPATH=. .venv/bin/python tools/test_endpoints.py

# Test API directly
PYTHONPATH=. .venv/bin/python server/test_api_all.py
```

#### Test Dashboard Buttons
```bash
# Start server first
PYTHONPATH=server .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 &

# Test IP scan
curl -X POST http://127.0.0.1:8000/api/v1/scan/ip \
  -H "Content-Type: application/json" \
  -d '{"target":"8.8.8.8"}'

# Test URL scan
curl -X POST http://127.0.0.1:8000/api/v1/scan/url \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com"}'

# Test file upload
curl -X POST http://127.0.0.1:8000/api/v1/scan/file \
  -F "file=@/path/to/test/file.txt"
```

## Troubleshooting

### Common Issues

#### 1. Import Errors
```bash
# Check all imports
PYTHONPATH=. .venv/bin/python tools/check_imports.py

# Common fix: Ensure PYTHONPATH is set
export PYTHONPATH=server
```

#### 2. Port Already in Use
```bash
# Kill existing server
pkill -f "uvicorn app.main:app"

# Or find and kill specific process
lsof -ti:8000 | xargs kill -9
```

#### 3. Module Not Found
```bash
# Reinstall dependencies
pip install -r server/requirements.txt

# Check Python path
python -c "import sys; print('\n'.join(sys.path))"
```

#### 4. Gemini API Quota Errors (429)
- Circuit breaker will activate after 6 failures
- Falls back to local analysis automatically
- Reset by restarting server or waiting for timeout

#### 5. Database Errors
```bash
# Reset database (development only)
rm -f server/sentinel.db
# Server will recreate on next start
```

### Dashboard Button Issues

If buttons don't work:
1. Check browser console for JavaScript errors
2. Verify server is running: `curl http://127.0.0.1:8000/api/v1/health`
3. Check API endpoint alignment in `static/js/api.js`
4. Verify CORS is enabled in `main.py`

## Storage Optimization

### Minimal Mode (Current Setup)
- No NumPy or heavy ML dependencies
- Uses rule-based analysis fallbacks
- Total installation: ~500MB

### Full Mode (Optional)
If storage permits, install:
```bash
pip install numpy pandas scikit-learn tensorflow
```
Requires: ~2-3GB additional storage

## Git Workflow

### Commit and Push
```bash
# Stage changes
git add -A

# Commit with descriptive message
git commit -m "feat: add new feature"

# Push to GitHub
git push origin main
```

### Fixing Email Privacy Issues
```bash
git config user.email "username@users.noreply.github.com"
git commit --amend --reset-author --no-edit
git push origin main --force
```

## Performance Tips

1. **Use workers in production**
   ```bash
   uvicorn app.main:app --workers 4
   ```

2. **Enable caching**
   - Gemini responses cached for 5 minutes
   - API results cached per configuration

3. **Rate limiting**
   - Configured in `gemini_config.py`
   - Default: 60 requests per minute

4. **Background tasks**
   - Use FastAPI BackgroundTasks for heavy operations
   - Async endpoints for I/O operations

## Security Considerations

1. **API Keys**
   - Never commit `.env` file
   - Use `.env.example` as template
   - Rotate keys regularly

2. **CORS**
   - Configured for local development
   - Restrict origins in production

3. **Input Validation**
   - All inputs validated via Pydantic models
   - Sanitized before processing

4. **Rate Limiting**
   - Implement rate limiting middleware
   - Configure per-endpoint limits

## Deployment

### Production Checklist
- [ ] Set `DEBUG=false` in environment
- [ ] Configure proper CORS origins
- [ ] Use HTTPS/SSL certificates
- [ ] Set up reverse proxy (nginx)
- [ ] Configure firewall rules
- [ ] Set up monitoring/logging
- [ ] Configure database backups
- [ ] Set up auto-restart on failure

### Systemd Service (Linux)
```ini
[Unit]
Description=SENTINEL-AI API Server
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/sentinel-ai
Environment="PYTHONPATH=/opt/sentinel-ai/server"
ExecStart=/opt/sentinel-ai/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always

[Install]
WantedBy=multi-user.target
```

## Maintenance

### Regular Tasks
1. **Update dependencies** (monthly)
   ```bash
   pip install --upgrade -r server/requirements.txt
   ```

2. **Check for security updates**
   ```bash
   pip-audit
   ```

3. **Clean old logs** (weekly)
   ```bash
   find logs/ -mtime +7 -delete
   ```

4. **Monitor disk space**
   ```bash
   df -h
   ```

## Support & Documentation

- **API Docs**: http://127.0.0.1:8000/docs (when server running)
- **GitHub**: https://github.com/raviranbir007-stack/SENTINELAI-main
- **Issues**: Use GitHub Issues for bug reports

## Version History

- **v2.0.0** (2025-12-28)
  - Fixed critical syntax errors
  - Updated dashboard button functionality
  - Aligned API endpoints
  - Added minimal ML mode
  - Improved documentation

- **v1.0.0** (Initial Release)
  - Basic threat scanning
  - Dashboard interface
  - Multi-API integration
