# SENTINEL-AI: AI-Powered Threat Detection System

## Overview
SENTINEL-AI is a comprehensive threat detection and response system that combines AI/ML analysis with multiple security APIs to provide real-time threat intelligence.

## Project Structure

```
SENTINEL-AI-SYSTEM/
├── server/                      # Central Dashboard Server
│   ├── app/
│   │   ├── main.py             # FastAPI server
│   │   ├── config.py           # Configuration
│   │   ├── database.py         # Database setup
│   │   ├── models.py           # SQLAlchemy models
│   │   ├── auth.py             # Authentication
│   │   ├── api/
│   │   │   ├── v1/
│   │   │   │   ├── endpoints/
│   │   │   │   │   ├── auth.py
│   │   │   │   │   ├── scan.py
│   │   │   │   │   ├── threats.py
│   │   │   │   │   └── dashboard.py
│   │   │   │   └── api.py
│   │   ├── services/           # API integrations
│   │   │   ├── virus_total.py
│   │   │   ├── abuseipdb.py
│   │   │   ├── shodan.py
│   │   │   ├── hybrid_analysis.py
│   │   │   └── urlscan.py
│   │   ├── ai_engine/          # AI/ML analysis
│   │   │   ├── analyzer.py
│   │   │   ├── predictor.py
│   │   │   └── models/
│   │   ├── core/               # Core logic
│   │   │   ├── scanner.py
│   │   │   └── notifier.py
│   │   └── static/             # Dashboard frontend
│   │       ├── index.html
│   │       ├── css/
│   │       ├── js/
│   │       └── dashboard.js
│   ├── requirements.txt
│   ├── .env.example
│   └── run_server.py
├── client/                     # Client Python Script
│   ├── sentinel_client.py
│   ├── scanner/
│   │   ├── file_scanner.py
│   │   ├── network_scanner.py
│   │   ├── process_scanner.py
│   │   └── system_info.py
│   ├── utils/
│   │   ├── helpers.py
│   │   └── validator.py
│   ├── requirements.txt
│   └── config.ini.example
├── database/                   # Database files
├── logs/                      # System logs
├── docs/                      # Documentation
└── README.md
```

## Features

### Server
- **FastAPI Backend**: Modern, fast Python web framework
- **Authentication**: Secure user authentication and authorization
- **API Integrations**: VirusTotal, AbuseIPDB, Shodan, Hybrid Analysis, URLScan
- **AI/ML Engine**: Advanced threat analysis and prediction
- **Real-time Dashboard**: Monitor threats in real-time
- **Database**: SQLAlchemy ORM with PostgreSQL support

### Client
- **File Scanning**: Analyze files for threats
- **Network Scanning**: Monitor network for suspicious activity
- **Process Monitoring**: Track running processes
- **System Information**: Gather system details
- **Real-time Reporting**: Send data to server

## Setup

### Server Setup
1. Clone the repository
2. Navigate to the server directory
3. Create virtual environment: `python -m venv venv`
4. Activate virtual environment
5. Install dependencies: `pip install -r requirements.txt`
6. Copy `.env.example` to `.env` and configure
7. Run server: `python run_server.py`

### Client Setup
1. Navigate to the client directory
2. Create virtual environment: `python -m venv venv`
3. Activate virtual environment
4. Install dependencies: `pip install -r requirements.txt`
5. Copy `config.ini.example` to `config.ini` and configure
6. Run client: `python sentinel_client.py`

## API Endpoints

### Authentication
- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - Login user
- `POST /api/v1/auth/logout` - Logout user

### Scanning
- `POST /api/v1/scan/file` - Scan file
- `POST /api/v1/scan/url` - Scan URL
- `GET /api/v1/scan/results/{scan_id}` - Get scan results

### Threats
- `GET /api/v1/threats` - Get all threats
- `GET /api/v1/threats/{threat_id}` - Get threat details
- `POST /api/v1/threats/{threat_id}/respond` - Respond to threat

### Dashboard
- `GET /api/v1/dashboard/summary` - Get dashboard summary
- `GET /api/v1/dashboard/threats` - Get threats
- `GET /api/v1/dashboard/stats` - Get statistics

## Configuration

### Server .env Variables
```
DEBUG=True
PROJECT_NAME=SENTINEL-AI
VERSION=1.0.0
API_V1_PREFIX=/api/v1

# API Keys
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
SHODAN_API_KEY=your_key
HYBRIDANALYSIS_API_KEY=your_key
URLSCAN_API_KEY=your_key

# Database
DATABASE_URL=sqlite:///./test.db
REDIS_URL=redis://localhost:6379

# Security
SECRET_KEY=your-secret-key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

## Technologies Used

- **Backend**: FastAPI, SQLAlchemy, Pydantic
- **Database**: PostgreSQL/SQLite
- **Cache**: Redis
- **Authentication**: JWT
- **AI/ML**: scikit-learn, TensorFlow, PyTorch
- **Frontend**: HTML5, CSS3, JavaScript
- **Task Queue**: Celery

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, email support@sentinel-ai.com or open an issue on GitHub.

## Roadmap

- [ ] Advanced ML models for threat prediction
- [ ] Real-time log analysis
- [ ] Automated response actions
- [ ] Integration with SIEM systems
- [ ] Mobile application
- [ ] Threat intelligence sharing
