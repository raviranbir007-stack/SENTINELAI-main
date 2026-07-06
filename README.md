# SENTINEL-AI

SENTINEL-AI is a Python-based cybersecurity platform developed as a final-year project to demonstrate endpoint monitoring, threat intelligence enrichment, attack detection, and defensive response coordination.

## Problem Statement

Modern endpoints generate large volumes of security-relevant events, but many small organizations and student labs lack integrated tooling to correlate telemetry, enrich threats, and respond quickly. SENTINEL-AI addresses this gap by combining local monitoring, server-side analysis, and actionable dashboard visibility in one project.

## Key Features

- Real-time endpoint telemetry collection
- Multi-surface monitoring: process, file, network, DNS, USB, email, and behavior
- Threat intelligence enrichment via VirusTotal, AbuseIPDB, Shodan, URLScan, and Hybrid Analysis
- AI-assisted analysis and reporting workflows
- FastAPI-powered backend with dashboard and API endpoints
- Defensive orchestration for alerting and containment pipelines
- Security reporting and operational visibility

## Architecture Overview

1. Client modules collect host telemetry and suspicious activity signals.
2. Server APIs ingest and normalize events.
3. Core analysis components score and correlate threats.
4. Intelligence adapters enrich indicators with external context.
5. Defense components coordinate alerts and response actions.
6. Reporting modules generate technical and executive outputs.

## Technology Stack

- Language: Python 3.11+
- Backend: FastAPI, Uvicorn
- Database: SQLite (project runtime)
- Security tooling: Bandit, Gitleaks, custom IDS/IPS components
- Testing: Pytest and manual security validation scripts
- Integrations: VirusTotal, AbuseIPDB, Shodan, URLScan, Hybrid Analysis, Gemini

## Installation

1. Clone the repository and enter project root.
2. Create and activate a virtual environment.
3. Install dependencies.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements/server.txt
pip install -r requirements/client.txt
```

4. Prepare environment configuration.

```bash
cp .env.example .env
```

5. Add required API keys in `.env`.

## Usage

1. Start backend service:

```bash
source .venv/bin/activate
python server/run_server.py
```

2. Open local interfaces:
- Dashboard: http://localhost:8000
- API docs: http://localhost:8000/api/docs
- Health endpoint: http://localhost:8000/api/v1/health

3. Optional operational scripts:
- Full run helper: `scripts/run/run_complete_system.sh`
- Validation checks: `scripts/validation/`
- Security simulation scripts: `scripts/security/`

## Project Structure

```text
SENTINELAI-main/
|-- client/                 # Endpoint agent and scanner modules
|-- server/                 # FastAPI app, core logic, services, migrations
|-- tests/                  # Automated tests and manual validation scripts
|   |-- manual/             # Manual/instructor demonstration test scripts
|-- scripts/                # Run, setup, validation, and security helper scripts
|-- tools/                  # Utility tooling for development and packaging
|-- docs/                   # Supplemental project documentation
|-- requirements/           # Dependency sets by runtime profile
|-- README.md
|-- LICENSE
```

## Screenshots

Add screenshots in this section before final submission/public showcase.

- Dashboard overview
- Threat detection event feed
- Incident/alerts panel
- Report generation view

## Ethical Use and Disclaimer

This project is for defensive cybersecurity education and authorized testing only. Do not run attack simulations, scanning, or automated defensive controls against systems you do not own or do not have explicit permission to assess.

## Future Improvements

- Containerized deployment for reproducible environments
- Expanded SIEM integration and structured log export
- Role-based access controls and stronger audit trails
- More comprehensive unit and integration test coverage
- Threat model documentation and benchmarking dataset support

## License

This project is distributed under the license in [LICENSE](LICENSE).
