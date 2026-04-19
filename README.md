# SENTINEL-AI

SENTINEL-AI is a Python-based security platform for endpoint monitoring, threat detection, defense orchestration, and operational reporting. It combines a local client, a server-side API and dashboard, and external threat-intelligence integrations into a single workflow for defensive security operations.

## Overview

The repository is organized around two primary components:

- `client/` contains the endpoint client and local scanning modules.
- `server/` contains the FastAPI backend, dashboard API, defense workflows, and reporting logic.

Supporting folders provide dependency manifests, automated tests, and operational utilities.

## Key Capabilities

- Real-time endpoint telemetry collection
- Intrusion detection and prevention orchestration
- Network, process, file, DNS, USB, email, and behavior monitoring
- Threat enrichment through VirusTotal, AbuseIPDB, URLScan, Shodan, and Hybrid Analysis
- AI-assisted analysis and reporting with Gemini support
- Dashboard and API endpoints for monitoring, defense, threats, and reports
- Rotating log files and health checks for operational visibility

## Architecture

1. The client agent collects endpoint telemetry and performs local scans.
2. The server receives data, applies analysis, and exposes dashboard and API workflows.
3. Threat-intelligence services enrich indicators with external context.
4. Defense modules coordinate alerting, blocking, and response actions.
5. Reporting modules generate operational and advanced security reports.

## Project Structure

- `client/sentinel_client_v3.py` is the main client entry point.
- `client/scanner/` contains the endpoint monitoring and scan engines.
- `server/run_server.py` is the integrated launcher.
- `server/app/main.py` defines the FastAPI application lifecycle.
- `server/app/api/v1/endpoints/` contains the public API surface.
- `server/app/core/` contains the detection, response, and reporting logic.
- `server/app/services/` contains external integration adapters.
- `tests/` contains the automated test suite.
- `tools/` contains helper scripts for validation and reporting.
- `requirements/` contains the dependency sets for different runtime targets.

## Quick Start

### 1. Create a virtual environment

```bash
cd /home/kali/Documents/SENTINELAI-main
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements/server.txt
pip install -r requirements/client.txt
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

Configure the required secrets and integrations in `.env`, including:

- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY`
- `SHODAN_API_KEY`
- `HYBRIDANALYSIS_API_KEY`
- `URLSCAN_API_KEY`

Optional values for AI and notifications can also be added, such as:

- `GEMINI_API_KEY`
- `SMTP_SERVER`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`
- `FROM_EMAIL`, `ALERT_EMAIL`, `CLIENT_REGISTRATION_ALERT_EMAILS`

### 3. Start the system

```bash
sudo /home/kali/Documents/SENTINELAI-main/.venv/bin/python /home/kali/Documents/SENTINELAI-main/server/run_server.py
```

Then open:

- Dashboard: `http://localhost:8000`
- API docs: `http://localhost:8000/api/docs`
- Health check: `http://localhost:8000/api/v1/health`

## Main API Areas

The API is grouped under the `/api/v1` prefix:

- `/auth` for authentication workflows
- `/scan` for scan submission and analysis
- `/threats` for findings and threat management
- `/dashboard` for status and summary views
- `/monitoring` for background monitor control
- `/network` for network defense operations
- `/defense` for response and containment actions
- `/reports` and `/advanced-reports` for standard and advanced reporting
- `/ai-prediction` and `/analyze` for AI-assisted analysis

## Testing

Run the main test suite from the repository root:

```bash
cd /home/kali/Documents/SENTINELAI-main
source .venv/bin/activate
pytest -q
```

Additional validation scripts are available in `tests/` and `tools/` for targeted checks.

## Operational Notes

- Logs are written to `logs/` with rotation enabled.
- The server can run with elevated host-level prevention controls when launched with the appropriate privileges.
- Admin infrastructure identity can be controlled through `ADMIN_INFRA_HOSTNAMES` and `ADMIN_INFRA_IPS` in `.env`.
- Keep environment files and API keys private; do not commit secrets to the repository.

## Contributing

1. Create a feature branch for the change.
2. Keep each commit focused and testable.
3. Run the relevant validation steps before opening a pull request.
4. Include clear technical notes and evidence of verification.

## Security Notice

SENTINEL-AI includes active monitoring and defensive controls. Use it only on systems you own or are explicitly authorized to test.
