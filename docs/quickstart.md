# SENTINEL-AI Quickstart

This guide provides the minimum steps to run SENTINEL-AI for demonstration and evaluation.

## 1) Environment Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements/server.txt
pip install -r requirements/client.txt
```

## 2) Configure Secrets

```bash
cp .env.example .env
```

Populate required keys in `.env`:

- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY`
- `SHODAN_API_KEY`
- `HYBRIDANALYSIS_API_KEY`
- `URLSCAN_API_KEY`

## 3) Run the Server

```bash
source .venv/bin/activate
python server/run_server.py
```

## 4) Access the Platform

- Dashboard: http://localhost:8000
- API docs: http://localhost:8000/api/docs
- Health check: http://localhost:8000/api/v1/health

## 5) Optional Utility Scripts

- Full stack runner: `scripts/run/run_complete_system.sh`
- Setup helpers: `scripts/setup/`
- Validation helpers: `scripts/validation/`
- Security simulation scripts: `scripts/security/`

## 6) Testing

```bash
pytest -q
```

Manual validation scripts are available under `tests/manual/`.

## Ethical Notice

Use attack simulation scripts only in isolated labs or environments where you have explicit authorization.
