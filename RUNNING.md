## Running the SENTINELAI server (quick start)

Prerequisites:
- Python 3.11+ (a virtualenv is recommended)
- System packages for building wheels if you plan to install optional C-extensions

Steps (Linux):

1. Create and activate a virtualenv (if you don't already have `.venv`):

```bash
python -m venv .venv
source .venv/bin/activate
```

2. Install runtime dependencies for the server:

```bash
pip install -r server/requirements.txt
```

3. Copy example env and edit keys as needed:

```bash
cp server/.env.example server/.env
# Edit server/.env and add API keys if you want external scans and AI reports
```

4. Start the server (development):

```bash
uvicorn server.app.main:app --host 127.0.0.1 --port 8000 --reload
```

5. Health check:

```bash
curl http://127.0.0.1:8000/api/v1/health
```

Notes:
- Optional heavy ML packages (TensorFlow/PyTorch) are separated into `server/requirements-ml.txt` to avoid protobuf
  conflicts with cloud clients. Install those in a separate environment if needed.
- `asyncpg` is optional (only needed for async Postgres support); it may require a C toolchain to build.
- To enable real external scans and AI-generated PDF reports, populate the API keys in `server/.env`.
Setup and run instructions (minimal)

1) Create and activate a virtualenv

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2) Install server and client dependencies

```bash
pip install -r server/requirements.txt
pip install -r client/requirements.txt
```

3) Copy example env and edit API keys and secrets

```bash
cp .env.example .env
# Edit .env: set GEMINI_API_KEY, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY,
# SHODAN_API_KEY, HYBRIDANALYSIS_API_KEY, URLSCAN_API_KEY, DATABASE_URL, SECRET_KEY
```

4) Run tests (unit tests only; standalone test scripts are intentionally ignored by pytest)

```bash
python3 -m pytest -q
```

5) Start server (development)

```bash
python3 server/run_server.py
# or
uvicorn server.app.main:app --reload
```

6) Quick smoke check

```bash
curl -sS http://localhost:8000/api/v1/health | jq
```

Notes:
- `aiosqlite` is added to `server/requirements.txt` so the default sqlite URL works with SQLAlchemy async.
- If you want pytest to collect the async standalone scripts, install `pytest-asyncio` and remove the scripts from `conftest.py` ignore list.
- For full PDF + Gemini functionality install `reportlab` and `google-generativeai` and set `GEMINI_API_KEY`.

Optional ML extras (separate): heavy ML packages (TensorFlow, PyTorch) were moved to `server/requirements-ml.txt` to avoid dependency conflicts with `google-generativeai` (protobuf version constraints). Install them only when needed:

```bash
pip install -r server/requirements-ml.txt
```

Note: Installing `server/requirements-ml.txt` together with `google-generativeai` may still cause protobuf version conflicts; consider using a separate virtualenv/container if you need both on the same machine.
