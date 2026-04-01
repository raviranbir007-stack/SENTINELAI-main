# SENTINEL-AI

Unified IDS/IPS and monitoring system written in Python.

## Features

- Real-time intrusion detection and prevention
- Browser activity monitoring (Firefox, Chrome, Edge, Safari, etc.)
- Operating system log monitoring (syslog/journal) with database storage and callbacks
- Accurate browser monitoring even when server is run with sudo (detects real user home directory)
- Persistent file logging (logs/protection.log) for audit and troubleshooting
- Automatic traffic analysis and artifact scanning
- Cross-platform support (Linux, macOS, Windows fallback)
- Quarantine and alerting mechanisms

## Quick start

Run the integrated system:

```bash
sudo python3 server/run_server.py
```

Or use provided shell scripts (`START.sh`, `run_complete_system.sh`).

See documentation files for additional configuration notes.

## Email Alerts and Client-Safe API Mode

Set these in `server/.env`:

```env
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-gmail@gmail.com
SMTP_PASSWORD=your-gmail-app-password
FROM_EMAIL=alerts@sentinel-ai.com
ALERT_EMAIL=your-gmail@gmail.com
CLIENT_REGISTRATION_ALERT_EMAILS=soc@example.com,sec-lead@example.com

SENTINEL_CLIENT_SAFE_DASHBOARD_MODE=true
SENTINEL_ADMIN_BYPASS_KEY=replace-with-long-random-secret
```

- `ALERT_EMAIL` receives core security alerts.
- `CLIENT_REGISTRATION_ALERT_EMAILS` receives "new client registered" notifications (deduplicated automatically).
- In client-safe mode, admin management routes are blocked unless header `X-Sentinel-Admin-Bypass` matches `SENTINEL_ADMIN_BYPASS_KEY`.
- To force your current server OS to be treated as admin (not client), set `ADMIN_INFRA_HOSTNAMES` and/or `ADMIN_INFRA_IPS` in `server/.env`.

## Testing and Diagnostics

- **Browser activity**: refer to `BROWSER_MONITORING.md` for tips when running as root.
- **API connectivity**: run `python3 test_services_api.py` to verify that VirusTotal, AbuseIPDB, URLScan, Shodan and Hybrid Analysis are reachable and returning results.
- **Monitoring simulation**: use the demo snippet in `BROWSER_MONITORING.md` or simply open a website while the server is running and watch the console/logs.

## Main Client Entry Point

**Use only `client/sentinel_client_v3.py` as the main entry point for all client deployments.**

All other client files (`sentinel_client.py`, `sentinel_client_enhanced.py`, `sentinel_integrated_protection.py`, `sentinel_realtime_protection.py`, `sentinel_automated.py`) are now deprecated and retained for legacy reference only. All new development, deployment, and integration should use `sentinel_client_v3.py`.

For specialized or legacy use cases, review the deprecated files for reference, but do not use them as the main client.
