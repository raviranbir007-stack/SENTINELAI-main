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

## Testing and Diagnostics

- **Browser activity**: refer to `BROWSER_MONITORING.md` for tips when running as root.
- **API connectivity**: run `python3 test_services_api.py` to verify that VirusTotal, AbuseIPDB, URLScan, Shodan and Hybrid Analysis are reachable and returning results.
- **Monitoring simulation**: use the demo snippet in `BROWSER_MONITORING.md` or simply open a website while the server is running and watch the console/logs.
