#!/usr/bin/env python3
import asyncio
from pathlib import Path

print("=" * 80)
print("COMPREHENSIVE SYSTEM CHECK")
print("=" * 80)

# Check 1: Environment and Dependencies
print("\n✅ [1] PYTHON ENVIRONMENT & DEPENDENCIES")
import sys
print(f"  • Python version: {sys.version.split()[0]}")
print(f"  • Python executable: {sys.executable}")

try:
    import server.app
    print(f"  • App module: ✅")
except ImportError as e:
    print(f"  • App module: ❌ {e}")

# Check 2: Configuration
print("\n✅ [2] CONFIGURATION FILES")
config_files = [
    ".env",
    "server/app/config.py",
    "client/config.ini",
    ".env.example"
]
for cf in config_files:
    p = Path(cf)
    status = "✅" if p.exists() else "⚠️ (missing)"
    print(f"  • {cf}: {status}")

# Check 3: Database
print("\n✅ [3] DATABASE FILES")
db_files = [
    "server/sentinel.db",
    "server/activity_monitoring.db",
    "activity_logs.db"
]
for db in db_files:
    p = Path(db)
    size_mb = f"{p.stat().st_size / (1024*1024):.2f}MB" if p.exists() else "N/A"
    status = "✅" if p.exists() else "⚠️ (missing)"
    print(f"  • {db}: {status} ({size_mb})")

# Check 4: Log Files
print("\n✅ [4] LOG FILES")
log_files = [
    "logs/protection.log",
    "logs/security.log",
]
for log in log_files:
    p = Path(log)
    lines = len(p.read_text().split('\n')) if p.exists() else 0
    status = "✅" if p.exists() else "⚠️ (missing)"
    print(f"  • {log}: {status} ({lines} lines)")

# Check 5: Critical Modules
print("\n✅ [5] CRITICAL MODULES")
modules = [
    "server.app.core.threat_analyzer",
    "server.app.core.report_generator",
    "server.app.core.activity_database",
    "server.app.core.terminal_monitor",
    "server.app.ai_engine.analyzer",
]
for mod in modules:
    try:
        __import__(mod)
        print(f"  • {mod}: ✅")
    except ImportError as e:
        print(f"  • {mod}: ❌ {str(e)[:60]}")

# Check 6: API Endpoints
print("\n✅ [6] API ENDPOINTS")
endpoints = [
    "server.app.api.v1.endpoints.scan",
    "server.app.api.v1.endpoints.dashboard",
    "server.app.api.v1.endpoints.network_defense",
    "server.app.api.v1.endpoints.reports",
    "server.app.api.compat",
]
for ep in endpoints:
    try:
        __import__(ep)
        print(f"  • {ep}: ✅")
    except ImportError as e:
        print(f"  • {ep}: ❌ {str(e)[:60]}")

# Check 7: Frontend Assets
print("\n✅ [7] FRONTEND ASSETS")
frontend_files = [
    "server/app/static/index.html",
    "server/app/static/style.css",
    "server/app/static/main.js",
]
for ff in frontend_files:
    p = Path(ff)
    size_kb = f"{p.stat().st_size / 1024:.1f}KB" if p.exists() else "N/A"
    status = "✅" if p.exists() else "⚠️ (missing)"
    print(f"  • {ff}: {status} ({size_kb})")

# Check 8: Critical Directories
print("\n✅ [8] CRITICAL DIRECTORIES")
dirs = [
    "server/app",
    "server/app/api/v1/endpoints",
    "server/app/core",
    "server/app/ai_engine",
    "client/scanner",
    "logs",
    "generated_reports",
]
for d in dirs:
    p = Path(d)
    num_files = len(list(p.glob("**/*"))) if p.exists() else 0
    status = "✅" if p.exists() else "⚠️ (missing)"
    print(f"  • {d}: {status} ({num_files} items)")

print("\n" + "=" * 80)
print("✅ ALL CHECKS COMPLETE")
print("=" * 80)
