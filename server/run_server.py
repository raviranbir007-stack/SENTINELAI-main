#!/usr/bin/env python
"""
SENTINEL-AI Unified Launcher
Starts both server AND integrated protection client automatically
Single command to start complete IDS/IPS/Monitoring system
"""
import logging
import logging.handlers
import multiprocessing
import os
import signal
import sys
import time
from pathlib import Path

# Ensure we run with the project venv interpreter when available (important for Gemini deps)
def _reexec_with_venv_if_needed():
    try:
        project_root = Path(__file__).parent.parent
        venv_python = project_root / ".venv" / "bin" / "python"

        if venv_python.exists() and os.path.realpath(sys.executable) != os.path.realpath(venv_python):
            os.execv(str(venv_python), [str(venv_python)] + sys.argv)

        # If re-exec didn't happen and venv exists, force exit to avoid using system Python
        if venv_python.exists() and os.path.realpath(sys.executable) != os.path.realpath(venv_python):
            print("❌ This server must run with the project venv interpreter.")
            print(f"   Expected: {venv_python}")
            print(f"   Current : {sys.executable}")
            print("   Run: sudo /home/kali/Documents/SENTINELAI-main/.venv/bin/python /home/kali/Documents/SENTINELAI-main/server/run_server.py")
            sys.exit(1)
    except Exception:
        # If anything goes wrong, continue with current interpreter
        return

_reexec_with_venv_if_needed()

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Preserve Gemini quota by skipping startup tests
os.environ.setdefault("SKIP_GEMINI_STARTUP_TESTS", "true")
# Integrated launcher should explicitly enable background monitoring
os.environ.setdefault("SENTINEL_ENABLE_STARTUP_MONITORS", "true")

import uvicorn

# Setup logging - CLEAN CONSOLE + DETAILED FILE
root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)

# Console handler: ONLY important messages (sentinel alerts, detections, errors)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)

# Reduce console noise from verbose internal modules (keep file logs intact)
class ConsoleNoiseFilter(logging.Filter):
    noisy_prefixes = (
        "app.activity_monitor",
        "app.services.",
        "app.gemini_integration",
        "google_genai",
        "app.api.v1.endpoints.advanced_reports",
    )

    def filter(self, record: logging.LogRecord) -> bool:
        if record.name.startswith(self.noisy_prefixes):
            return False
        return True

console_handler.addFilter(ConsoleNoiseFilter())
console_formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
console_handler.setFormatter(console_formatter)

# File handler: ALL debug messages for troubleshooting
log_dir = Path(__file__).parent.parent / "logs"
try:
    log_dir.mkdir(exist_ok=True)
    file_handler = logging.handlers.RotatingFileHandler(
        log_dir / "protection.log", maxBytes=5 * 1024 * 1024, backupCount=3
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(name)s - %(message)s"))
    root_logger.addHandler(file_handler)
except Exception:
    pass

root_logger.addHandler(console_handler)

# Suppress VERY verbose loggers entirely (set to CRITICAL so they never appear)
logging.getLogger('sqlalchemy.engine').setLevel(logging.CRITICAL)
logging.getLogger('sqlalchemy.engine.Engine').setLevel(logging.CRITICAL)
logging.getLogger('sqlalchemy.pool').setLevel(logging.CRITICAL)
logging.getLogger('sqlalchemy.dialects.postgresql.psycopg2').setLevel(logging.CRITICAL)
logging.getLogger('httpx').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)
logging.getLogger('urllib3.connectionpool').setLevel(logging.CRITICAL)
logging.getLogger('asyncio').setLevel(logging.CRITICAL)
logging.getLogger('uvicorn').setLevel(logging.WARNING)  # Only show uvicorn errors
logging.getLogger('uvicorn.access').setLevel(logging.CRITICAL)  # NO access logs on console

logger = logging.getLogger(__name__)
if log_dir.exists():
    logger.info(f"Logging to file: {log_dir / 'protection.log'}")

from app.config import settings

# Global process references
server_process = None
client_process = None


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    # Avoid logging during multiprocessing to prevent reentrant errors
    print("\n🛑 Shutdown signal received, stopping all components...")
    
    global client_process, server_process
    
    try:
        if client_process is not None and hasattr(client_process, 'is_alive') and client_process.is_alive():
            print("Stopping protection client...")
            client_process.terminate()
            client_process.join(timeout=5)
    except Exception as e:
        pass  # Silently handle errors during shutdown
    
    try:
        if server_process is not None and hasattr(server_process, 'is_alive') and server_process.is_alive():
            print("Stopping server...")
            server_process.terminate()
            server_process.join(timeout=5)
    except Exception as e:
        pass  # Silently handle errors during shutdown
    
    print("✅ All components stopped")
    sys.exit(0)


def run_protection_client():
    """Run the integrated protection client (IDS/IPS/Monitoring)"""
    try:
        # Add client directory to Python path
        client_dir = Path(__file__).parent.parent / "client"
        scanner_dir = client_dir / "scanner"
        sys.path.insert(0, str(client_dir))
        sys.path.insert(0, str(scanner_dir))
        
        # Import all protection components
        from client.scanner.intrusion_detector import IntrusionDetector
        from client.scanner.prevention_system import PreventionSystem
        from client.scanner.activity_logger import ActivityLogger
        from client.scanner.traffic_monitor import AutomaticTrafficMonitor
        from client.scanner.defense_coordinator import DefenseCoordinator
        from client.scanner.startup_hardening import StartupThreatMonitor
        
        # Initialize components
        stats = {
            "start_time": time.time(),
            "intrusions_detected": 0,
            "intrusions_blocked": 0,
            "activities_logged": 0,
            "threats_detected": 0,
            "startup_findings": 0,
            "files_quarantined": 0,
            "firewall_hardening_actions": 0,
        }
        
        def handle_intrusion(intrusion):
            stats["intrusions_detected"] += 1
            logger.warning(f"🚨 INTRUSION: {intrusion['type']} from {intrusion.get('source_ip', 'UNKNOWN')}")
            if intrusion.get('severity') in ['HIGH', 'CRITICAL']:
                ips.block_ip(intrusion.get('source_ip', ''), reason=intrusion['type'])
                stats["intrusions_blocked"] += 1
                defense_coordinator.handle_attack(intrusion)
        
        def handle_activity(activity):
            stats["activities_logged"] += 1
            # Heuristic for OS log entries
            if activity.get('type') == 'os_log':
                msg = activity.get('message', '').lower()
                keywords = ['fail', 'error', 'unauthorized', 'denied', 'alert', 'critical', 'panic']
                if any(k in msg for k in keywords):
                    logger.warning(f"⚠️  Suspicious OS log entry: {activity.get('message')}")
                return

            if activity.get('risk_level') in ['HIGH', 'CRITICAL']:
                logger.warning(f"⚠️  Suspicious activity: {activity.get('type', 'UNKNOWN')}")
        
        def handle_artifact(artifact):
            if artifact.get('threat_level') in ['high', 'critical', 'malicious']:
                stats["threats_detected"] += 1
                logger.warning(f"⚠️  Malicious {artifact['type']}: {artifact['value']}")
                if artifact['type'] == 'ip':
                    ips.block_ip(artifact['value'], reason="Malicious IP detected")
        
        def handle_defense_event(event):
            if event.get('event') == 'QUARANTINE_ACTIVATED':
                logger.critical("🔒 SYSTEM QUARANTINED - Threat response timeout")

        def handle_prevention_event(event):
            event_type = event.get('event')
            if event_type == 'FILE_QUARANTINED':
                stats['files_quarantined'] += 1
            elif event_type == 'FIREWALL_HARDENED':
                details = event.get('details', {})
                stats['firewall_hardening_actions'] += len(details.get('actions', []))

        def handle_startup_event(event):
            if event.get('event') != 'STARTUP_ASSESSMENT_COMPLETED':
                return

            summary = event.get('report', {}).get('summary', {})
            stats['startup_findings'] += summary.get('total_findings', 0)
            logger.info(
                "🧪 Startup assessment complete | findings=%s critical=%s high=%s",
                summary.get('total_findings', 0),
                summary.get('critical_findings', 0),
                summary.get('high_findings', 0),
            )
        
        # Start all components
        ids = IntrusionDetector(callback=handle_intrusion)
        ids.start()
        
        ips = PreventionSystem(callback=handle_prevention_event)
        ips.start()
        
        activity_logger = ActivityLogger(callback=handle_activity)
        activity_logger.start()
        
        traffic_config = {'scan_interval': 60, 'batch_size': 10}
        traffic_monitor = AutomaticTrafficMonitor(scan_callback=handle_artifact, config=traffic_config)
        traffic_monitor.start()
        
        defense_coordinator = DefenseCoordinator(server_url="http://localhost:8000", callback=handle_defense_event)
        defense_coordinator.start()

        startup_monitor = StartupThreatMonitor(
            prevention_system=ips,
            defense_coordinator=defense_coordinator,
            callback=handle_startup_event,
        )
        startup_monitor.run_startup_assessment(apply_firewall_hardening=True)
        
        logger.info("✅ IDS | IPS | Monitor | Traffic | Defense → ACTIVE")
        
        # Keep running and print stats periodically
        last_stats = time.time()
        while True:
            time.sleep(10)
            
            # Print stats every 5 minutes
            if time.time() - last_stats > 300:
                uptime = int(time.time() - stats["start_time"])
                logger.info("")
                logger.info(f"📊 PROTECTION STATS (Uptime: {uptime//60}m)")
                logger.info(f"  • Intrusions detected: {stats['intrusions_detected']}")
                logger.info(f"  • Intrusions blocked: {stats['intrusions_blocked']}")
                logger.info(f"  • Activities logged: {stats['activities_logged']}")
                logger.info(f"  • Threats detected: {stats['threats_detected']}")
                logger.info(f"  • Startup findings: {stats['startup_findings']}")
                logger.info(f"  • Files quarantined: {stats['files_quarantined']}")
                logger.info(f"  • Firewall hardening actions: {stats['firewall_hardening_actions']}")
                last_stats = time.time()
        
    except ImportError as e:
        logger.error(f"❌ Failed to import protection modules: {e}", exc_info=True)
        logger.error(f"Make sure client directory exists at: {client_dir}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Failed to start protection client: {e}", exc_info=True)
        sys.exit(1)


def run_server():
    """Run the API server"""
    try:
        logger.info("🚀 Starting SENTINEL-AI Server...")
        uvicorn.run(
            "app.main:app",
            host="0.0.0.0",
            port=settings.API_PORT,
            log_level="warning",  # Only show warnings and errors
            access_log=False,  # Disable access logs (they're noise)
        )
    except Exception as e:
        logger.error(f"❌ Server failed: {e}", exc_info=True)
        sys.exit(1)


def run_kali_optimized():
    """
    Run complete SENTINEL-AI system (Server + IDS/IPS/Monitoring)
    - Single command starts everything
    - Full threat detection and prevention
    - Real-time intrusion detection
    - Automatic blocking and quarantine
    - Network accessibility on 0.0.0.0
    """
    logger.info("\n" + "="*70)
    logger.info("🛡️  SENTINEL-AI PROTECTION SYSTEM v2.0")
    logger.info("="*70)
    logger.info(f"🌐 Server: http://localhost:{settings.API_PORT}")
    logger.info(f"📊 Components: IDS | IPS | Monitor | Traffic | Defense")
    logger.info(f"🔍 Detection: Port Scans, DDoS, Brute Force, Malicious IPs")
    logger.info(f"🚫 Prevention: Auto-blocking, Quarantine, Firewall Rules")
    logger.info("="*70)
    
    try:
        # Start server in separate process
        global server_process
        server_process = multiprocessing.Process(target=run_server, name="SentinelServer")
        server_process.start()
        
        logger.info("✅ Server process started (PID: %d)", server_process.pid)
        
        # Wait for server to be ready
        logger.info("⏳ Waiting for server to initialize...")
        time.sleep(5)
        
        # Check if we need sudo for full protection
        if os.geteuid() != 0:
            logger.warning("")
            logger.warning("⚠️  WARNING: Not running as root!")
            logger.warning("   Some protection features may be limited:")
            logger.warning("   - IP blocking via iptables")
            logger.warning("   - Packet capture for IDS")
            logger.warning("   - Domain blocking (hosts file)")
            logger.warning("")
            logger.warning("   For FULL protection, run: sudo python run_server.py")
            logger.warning("")
            time.sleep(3)
        
        # Start protection client in separate process
        global client_process
        client_process = multiprocessing.Process(target=run_protection_client, name="SentinelProtection")
        client_process.start()
        
        logger.info("\n" + "="*70)
        logger.info("✅ SENTINEL-AI PROTECTION ACTIVE")
        logger.info("="*70)
        logger.info(f"🌐 Dashboard: http://localhost:{settings.API_PORT}")
        logger.info(f"📊 Status: Server | IDS | IPS | Monitor | Traffic | Defense → RUNNING")
        logger.info(f"🚨 Alerts: 3 warnings before auto-quarantine (60s intervals)")
        logger.info(f"📝 Logs: logs/ | Press Ctrl+C to stop")
        logger.info("="*70 + "\n")
        
        # Monitor both processes
        while True:
            if not server_process.is_alive():
                logger.error("❌ Server process died unexpectedly!")
                if client_process and client_process.is_alive():
                    client_process.terminate()
                sys.exit(1)
                
            if not client_process.is_alive():
                logger.error("❌ Protection client died unexpectedly!")
                if server_process and server_process.is_alive():
                    server_process.terminate()
                sys.exit(1)
            
            time.sleep(5)
            
    except KeyboardInterrupt:
        signal_handler(None, None)
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}", exc_info=True)
        if 'server_process' in globals() and server_process and server_process.is_alive():
            server_process.terminate()
        if 'client_process' in globals() and client_process and client_process.is_alive():
            client_process.terminate()
        sys.exit(1)


def run_development():
    """Run in development mode with auto-reload"""
    logger.info("Starting in DEVELOPMENT mode with auto-reload...")
    uvicorn.run(
        "app.main:app", host="127.0.0.1", port=8000, reload=True, log_level="debug"
    )


def run_production():
    """Run in production mode with optimized settings"""
    logger.info("Starting in PRODUCTION mode...")
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="warning",
        access_log=False,
        workers=4,
    )


if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Check environment to determine run mode
        if os.getenv("ENVIRONMENT") == "production":
            run_production()
        elif os.getenv("ENVIRONMENT") == "development":
            run_development()
        else:
            # Default to integrated mode (server + IDS/IPS/monitoring)
            if sys.platform in ["linux", "linux2", "darwin"]:
                run_kali_optimized()
            else:
                # Windows fallback
                logger.warning("Windows detected. Consider using run_app.py instead.")
                logger.info("Running in basic mode...")
                uvicorn.run(
                    "app.main:app", host="127.0.0.1", port=8000, reload=settings.DEBUG
                )
    except Exception as e:
        logger.error(f"[FATAL] Server failed to start: {e}", exc_info=True)
        sys.exit(1)
