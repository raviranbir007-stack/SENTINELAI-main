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
from datetime import datetime, UTC
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

    # Suppress routine scan/analysis INFO lines in terminal only.
    # Warnings/errors from these loggers are still shown.
    noisy_info_only = (
        "app.api.v1.endpoints.scan",
        "app.core.threat_analyzer",
        "app.main",
        "app.database",
        "app.gemini_config",
        "app.ai_engine.analyzer",
        "app.ml_models",
        "app.core.report_generator",
        "AutoMonitor",
        "ActivityDatabase",
        "TerminalMonitor",
    )

    def filter(self, record: logging.LogRecord) -> bool:
        if record.name.startswith(self.noisy_prefixes):
            return False
        if record.levelno <= logging.INFO and record.name.startswith(self.noisy_info_only):
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
    """Run the full integrated protection client stack."""
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
        from client.scanner.threat_analyzer import ThreatAnalyzer
        from client.scanner.usb_monitor import USBMonitor
        from client.scanner.email_monitor import EmailMonitor
        from client.scanner.vulnerability_scanner import VulnerabilityScanner
        from client.scanner.behavioral_monitor import BehavioralMonitor
        from client.scanner.dns_monitor import DNSMonitor
        from client.scanner.network_scanner import NetworkScanner
        from client.scanner.process_scanner import ProcessScanner
        from client.scanner.file_scanner import FileScanner
        
        # Initialize components
        stats = {
            "start_time": time.time(),
            "intrusions_detected": 0,
            "intrusions_blocked": 0,
            "activities_logged": 0,
            "threats_detected": 0,
            "extended_events": 0,
            "startup_findings": 0,
            "files_quarantined": 0,
            "firewall_hardening_actions": 0,
        }

        def _normalize_risk(value: str) -> str:
            text = str(value or "").strip().upper()
            if text in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                return text
            if text in {"MALICIOUS", "DANGEROUS"}:
                return "HIGH"
            if text in {"SUSPICIOUS", "WARNING"}:
                return "MEDIUM"
            return "LOW"
        
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

        def handle_threat_verdict(verdict):
            verdict_value = str(verdict.get('verdict', '')).upper()
            artifact_type = verdict.get('artifact_type', 'artifact')
            artifact_value = verdict.get('artifact', 'UNKNOWN')

            if verdict_value != 'MALICIOUS':
                return

            stats['threats_detected'] += 1
            logger.warning("⚠️  Threat intel verdict: %s -> %s", artifact_type, artifact_value)

            if artifact_type == 'ip':
                ips.block_ip(artifact_value, reason="Threat intelligence malicious IP")
            elif artifact_type in {'domain', 'url'}:
                from urllib.parse import urlparse

                domain = artifact_value if artifact_type == 'domain' else urlparse(artifact_value).netloc
                if domain:
                    ips.block_domain(domain, reason="Threat intelligence malicious domain")
        
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

        def handle_extended_monitor_event(event):
            event_type = event.get('type', 'extended_monitor_event')
            risk = _normalize_risk(event.get('risk') or event.get('severity'))
            stats['extended_events'] += 1

            if event_type in {'usb_file_quarantined', 'FILE_QUARANTINED'}:
                stats['files_quarantined'] += 1

            if risk not in {'HIGH', 'CRITICAL'}:
                return

            stats['threats_detected'] += 1
            description = event.get('description') or event.get('reason') or event_type
            logger.warning("⚠️  Extended monitor alert [%s]: %s", risk, description)

            remote_ip = event.get('source_ip') or event.get('remote_ip') or event.get('ip')
            domain = event.get('domain') or event.get('source_domain')
            file_path = event.get('file_path') or event.get('original_path')

            # Avoid noisy SOC popup alerts for local host-only heuristics
            # (e.g. browser helper path or short-lived Python CPU spikes)
            alert_type = str(event.get('alert_type') or '').upper()
            if event_type in {'process_alert', 'behavioral_alert'} and not remote_ip and not domain:
                if alert_type in {'EXEC_FROM_TEMP', 'CPU_SPIKE'}:
                    logger.info("ℹ️  Local heuristic noted (not escalated to attack alert): %s", description)
                    return

            if remote_ip:
                ips.block_ip(remote_ip, reason=description)
            if domain and event_type in {'dns_threat', 'email_threat'}:
                ips.block_domain(domain, reason=description)
            if file_path and event_type in {'usb_file_quarantined', 'email_threat'}:
                ips.block_file(file_path, reason=description)

            defense_coordinator.handle_attack({
                'type': event_type,
                'severity': risk,
                'description': description,
                'source_ip': remote_ip or 'UNKNOWN',
                'timestamp': datetime.now(UTC),
            })
        
        # Start all components
        threat_analyzer = ThreatAnalyzer(
            callback=handle_threat_verdict,
            server_url="http://localhost:8000",
        )
        threat_analyzer.start()

        ids = IntrusionDetector(callback=handle_intrusion)
        ids.start()
        
        ips = PreventionSystem(callback=handle_prevention_event)
        ips.start()
        
        activity_logger = ActivityLogger(callback=handle_activity, threat_analyzer=threat_analyzer)
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

        usb_monitor = USBMonitor(callback=handle_extended_monitor_event, threat_analyzer=threat_analyzer)
        email_monitor = EmailMonitor(callback=handle_extended_monitor_event, threat_analyzer=threat_analyzer)
        vulnerability_scanner = VulnerabilityScanner(callback=handle_extended_monitor_event)
        behavioral_monitor = BehavioralMonitor(callback=handle_extended_monitor_event)
        dns_monitor = DNSMonitor(callback=handle_extended_monitor_event, threat_analyzer=threat_analyzer)
        network_scanner = NetworkScanner(callback=handle_extended_monitor_event, threat_analyzer=threat_analyzer)
        process_scanner = ProcessScanner(callback=handle_extended_monitor_event)
        file_scanner = FileScanner(threat_analyzer=threat_analyzer)

        usb_monitor.start()
        email_monitor.start()
        vulnerability_scanner.start()
        behavioral_monitor.start()
        dns_monitor.start()
        network_scanner.start()
        process_scanner.start()
        
        logger.info("✅ IDS | IPS | Monitor | Traffic | Defense | USB | Email | Vuln | Behavior | DNS | Network | Process → ACTIVE")
        
        # Keep running and print stats periodically
        last_stats = time.time()
        while True:
            time.sleep(10)
            
            # Print stats every 5 minutes
            if time.time() - last_stats > 300:
                uptime = int(time.time() - stats["start_time"])
                usb_summary = usb_monitor.get_events_summary()
                email_summary = email_monitor.get_summary()
                vuln_summary = vulnerability_scanner.get_summary()
                behavioral_summary = behavioral_monitor.get_summary()
                dns_summary = dns_monitor.get_summary()
                network_summary = network_scanner.get_summary()
                process_summary = process_scanner.get_summary()
                traffic_summary = traffic_monitor.get_statistics()

                logger.info(
                    "📊 PROTECTION | up=%sm | intrusions=%s blocked=%s | activities=%s | threats=%s",
                    uptime // 60,
                    stats['intrusions_detected'],
                    stats['intrusions_blocked'],
                    stats['activities_logged'],
                    stats['threats_detected'],
                )
                logger.info(
                    "   monitors | ext=%s startup=%s quarantined=%s firewall=%s | net_conns=%s suspicious=%s | scans=%s queue=%s",
                    stats['extended_events'],
                    stats['startup_findings'],
                    stats['files_quarantined'],
                    stats['firewall_hardening_actions'],
                    network_summary.get('connections_logged', 0),
                    network_summary.get('suspicious_connections', 0),
                    traffic_summary.get('scanned_artifacts_count', traffic_summary.get('artifacts_scanned', 0)),
                    traffic_summary.get('queue_size', 0),
                )
                logger.info(
                    "   security | vulns(C/H/M/L)=%s/%s/%s/%s | process_high=%s | behavioral_high=%s | usb_threats=%s | email_critical=%s | dns_threats=%s",
                    vuln_summary.get('CRITICAL', 0),
                    vuln_summary.get('HIGH', 0),
                    vuln_summary.get('MEDIUM', 0),
                    vuln_summary.get('LOW', 0),
                    process_summary.get('process_alerts', {}).get('HIGH', 0),
                    behavioral_summary.get('behavioral_alerts', {}).get('HIGH', 0),
                    usb_summary.get('usb_threats', 0),
                    email_summary.get('critical', 0),
                    dns_summary.get('dns_threats', 0),
                )
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
