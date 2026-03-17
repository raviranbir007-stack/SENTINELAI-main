#!/usr/bin/env python3
"""
SENTINELAI Integrated Protection System
Combines IDS, IPS, and Monitoring into a single unified system
"""

import asyncio
import logging
import platform
import signal
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import uuid

import requests

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Import all scanner components
from scanner.intrusion_detector import IntrusionDetector
from scanner.prevention_system import PreventionSystem
from scanner.activity_logger import ActivityLogger
from scanner.traffic_monitor import AutomaticTrafficMonitor
from scanner.defense_coordinator import DefenseCoordinator
from scanner.network_scanner import NetworkScanner
from scanner.file_scanner import FileScanner
from scanner.process_scanner import ProcessScanner
from scanner.threat_analyzer import ThreatAnalyzer
from scanner.minimal_cli import MinimalCLI
from scanner.startup_hardening import StartupThreatMonitor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("sentinel_integrated.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("IntegratedProtection")


class IntegratedProtectionSystem:
    """
    Unified protection system combining:
    - IDS (Intrusion Detection System)
    - IPS (Intrusion Prevention System)  
    - Real-time Activity Monitoring
    - Threat Detection and Response
    - Automatic Blocking and Quarantine
    """

    def __init__(self, server_url: str = "http://localhost:8000"):
        self.server_url = server_url
        self.running = False
        self.client_id: Optional[str] = None
        self.heartbeat_interval = 60
        self._heartbeat_thread = None
        
        # Initialize all components
        logger.info("🔧 Initializing protection components...")
        
        # Core detection and prevention
        self.ids = IntrusionDetector(callback=self._handle_intrusion)
        self.ips = PreventionSystem(callback=self._handle_prevention_event)
        
        # Activity monitoring
        self.cli = MinimalCLI()
        self.threat_analyzer = ThreatAnalyzer(
            callback=self._handle_threat_verdict,
            server_url=server_url
        )
        self.activity_logger = ActivityLogger(
            callback=self._handle_activity,
            threat_analyzer=self.threat_analyzer
        )
        self.traffic_monitor = AutomaticTrafficMonitor(
            scan_callback=self._handle_artifact,
            config={"scan_interval": 15, "batch_size": 10}
        )
        
        # Defense coordination
        self.defense_coordinator = DefenseCoordinator(
            server_url=server_url,
            callback=self._handle_defense_event
        )
        self.startup_monitor = StartupThreatMonitor(
            prevention_system=self.ips,
            defense_coordinator=self.defense_coordinator,
            callback=self._handle_startup_event,
        )
        
        # Scanners
        self.network_scanner = NetworkScanner()
        self.file_scanner = FileScanner()
        self.process_scanner = ProcessScanner()
        
        # Statistics
        self.stats = {
            "start_time": None,
            "intrusions_detected": 0,
            "intrusions_blocked": 0,
            "threats_detected": 0,
            "domains_blocked": 0,
            "ips_blocked": 0,
            "files_quarantined": 0,
            "activities_logged": 0,
            "artifacts_scanned": 0,
            "websites_scanned": 0,
            "files_scanned": 0,
            "startup_findings": 0,
            "firewall_hardening_actions": 0,
        }
        
        # Threat correlation
        self.active_threats = {}
        
        logger.info("✅ All components initialized")

    def _register_with_server(self):
        """Register this protection agent with server for event correlation."""
        try:
            host = socket.gethostname()
            try:
                ip = socket.gethostbyname(host)
            except Exception:
                ip = "127.0.0.1"

            payload = {
                "hostname": host,
                "ip_address": ip,
                "mac_address": "00:00:00:00:00:00",
                "os_type": platform.system(),
                "os_version": platform.version(),
                "network_segment": f"{'.'.join(ip.split('.')[:3])}.0/24" if ip.count('.') == 3 else None,
                "gateway": "unknown",
                "dns_servers": [],
                "version": "integrated-3.0",
            }

            res = requests.post(
                f"{self.server_url}/api/v1/network/client/register",
                json=payload,
                timeout=10,
            )
            if res.status_code == 200:
                self.client_id = (res.json() or {}).get("client_id") or self.client_id
                logger.info("✅ Registered with server: %s", self.client_id)
            else:
                logger.warning("Server registration failed (%s)", res.status_code)
        except Exception as exc:
            logger.warning("Server registration skipped: %s", exc)

    def _heartbeat_loop(self):
        """Send periodic heartbeat so dashboard can reflect live client status."""
        while self.running:
            if self.client_id:
                try:
                    requests.post(
                        f"{self.server_url}/api/v1/network/client/heartbeat",
                        params={"client_id": self.client_id},
                        timeout=6,
                    )
                except Exception:
                    pass
            time.sleep(self.heartbeat_interval)

    def _to_jsonable(self, value):
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, dict):
            return {k: self._to_jsonable(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._to_jsonable(v) for v in value]
        return value

    def _post_defense_event(self, event_name: str, severity: str = "medium", description: str = "", payload: Optional[Dict] = None):
        """Forward endpoint events to server so threats/heartbeat/dashboard stay in sync."""
        try:
            requests.post(
                f"{self.server_url}/api/v1/network/event",
                json={
                    "client_id": self.client_id,
                    "event": event_name,
                    "severity": str(severity).lower(),
                    "description": description,
                    "monitor_event": self._to_jsonable(payload or {}),
                },
                timeout=8,
            )
        except Exception as exc:
            logger.debug("Failed to post defense event: %s", exc)

    def _action_prompt(self, action: str, target: str = "-", status: str = "ok", severity: str = "info"):
        """Short, structured terminal prompt for recent actions."""
        emoji = "✅"
        sev = str(severity or "info").lower()
        if sev in {"high", "warning"}:
            emoji = "⚠️"
        if sev in {"critical", "error"}:
            emoji = "🚨"
        logger.info(
            "%s ACTION | type=%s | target=%s | status=%s",
            emoji,
            str(action or "unknown").upper(),
            str(target or "-"),
            str(status or "ok"),
        )

    def _handle_intrusion(self, intrusion: Dict):
        """Handle detected intrusion from IDS"""
        self.stats["intrusions_detected"] += 1
        
        severity = intrusion.get("severity", "MEDIUM")
        source_ip = intrusion.get("source_ip", "UNKNOWN")
        attack_type = intrusion.get("type", "UNKNOWN")
        
        logger.warning(f"🚨 INTRUSION DETECTED: {attack_type} from {source_ip} (Severity: {severity})")
        self._action_prompt(attack_type, source_ip, "detected", severity)
        self._post_defense_event(
            event_name=attack_type,
            severity=severity,
            description=intrusion.get("description", f"Intrusion detected: {attack_type}"),
            payload=intrusion,
        )
        
        # Send to defense coordinator
        self.defense_coordinator.handle_attack(intrusion)
        
        # Auto-block high severity attacks
        if severity in ["HIGH", "CRITICAL"]:
            logger.warning(f"🛡️  AUTO-BLOCKING: {source_ip} (High severity threat)")
            self.ips.block_ip(source_ip, reason=f"IDS: {attack_type}")
            self.stats["intrusions_blocked"] += 1
            self.stats["ips_blocked"] += 1

    def _handle_prevention_event(self, event: Dict):
        """Handle prevention events from IPS"""
        event_type = event.get("event", "UNKNOWN")
        
        if event_type == "DOMAIN_BLOCKED":
            self.stats["domains_blocked"] += 1
            domain = event.get("domain", "")
            logger.info(f"🚫 Domain blocked: {domain}")
            self._action_prompt(event_type, domain, "applied", "high")
            
        elif event_type == "IP_BLOCKED":
            self.stats["ips_blocked"] += 1
            ip = event.get("ip", "")
            logger.info(f"🚫 IP blocked: {ip}")
            self._action_prompt(event_type, ip, "applied", "high")
            
        elif event_type == "FILE_QUARANTINED":
            self.stats["files_quarantined"] += 1
            file_path = event.get("file", "")
            logger.info(f"🔒 File quarantined: {file_path}")
            self._action_prompt(event_type, file_path, "applied", "high")
        elif event_type == "FIREWALL_HARDENED":
            details = event.get("details", {})
            self.stats["firewall_hardening_actions"] += len(details.get("actions", []))
            logger.info("🛡️  Firewall hardening applied")
            self._action_prompt(event_type, "host-firewall", "applied", "medium")
        else:
            self._action_prompt(event_type, event.get("target") or event.get("source_ip") or "system", "processed", "medium")

        self._post_defense_event(
            event_name=event_type,
            severity="high" if event_type in {"IP_BLOCKED", "DOMAIN_BLOCKED", "FILE_QUARANTINED"} else "medium",
            description=event.get("reason") or f"Prevention event: {event_type}",
            payload=event,
        )

    def _handle_activity(self, activity: Dict):
        """Handle logged activity"""
        self.stats["activities_logged"] += 1
        
        # Check if activity is suspicious
        risk_level = activity.get("risk_level", "UNKNOWN")
        
        if risk_level in ["HIGH", "CRITICAL"]:
            logger.warning(f"⚠️  Suspicious activity: {activity.get('type', 'UNKNOWN')}")
            
            # Create alert
            alert = {
                "type": "SUSPICIOUS_ACTIVITY",
                "severity": risk_level,
                "details": activity,
                "timestamp": datetime.now(),
            }
            self.defense_coordinator.handle_attack(alert)

    def _handle_artifact(self, artifact: Dict):
        """Handle detected network artifact"""
        self.stats["artifacts_scanned"] += 1
        artifact_type = artifact.get("type", "")
        value = artifact.get("value", "")
        
        # Queue for multi-API scan
        if artifact_type and value:
            self.threat_analyzer.queue_scan(
                artifact_type=artifact_type,
                artifact_value=value,
                metadata=artifact.get("metadata", {})
            )

    def _handle_defense_event(self, event: Dict):
        """Handle defense coordinator events"""
        event_type = event.get("event", "")
        
        if event_type == "QUARANTINE_ACTIVATED":
            logger.critical("🔒 SYSTEM QUARANTINED - Threat response timeout")
            self._action_prompt(event_type, "system", "active", "critical")
        elif event_type == "QUARANTINE_RELEASED":
            logger.info("🔓 System quarantine released")
            self._action_prompt(event_type, "system", "released", "high")
        else:
            self._action_prompt(event_type or "DEFENSE_EVENT", "system", "processed", "high")

        self._post_defense_event(
            event_name=event_type or "DEFENSE_EVENT",
            severity="critical" if event_type == "QUARANTINE_ACTIVATED" else "high",
            description=event.get("reason") or "Defense coordinator event",
            payload=event,
        )

    def _handle_startup_event(self, event: Dict):
        """Handle startup hardening results."""
        if event.get("event") != "STARTUP_ASSESSMENT_COMPLETED":
            return

        summary = event.get("report", {}).get("summary", {})
        self.stats["startup_findings"] += summary.get("total_findings", 0)
        logger.info(
            "🧪 Startup security baseline complete | findings=%s critical=%s high=%s",
            summary.get("total_findings", 0),
            summary.get("critical_findings", 0),
            summary.get("high_findings", 0),
        )
        self._action_prompt(
            "STARTUP_ASSESSMENT_COMPLETED",
            "baseline",
            "completed",
            "warning" if (summary.get("critical_findings", 0) or summary.get("high_findings", 0)) else "info",
        )

    def _handle_threat_verdict(self, verdict: Dict):
        """Handle threat verdicts from multi-API scanner"""
        try:
            artifact_type = verdict.get("artifact_type", "unknown")
            artifact_value = verdict.get("artifact", "")
            verdict_label = verdict.get("verdict", "UNKNOWN")
            risk = verdict.get("risk", "UNKNOWN")
            apis_checked = verdict.get("sources", 0) or len(verdict.get("sources_list", []))

            # Track stats
            if artifact_type == "url":
                self.stats["websites_scanned"] += 1
            elif artifact_type == "file":
                self.stats["files_scanned"] += 1

            # Minimal prompt (reduce noise: show SAFE only for URLs/domains)
            show_safe = artifact_type in ["url", "domain"]
            if verdict_label.upper() != "SAFE" or show_safe:
                self.cli.prompt_scan_result(artifact_type, artifact_value, verdict_label, apis_checked)

            # Apply responses for malicious findings
            if verdict_label.upper() == "MALICIOUS" or risk.upper() in ["HIGH", "CRITICAL"]:
                self.stats["threats_detected"] += 1
                if artifact_type == "domain":
                    self.ips.block_domain(artifact_value, reason="Malicious domain detected")
                elif artifact_type == "ip":
                    self.ips.block_ip(artifact_value, reason="Malicious IP detected")
                elif artifact_type == "url":
                    # block domain if URL
                    try:
                        domain = artifact_value.split("/")[2]
                    except Exception:
                        domain = artifact_value
                    self.ips.block_domain(domain, reason="Malicious URL detected")
                elif artifact_type == "file":
                    file_path = verdict.get("metadata", {}).get("file_path") if isinstance(verdict, dict) else None
                    if file_path:
                        self.ips.block_file(file_path, reason="Malicious file detected")

        except Exception as e:
            logger.debug("Threat verdict handling failed")

    def start(self):
        """Start all protection systems"""
        if self.running:
            logger.warning("System is already running")
            return
        
        self.running = True
        self.stats["start_time"] = datetime.now()
        self._register_with_server()
        
        logger.info("=" * 60)
        logger.info("🛡️  SENTINELAI INTEGRATED PROTECTION SYSTEM")
        logger.info("=" * 60)
        logger.info("")
        logger.info("Starting all protection components...")
        logger.info("")
        
        # Start all components
        components = [
            ("IDS (Intrusion Detection)", self.ids),
            ("IPS (Intrusion Prevention)", self.ips),
            ("Activity Logger", self.activity_logger),
            ("Traffic Monitor", self.traffic_monitor),
            ("Defense Coordinator", self.defense_coordinator),
            ("Threat Analyzer", self.threat_analyzer),
        ]
        
        for name, component in components:
            try:
                component.start()
                logger.info(f"✅ {name} - ACTIVE")
            except Exception as e:
                logger.error(f"❌ {name} - FAILED: {e}")

        if self._heartbeat_thread is None or not self._heartbeat_thread.is_alive():
            import threading
            self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
            self._heartbeat_thread.start()
        
        logger.info("")
        logger.info("=" * 60)
        logger.info("✅ ALL SYSTEMS ACTIVE - Protection enabled")
        logger.info("=" * 60)
        logger.info("")

        self.startup_monitor.run_startup_assessment(apply_firewall_hardening=True)
        
        # Start monitoring loop
        self._run_monitoring_loop()

    def stop(self):
        """Stop all protection systems"""
        if not self.running:
            return
        
        logger.info("Stopping all protection components...")
        self.running = False
        
        # Stop all components
        try:
            self.ids.stop()
            self.ips.stop()
            self.activity_logger.stop()
            self.traffic_monitor.stop()
            self.defense_coordinator.stop()
            self.threat_analyzer.stop()
        except Exception as e:
            logger.error(f"Error stopping components: {e}")

        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join(timeout=2)
        
        # Print final statistics
        self._print_statistics()
        
        logger.info("✅ SENTINELAI stopped")

    def _run_monitoring_loop(self):
        """Main monitoring loop"""
        last_stats_time = time.time()
        stats_interval = 300  # Print stats every 5 minutes
        
        try:
            while self.running:
                # Check component health
                if not self.ids.running:
                    logger.error("❌ IDS stopped unexpectedly - restarting")
                    self.ids.start()
                
                # Print statistics periodically
                current_time = time.time()
                if current_time - last_stats_time >= stats_interval:
                    self._print_statistics()
                    last_stats_time = current_time
                
                time.sleep(10)
                
        except KeyboardInterrupt:
            logger.info("Received shutdown signal")
            self.stop()

    def _print_statistics(self):
        """Print current statistics"""
        if not self.stats["start_time"]:
            return
        
        uptime = datetime.now() - self.stats["start_time"]
        hours = uptime.seconds // 3600
        minutes = (uptime.seconds % 3600) // 60
        
        logger.info("")
        logger.info("=" * 60)
        logger.info("📊 SENTINELAI STATISTICS")
        logger.info("=" * 60)
        logger.info(f"Uptime: {hours}h {minutes}m")
        logger.info("")
        logger.info("Detection & Prevention:")
        logger.info(f"  • Intrusions detected: {self.stats['intrusions_detected']}")
        logger.info(f"  • Intrusions blocked: {self.stats['intrusions_blocked']}")
        logger.info(f"  • Threats detected: {self.stats['threats_detected']}")
        logger.info("")
        logger.info("Blocking Statistics:")
        logger.info(f"  • Domains blocked: {self.stats['domains_blocked']}")
        logger.info(f"  • IPs blocked: {self.stats['ips_blocked']}")
        logger.info(f"  • Files quarantined: {self.stats['files_quarantined']}")
        logger.info(f"  • Startup findings: {self.stats['startup_findings']}")
        logger.info(f"  • Firewall hardening actions: {self.stats['firewall_hardening_actions']}")
        logger.info("")
        logger.info("Monitoring:")
        logger.info(f"  • Activities logged: {self.stats['activities_logged']}")
        logger.info(f"  • Artifacts scanned: {self.stats['artifacts_scanned']}")
        logger.info(f"  • Websites scanned: {self.stats['websites_scanned']}")
        logger.info(f"  • Files scanned: {self.stats['files_scanned']}")
        logger.info("=" * 60)
        logger.info("")


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info("Shutdown signal received")
    sys.exit(0)


def main():
    """Main entry point"""
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Get server URL from environment or use default
    import os
    server_url = os.getenv("SENTINELAI_SERVER", "http://localhost:8000")
    
    # Create and start protection system
    protection = IntegratedProtectionSystem(server_url=server_url)
    
    try:
        protection.start()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        protection.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        protection.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
