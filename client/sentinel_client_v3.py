"""
SENTINEL-AI Client v3.0 - Real-time Defense & Activity Monitoring
Features:
- Real-time intrusion detection and prevention
- Auto-quarantine on 5 failed alerts
- Comprehensive activity logging (websites, applications)
- AI-powered threat analysis using 5 APIs + Gemini
- Proactive blocking and prevention
"""

import asyncio
import os
import hashlib
import json
import logging
import platform
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import psutil
import requests

# Import our new security modules
from scanner.intrusion_detector import IntrusionDetector
from scanner.activity_logger import ActivityLogger
from scanner.activity_analyzer import ActivityAnalyzer
from scanner.defense_coordinator import DefenseCoordinator
from scanner.prevention_system import PreventionSystem
from scanner.threat_analyzer import ThreatAnalyzer
from scanner.logging_config import configure_module_logger
from scanner.minimal_cli import MinimalCLI
from scanner.usb_monitor import USBMonitor
from scanner.email_monitor import EmailMonitor
from scanner.vulnerability_scanner import VulnerabilityScanner
from scanner.behavioral_monitor import BehavioralMonitor
from scanner.dns_monitor import DNSMonitor
from scanner.network_scanner import NetworkScanner
from scanner.process_scanner import ProcessScanner
from scanner.file_scanner import FileScanner

# Configuration
CONFIG_FILE = Path("config.ini")
LOG_FILE = Path("sentinel_client_v3.log")

# Setup logging - MINIMAL CONSOLE OUTPUT
logger = configure_module_logger("SentinelAI_v3", LOG_FILE, file_level=logging.INFO)


class SentinelClientV3:
    """
    SENTINEL-AI Client v3.0 with real-time defense capabilities
    """

    def __init__(self, config_path: Path = CONFIG_FILE):
        self.config = self._load_config(config_path)
        # server URL may be overridden via environment variable for flexibility
        env_url = os.getenv("SENTINEL_SERVER_URL")
        default_url = "http://localhost:8000"
        self.server_url = env_url or self.config.get("server", {}).get("url", default_url)
        self.api_key = self.config.get("server", {}).get("api_key", "")
        
        # Separate runtime ID from server-assigned client ID
        self.local_runtime_id = str(uuid.uuid4())  # Always unique, never changes
        self.server_client_id = None  # Set only after successful registration
        self.is_registered = False
        self.offline_mode = False
        
        # Check if this host should run as admin infrastructure (not client)
        self._is_admin_infrastructure = self._check_admin_infrastructure()
        
        self.running = False
        self.cli = MinimalCLI()  # Minimal CLI interface

        # Load API keys for threat intelligence
        self.api_keys = {
            'virustotal': self.config.get("apis", {}).get("virustotal", "").strip(),
            'abuseipdb': self.config.get("apis", {}).get("abuseipdb", "").strip(),
            'urlscan': self.config.get("apis", {}).get("urlscan", "").strip(),
            'otx': self.config.get("apis", {}).get("otx", "").strip(),
            'ipqualityscore': self.config.get("apis", {}).get("ipqualityscore", "").strip(),
            'shodan': self.config.get("apis", {}).get("shodan", "").strip(),
            'hybrid_analysis': self.config.get("apis", {}).get("hybrid_analysis", "").strip()
        }
        # Debug: Log loaded API keys (masking for safety)
        for k, v in self.api_keys.items():
            if v:
                logger.info(f"API key loaded for {k}: {'*' * (len(v)-4) + v[-4:]}")
            else:
                logger.warning(f"API key for {k} NOT SET")

        # Configuration
        self.scan_interval = int(self.config.get("client", {}).get("scan_interval", 300))
        self.heartbeat_interval = int(self.config.get("client", {}).get("heartbeat_interval", 60))
        
        # Initialize security modules
        
        # 1. Threat Analysis Engine (background multi-API scanning)
        self.threat_analyzer = ThreatAnalyzer(
            api_keys=self.api_keys,
            callback=self._handle_threat_verdict
        )
        
        # 2. Intrusion Detection System
        self.intrusion_detector = IntrusionDetector(callback=self._handle_attack)
        
        # 3. Activity Logger (websites, apps) - integrated with threat analyzer
        self.activity_logger = ActivityLogger(
            callback=self._handle_activity_alert,
            threat_analyzer=self.threat_analyzer
        )
        
        # 3. Activity Analyzer (AI-powered)
        self.activity_analyzer = ActivityAnalyzer(
            server_url=self.server_url,
            api_key=self.api_key,
            api_keys=self.api_keys
        )
        
        # 4. Defense Coordinator (alerts & quarantine)
        self.defense_coordinator = DefenseCoordinator(
            server_url=self.server_url,
            callback=self._send_defense_event_to_server
        )
        
        # 5. Prevention System (blocking)
        self.prevention_system = PreventionSystem(callback=self._handle_prevention_event)

        # 6+ Extended endpoint telemetry monitors
        self.usb_monitor = USBMonitor(
            callback=self._handle_extended_monitor_event,
            threat_analyzer=self.threat_analyzer
        )
        self.email_monitor = EmailMonitor(
            callback=self._handle_extended_monitor_event,
            threat_analyzer=self.threat_analyzer,
            # IMAP/POP are optional, can be left blank and local Thunderbird scan still works
            imap_host=self.config.get("email", {}).get("imap_host", ""),
            imap_port=int(self.config.get("email", {}).get("imap_port", 993)),
            imap_user=self.config.get("email", {}).get("imap_user", ""),
            imap_pass=self.config.get("email", {}).get("imap_pass", ""),
            pop3_host=self.config.get("email", {}).get("pop3_host", ""),
            pop3_port=int(self.config.get("email", {}).get("pop3_port", 995)),
            pop3_user=self.config.get("email", {}).get("pop3_user", ""),
            pop3_pass=self.config.get("email", {}).get("pop3_pass", ""),
            scan_local_thunderbird=self.config.get("email", {}).get("scan_local_thunderbird", "true").lower() in ["1", "true", "yes", "on"],
            poll_interval=int(self.config.get("email", {}).get("poll_interval", 60))
        )
        self.vulnerability_scanner = VulnerabilityScanner(
            callback=self._handle_extended_monitor_event,
            shodan_api_key=self.api_keys.get("shodan", ""),
            scan_interval_hours=int(self.config.get("vulnerability", {}).get("scan_interval_hours", 6)),
            full_scan_on_start=self.config.get("vulnerability", {}).get("full_scan_on_start", "true").lower() in ["1", "true", "yes", "on"]
        )
        self.behavioral_monitor = BehavioralMonitor(
            callback=self._handle_extended_monitor_event,
            poll_interval=int(self.config.get("behavior", {}).get("poll_interval", 5))
        )
        self.dns_monitor = DNSMonitor(
            callback=self._handle_extended_monitor_event,
            threat_analyzer=self.threat_analyzer,
            use_scapy=self.config.get("dns", {}).get("use_scapy", "false").lower() in ["1", "true", "yes", "on"],
            poll_interval=int(self.config.get("dns", {}).get("poll_interval", 5))
        )
        self.network_scanner = NetworkScanner(
            callback=self._handle_extended_monitor_event,
            threat_analyzer=self.threat_analyzer,
            poll_interval=int(self.config.get("network", {}).get("poll_interval", 10))
        )
        self.process_scanner = ProcessScanner(
            callback=self._handle_extended_monitor_event,
            poll_interval=int(self.config.get("process", {}).get("poll_interval", 5))
        )
        self.file_scanner = FileScanner(threat_analyzer=self.threat_analyzer, db_path="file_scan_results.db")

    def _load_config(self, config_path: Path) -> Dict:
        """Load configuration from file"""
        try:
            if config_path.exists():
                import configparser
                config = configparser.ConfigParser()
                config.read(config_path)
                raw = {section: dict(config.items(section)) for section in config.sections()}
                # backwards compatibility: older config examples used a single
                # [client] section with uppercase keys.  Map those values to the
                # current layout so the example file works out of the box.
                if "client" in raw:
                    client_conf = raw.get("client", {})
                    if "SERVER_URL" in client_conf:
                        raw.setdefault("server", {})["url"] = client_conf.get("SERVER_URL")
                    if "CLIENT_ID" in client_conf:
                        raw.setdefault("client", {})["client_id"] = client_conf.get("CLIENT_ID")
                return raw
            else:
                return {
                    # default server port is now 8000 to match the bundled server
                    'server': {'url': 'http://localhost:8000', 'api_key': ''},
                    'client': {'scan_interval': '300', 'heartbeat_interval': '60'},
                    'apis': {}
                }
        except Exception as e:
            logger.error(f"Config load failed")
            return {}

    def _check_admin_infrastructure(self) -> bool:
        """Check if this host should run as admin infrastructure (not client)"""
        try:
            force_admin = os.getenv("SENTINEL_FORCE_ADMIN_INFRA", "").strip().lower() in {"1", "true", "yes", "on"}
            force_client = os.getenv("SENTINEL_FORCE_CLIENT_MODE", "").strip().lower() in {"1", "true", "yes", "on"}
            if force_client:
                logger.info("🧭 Forced client mode via SENTINEL_FORCE_CLIENT_MODE")
                return False
            if force_admin:
                logger.info("🧭 Forced admin infrastructure mode via SENTINEL_FORCE_ADMIN_INFRA")
                return True

            # Privilege-gated role: non-root always behaves as client.
            try:
                is_root = os.geteuid() == 0
            except Exception:
                is_root = False
            if not is_root:
                return False

            hostname = socket.gethostname().lower()
            fqdn = socket.getfqdn().lower()
            
            # Get local IPs
            local_ips = set()
            try:
                local_ips.update(socket.gethostbyname_ex(socket.gethostname())[2])
            except:
                pass
            local_ips.update({"127.0.0.1", "::1"})
            
            # Check hostname markers from config
            hostname_markers = self.config.get("registration", {}).get("admin_hostnames", "").split(",")
            hostname_markers = [h.strip().lower() for h in hostname_markers if h.strip()]
            
            # Check IP markers from config  
            ip_markers = self.config.get("registration", {}).get("admin_ips", "").split(",")
            ip_markers = [ip.strip() for ip in ip_markers if ip.strip()]
            
            # Check if hostname matches
            if hostname in hostname_markers or fqdn in hostname_markers:
                logger.info(f"🖥️  Host {hostname} identified as admin infrastructure")
                return True
                
            # Check if IP matches
            if any(ip in ip_markers for ip in local_ips):
                logger.info(f"🖥️  IP {list(local_ips)[0]} identified as admin infrastructure")
                return True

            # Root run on this machine defaults to admin infra mode.
            logger.info("🖥️  Root session detected: defaulting to admin infrastructure mode")
            return True
            
        except Exception as e:
            logger.debug(f"Admin infrastructure check failed: {e}")
            return False

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication"""
        # Use server_client_id if registered, otherwise local_runtime_id for registration
        client_id = self.server_client_id if self.server_client_id else self.local_runtime_id
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "X-Client-ID": client_id,
        }

    async def register(self) -> bool:
        """Register client with the server"""
        try:
            logger.info(f"🔗 Registering with {self.server_url} (runtime_id: {self.local_runtime_id[:8]}...)")
            
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)

            # Get MAC address
            mac_address = None
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if hasattr(psutil, 'AF_LINK') and addr.family == psutil.AF_LINK:
                        mac_address = addr.address
                        break
                if mac_address:
                    break

            # Get network info
            gateways = psutil.net_if_stats()
            gateway = None
            if gateways:
                gateway = list(gateways.keys())[0]

            # Determine network segment
            network_segment = f"{'.'.join(ip_address.split('.')[:3])}.0/24"

            registration_data = {
                "hostname": hostname,
                "ip_address": ip_address,
                "mac_address": mac_address,
                "os_type": platform.system(),
                "os_version": platform.version(),
                # network_segment already computed above
                "network_segment": network_segment,
                "gateway": gateway or "Unknown",
                "dns_servers": self._get_dns_servers(),
                "version": "3.0.0",
                "client_id": self.local_runtime_id,  # Send runtime ID for tracking
                "capabilities": [
                    "intrusion_detection",
                    "activity_logging",
                    "ai_analysis",
                    "auto_quarantine",
                    "real_time_prevention"
                ]
            }

            response = requests.post(
                f"{self.server_url}/api/v1/network/client/register",
                headers=self._get_headers(),
                json=registration_data,
                timeout=60,  # Increased from 30s to 60s (registration may trigger email + DB operations)
            )

            if response.status_code == 200:
                result = response.json()
                server_assigned_id = result.get("client_id")
                if server_assigned_id:
                    # Registration successful - set server client ID
                    self.server_client_id = server_assigned_id
                    self.is_registered = True
                    self.offline_mode = False
                    
                    logger.info(f"✅ Registration SUCCESS: {self.local_runtime_id[:8]}... → {self.server_client_id}")
                    logger.info(f"   Status: {result.get('status')} | Mode: online")
                    self.cli.prompt_registration_success(self.server_client_id)
                    return True
                else:
                    logger.error(f"❌ Registration response missing client_id. Response: {result}")
                    self.cli.prompt_registration_failed("No client_id in response")
                    return False
            else:
                # Registration failed - enter offline mode
                error_msg = f"HTTP {response.status_code}"
                logger.warning(f"⚠️  Registration failed: {error_msg} - entering offline mode")
                logger.warning(f"   Response: {response.text}")
                
                self.offline_mode = True
                self.cli.prompt_registration_failed(error_msg)
                return False

        except requests.exceptions.ConnectionError as e:
            logger.warning(f"⚠️  Registration connection failed: {self.server_url} unreachable - entering offline mode")
            logger.warning(f"   Error: {str(e)}")
            self.offline_mode = True
            self.cli.prompt_registration_failed(f"Server unreachable: {self.server_url}")
            return False
        except Exception as e:
            # Registration failed - enter offline mode
            logger.warning(f"⚠️  Registration exception: {str(e)} - entering offline mode")
            self.offline_mode = True
            self.cli.prompt_registration_failed(str(e))
            return False

    def _get_dns_servers(self) -> List[str]:
        """Get DNS servers"""
        try:
            if platform.system() == "Windows":
                import winreg
                try:
                    key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                    )
                    dns_servers, _ = winreg.QueryValueEx(key, "NameServer")
                    return dns_servers.split(",") if dns_servers else []
                except:
                    return []
            else:
                # Linux/macOS DNS detection
                try:
                    with open("/etc/resolv.conf", "r") as f:
                        dns_servers = []
                        for line in f:
                            if line.startswith("nameserver"):
                                dns_servers.append(line.split()[1])
                        return dns_servers
                except:
                    return []
        except Exception as e:
            logger.debug(f"DNS detection failed")
            return []

    # ===== CALLBACK HANDLERS =====

    def _handle_threat_verdict(self, verdict: Dict):
        """Handle threat analysis verdict - MINIMAL PROMPT"""
        artifact_type = verdict['artifact_type']
        artifact = verdict['artifact']
        verdict_result = verdict['verdict']
        risk = verdict['risk']
        
        # Only show if NOT SAFE
        if verdict_result == 'SAFE':
            self.cli.prompt_threat_safe(artifact_type, artifact)
        elif verdict_result == 'SUSPICIOUS':
            self.cli.prompt_threat_suspicious(artifact_type, artifact)
        elif verdict_result == 'MALICIOUS':
            self.cli.prompt_threat_malicious(artifact_type, artifact)
            # Auto-block malicious artifacts
            if artifact_type == 'ip':
                self.prevention_system.block_ip(artifact, reason="Malicious detected")
            elif artifact_type == 'url' or artifact_type == 'domain':
                from urllib.parse import urlparse
                domain = urlparse(artifact).netloc or artifact
                self.prevention_system.block_domain(domain, reason="Malicious detected")
    
    def _handle_attack(self, attack: Dict):
        """Handle detected attack from IntrusionDetector"""
        logger.critical(f"🚨 ATTACK DETECTED: {attack['type']} from {attack.get('source_ip', 'UNKNOWN')}")

        # Forward to backend so dashboard receives real-time attack visibility
        self._report_intrusion_attack(attack)
        
        # Pass to defense coordinator for alerting
        self.defense_coordinator.handle_attack(attack)
        
        # Analyze the attack with AI
        if attack.get('source_ip') and attack['source_ip'] != 'UNKNOWN' and attack['source_ip'] != 'MULTIPLE':
            try:
                analysis = self.activity_analyzer.analyze_ip(attack['source_ip'])
                
                # If high/critical risk, auto-block
                if analysis['risk_level'] in ['HIGH', 'CRITICAL']:
                    self.prevention_system.block_ip(
                        attack['source_ip'],
                        reason=f"{attack['type']}: {analysis['risk_level']} risk"
                    )
            except Exception as e:
                logger.debug(f"Attack source analysis failed")

    def _report_intrusion_attack(self, attack: Dict):
        """Report IDS attack to backend attack-events API for dashboard/monitoring."""
        try:
            severity = str(attack.get('severity', 'MEDIUM')).lower()
            if severity not in {'low', 'medium', 'high', 'critical'}:
                severity = 'medium'

            source_ip = attack.get('source_ip')
            source_hostname = attack.get('source_hostname') or attack.get('source_domain')

            attack_timestamp = attack.get('timestamp')
            if hasattr(attack_timestamp, 'isoformat'):
                attack_timestamp = attack_timestamp.isoformat()
            elif not attack_timestamp:
                attack_timestamp = datetime.utcnow().isoformat()

            payload = {
                'client_id': self.server_client_id or self.local_runtime_id,
                'attack_type': attack.get('type', 'intrusion_detected'),
                'source_ip': source_ip,
                'source_domain': source_hostname,
                'destination_port': attack.get('target_port'),
                'severity': severity,
                'description': attack.get('description') or attack.get('short_description') or 'Intrusion detected by IDS',
                'indicators': {
                    'source_hostname': source_hostname,
                    'short_description': attack.get('short_description'),
                    'attack_family': attack.get('attack_family'),
                    'tool_signature': attack.get('tool_signature'),
                    'prediction_summary': attack.get('prediction_summary'),
                    'predicted_next_step': attack.get('predicted_next_step'),
                    'prediction_confidence': attack.get('prediction_confidence'),
                    'mitigation_commands': attack.get('mitigation_commands') or [],
                    'recommended_action': attack.get('recommended_action'),
                    'timestamp': attack_timestamp,
                    'raw': {k: v for k, v in attack.items() if k not in {'timestamp'}},
                },
            }

            response = requests.post(
                f"{self.server_url}/api/v1/network/attack/report",
                headers=self._get_headers(),
                json=payload,
                timeout=10,
            )
            if response.status_code != 200:
                logger.debug(f"Attack report rejected: HTTP {response.status_code}")
        except Exception:
            logger.debug("Failed to report IDS attack to backend")

    def _handle_activity_alert(self, activity: Dict):
        """Handle activity alerts from ActivityLogger"""
        activity_type = activity.get('type')
        
        if activity_type == 'RISKY_WEBSITE':
            logger.warning(f"🚨 THREAT: Risky website")
            
            # Analyze with AI
            try:
                analysis = self.activity_analyzer.analyze_website(
                    activity['url'],
                    activity['domain']
                )
                
                # Show warning to user
                should_proceed = self.prevention_system.warn_user(
                    'RISKY_WEBSITE',
                    activity['domain'],
                    analysis
                )
                
                # If critical or user chose to block, block the domain
                if not should_proceed or analysis['risk_level'] == 'CRITICAL':
                    self.prevention_system.block_domain(
                        activity['domain'],
                        reason=f"Risky website: {analysis['risk_level']}"
                    )
                    
            except Exception as e:
                logger.debug(f"Website analysis failed")

    def _send_defense_event_to_server(self, event: Dict):
        """Send defense events to server"""
        try:
            event['client_id'] = self.server_client_id or self.local_runtime_id

            headers = self._get_headers()
            endpoints = [
                f"{self.server_url}/api/v1/network/event",  # current router prefix
                f"{self.server_url}/api/v1/defense/event",  # backward compatibility
            ]

            for endpoint in endpoints:
                response = requests.post(
                    endpoint,
                    headers=headers,
                    json=event,
                    timeout=10,
                )
                if response.status_code == 200:
                    logger.debug("Defense event sent")
                    return

            logger.debug("Defense event send failed")
                
        except Exception as e:
            logger.debug("Defense event send failed")

    def _handle_prevention_event(self, event: Dict):
        """Handle prevention system events"""
        logger.debug(f"Prevention event")
        
        # Send to server
        self._send_defense_event_to_server(event)

    def _handle_extended_monitor_event(self, event: Dict):
        """Handle events from USB, email, DNS, behavioral and vulnerability monitors."""
        try:
            event_type = event.get('type', '')
            risk = event.get('risk') or event.get('severity') or 'LOW'

            if event_type in ['usb_insert', 'usb_file_quarantined', 'email_threat', 'dns_threat', 'behavioral_alert']:
                if event_type == 'email_threat':
                    logger.warning("📧 Threat email detected")
                elif event_type == 'dns_threat':
                    logger.warning("🌐 DNS threat detected")
                elif event_type == 'behavioral_alert':
                    logger.warning("🧠 Behavioral anomaly detected")
                elif event_type == 'usb_file_quarantined':
                    logger.warning("🔌 USB file quarantined")

            # Forward high/critical events to defense pipeline
            if str(risk).upper() in ['HIGH', 'CRITICAL']:
                attack_payload = {
                    'type': event_type or 'extended_monitor_alert',
                    'severity': str(risk).upper(),
                    'description': event.get('description') or event.get('reason') or event_type,
                    'source_ip': event.get('source_ip') or event.get('remote_ip') or 'UNKNOWN',
                    'timestamp': datetime.now()
                }
                self.defense_coordinator.handle_attack(attack_payload)

            # Send raw event upstream too
            self._send_defense_event_to_server({
                'event': 'EXTENDED_MONITOR_EVENT',
                'monitor_event': event
            })
        except Exception:
            logger.debug("Extended monitor event handling failed")

    # ===== MONITORING LOOPS =====

    async def send_heartbeat(self):
        """Send heartbeat to server (only if registered)"""
        while self.running:
            # Only send heartbeat if registered
            if not self.is_registered:
                logger.debug("⏸️  Heartbeat skipped: not registered")
                await asyncio.sleep(self.heartbeat_interval)
                continue
                
            if not self.server_client_id:
                logger.warning("⏸️  Heartbeat skipped: no server client_id")
                await asyncio.sleep(self.heartbeat_interval)
                continue

            try:
                # Get status from all modules
                status = {
                    'intrusion_detector': self.intrusion_detector.get_statistics(),
                    'activity_logger': self.activity_logger.get_recent_activities(hours=1),
                    'defense_coordinator': self.defense_coordinator.get_status(),
                    'prevention_system': self.prevention_system.get_statistics(),
                    'threat_analyzer': self.threat_analyzer.get_statistics(),
                    'usb_monitor': self.usb_monitor.get_events_summary(),
                    'email_monitor': self.email_monitor.get_summary(),
                    'vulnerability_scanner': self.vulnerability_scanner.get_summary(),
                    'behavioral_monitor': self.behavioral_monitor.get_summary(),
                    'dns_monitor': self.dns_monitor.get_summary(),
                    'network_scanner': self.network_scanner.get_summary(),
                    'process_scanner': self.process_scanner.get_summary()
                }
                
                response = requests.post(
                    f"{self.server_url}/api/v1/network/client/heartbeat",
                    params={"client_id": self.server_client_id},
                    headers=self._get_headers(),
                    json={'status': status},
                    timeout=10,
                )

                if response.status_code == 200:
                    logger.debug(f"💓 Heartbeat sent (client_id={self.server_client_id})")
                else:
                    logger.warning(f"💓 Heartbeat failed ({self.server_client_id}): HTTP {response.status_code}")
                    if response.status_code == 403:
                        logger.warning("💓 Access denied - client may have been deactivated")

            except Exception as e:
                logger.warning(f"💓 Heartbeat error ({self.server_client_id}): {str(e)}")

            await asyncio.sleep(self.heartbeat_interval)

    async def activity_analysis_loop(self):
        """Periodically analyze logged activities"""
        while self.running:
            try:
                # Get recent activities
                activities = self.activity_logger.get_recent_activities(hours=1)
                
                # Analyze recent websites
                for website in activities['websites'][-10:]:  # Last 10 websites
                    url, domain, browser, risk_level, timestamp = website
                    
                    # If not yet analyzed or risk unknown
                    if risk_level in ['UNKNOWN', 'MEDIUM']:
                        try:
                            analysis = self.activity_analyzer.analyze_website(url, domain)
                            
                            # Update risk level in database
                            # (ActivityLogger handles this internally)
                            
                            # If high risk, take action
                            if analysis['risk_level'] in ['HIGH', 'CRITICAL']:
                                should_proceed = self.prevention_system.warn_user(
                                    'RISKY_WEBSITE',
                                    domain,
                                    analysis
                                )
                                
                                if not should_proceed:
                                    self.prevention_system.block_domain(
                                        domain,
                                        reason=f"AI Analysis: {analysis['risk_level']}"
                                    )
                                    
                        except Exception as e:
                            logger.debug(f"Website analysis failed")
                
                await asyncio.sleep(300)  # Analyze every 5 minutes
                
            except Exception as e:
                logger.debug(f"Activity analysis error")
                await asyncio.sleep(60)

    async def start_monitoring(self):
        """Start all monitoring and defense systems"""
        if not self.is_registered and not self.offline_mode:
            logger.error("❌ Cannot start monitoring: not registered and not in offline mode")
            return

        self.running = True
        
        # Start all security modules
        self.threat_analyzer.start()  # Start background threat analysis
        self.intrusion_detector.start()
        self.activity_logger.start()
        self.defense_coordinator.start()
        self.prevention_system.start()
        self.usb_monitor.start()
        self.email_monitor.start()
        self.vulnerability_scanner.start()
        self.behavioral_monitor.start()
        self.dns_monitor.start()
        self.network_scanner.start()
        self.process_scanner.start()
        
        # Start background tasks
        tasks = [
            asyncio.create_task(self.activity_analysis_loop()),
        ]
        
        # Only start heartbeat if registered
        if self.is_registered:
            tasks.append(asyncio.create_task(self.send_heartbeat()))
            logger.info("🚀 Monitoring started with server connectivity")
        else:
            logger.info("🚀 Monitoring started in offline mode (no heartbeat)")

        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            self.stop_monitoring()
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
            self.stop_monitoring()

    def stop_monitoring(self):
        """Stop all monitoring and defense systems"""
        self.running = False
        
        self.threat_analyzer.stop()  # Stop threat analysis
        self.intrusion_detector.stop()
        self.activity_logger.stop()
        self.defense_coordinator.stop()
        self.prevention_system.stop()
        self.usb_monitor.stop()
        self.email_monitor.stop()
        self.vulnerability_scanner.stop()
        self.behavioral_monitor.stop()
        self.dns_monitor.stop()
        self.network_scanner.stop()
        self.process_scanner.stop()
        
        logger.info("✅ All security modules stopped")

    # ===== MANUAL SCAN METHODS (backward compatibility) =====

    async def scan_file(self, file_path: Path) -> Dict:
        """Scan a file for threats using comprehensive file scanner"""
        try:
            if not file_path.exists():
                return {"error": "File not found"}

            # Use the comprehensive file scanner
            scan_result = self.file_scanner.scan_file(str(file_path))
            
            # Send to threat analyzer for external API checks
            if self.threat_analyzer and scan_result.get("risk_level") in ["MEDIUM", "HIGH", "CRITICAL"]:
                self.threat_analyzer.queue_scan(
                    "file", scan_result.get("sha256", ""), 
                    metadata={"file_path": str(file_path), "scan_result": scan_result}
                )
            
            # If malicious, quarantine
            if scan_result.get('risk_level') in ['HIGH', 'CRITICAL']:
                self.prevention_system.block_file(
                    str(file_path),
                    reason=f"Malware detected: {scan_result['risk_level']}"
                )
                # Trigger defense coordinator alert
                self.defense_coordinator.handle_attack({
                    "type": "malware_file",
                    "source_file": str(file_path),
                    "severity": scan_result['risk_level'],
                    "details": scan_result
                })
            
            return scan_result
            
        except Exception as e:
            logger.debug(f"File scan failed: {e}")
            return {"error": "Scan failed"}

    async def scan_url(self, url: str) -> Dict:
        """Scan a URL for threats"""
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            
            # Analyze with AI
            analysis = self.activity_analyzer.analyze_website(url, domain)
            
            # If malicious, block
            if analysis['risk_level'] in ['HIGH', 'CRITICAL']:
                self.prevention_system.block_domain(
                    domain,
                    reason=f"Malicious website: {analysis['risk_level']}"
                )
            
            return analysis
            
        except Exception as e:
            logger.debug(f"URL scan failed")
            return {"error": "Scan failed"}

    async def scan_ip(self, ip_address: str) -> Dict:
        """Scan an IP address for threats"""
        try:
            # Analyze with AI
            analysis = self.activity_analyzer.analyze_ip(ip_address)
            
            # If malicious, block
            if analysis['risk_level'] in ['HIGH', 'CRITICAL']:
                self.prevention_system.block_ip(
                    ip_address,
                    reason=f"Malicious IP: {analysis['risk_level']}"
                )
            
            return analysis
            
        except Exception as e:
            logger.debug(f"IP scan failed")
            return {"error": "Scan failed"}

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    # ===== STATUS & CONTROL =====

    def get_status(self) -> Dict:
        """Get comprehensive system status"""
        return {
            'local_runtime_id': self.local_runtime_id,
            'server_client_id': self.server_client_id,
            'is_registered': self.is_registered,
            'offline_mode': self.offline_mode,
            'admin_infrastructure': self._is_admin_infrastructure,
            'running': self.running,
            'intrusion_detector': self.intrusion_detector.get_statistics(),
            'defense_coordinator': self.defense_coordinator.get_status(),
            'prevention_system': self.prevention_system.get_statistics(),
            'threat_analyzer': self.threat_analyzer.get_statistics(),
            'usb_monitor': self.usb_monitor.get_events_summary(),
            'email_monitor': self.email_monitor.get_summary(),
            'vulnerability_scanner': self.vulnerability_scanner.get_summary(),
            'behavioral_monitor': self.behavioral_monitor.get_summary(),
            'dns_monitor': self.dns_monitor.get_summary(),
            'network_scanner': self.network_scanner.get_summary(),
            'process_scanner': self.process_scanner.get_summary(),
            'activity_logger': {
                'websites_logged': len(self.activity_logger.get_recent_activities(hours=24)['websites']),
                'applications_logged': len(self.activity_logger.get_recent_activities(hours=24)['applications']),
                'blocked_activities': len(self.activity_logger.get_recent_activities(hours=24)['blocked'])
            }
        }

    def lift_quarantine(self, admin_password: str = None):
        """Lift system quarantine (requires admin)"""
        return self.defense_coordinator.lift_quarantine(admin_password)


async def main():
    """Main entry point"""
    client = SentinelClientV3()

    logger.info(f"🚀 Initializing SENTINEL-AI Client v3.0")
    logger.info(f"   Runtime ID: {client.local_runtime_id[:8]}...")
    logger.info(f"   Server: {client.server_url}")
    
    registered = await client.register()
    
    if registered:
        logger.info(f"✅ Online mode: registered as {client.server_client_id}")
    elif client.offline_mode:
        logger.info(f"⚠️  Offline mode: registration failed, running locally")
    else:
        logger.error(f"❌ Failed to initialize: registration failed")
        return
    
    await client.start_monitoring()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
