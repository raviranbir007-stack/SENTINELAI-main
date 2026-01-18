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
import hashlib
import json
import logging
import platform
import socket
import subprocess
import sys
import time
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

# Configuration
CONFIG_FILE = Path("config.ini")
LOG_FILE = Path("sentinel_client_v3.log")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)

logger = logging.getLogger("SentinelAI_v3")


class SentinelClientV3:
    """
    SENTINEL-AI Client v3.0 with real-time defense capabilities
    """

    def __init__(self, config_path: Path = CONFIG_FILE):
        self.config = self._load_config(config_path)
        self.server_url = self.config.get("server", {}).get("url", "http://localhost:5000")
        self.api_key = self.config.get("server", {}).get("api_key", "your-api-key")
        self.client_id = None
        self.running = False

        # Load API keys for threat intelligence
        self.api_keys = {
            'virustotal': self.config.get("apis", {}).get("virustotal", ""),
            'abuseipdb': self.config.get("apis", {}).get("abuseipdb", ""),
            'urlscan': self.config.get("apis", {}).get("urlscan", ""),
            'shodan': self.config.get("apis", {}).get("shodan", ""),
            'hybrid_analysis': self.config.get("apis", {}).get("hybrid_analysis", "")
        }

        # Configuration
        self.scan_interval = int(self.config.get("client", {}).get("scan_interval", 300))
        self.heartbeat_interval = int(self.config.get("client", {}).get("heartbeat_interval", 60))
        
        # Initialize security modules
        logger.info("Initializing security modules...")
        
        # 1. Intrusion Detection System
        self.intrusion_detector = IntrusionDetector(callback=self._handle_attack)
        
        # 2. Activity Logger (websites, apps)
        self.activity_logger = ActivityLogger(callback=self._handle_activity_alert)
        
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
        
        logger.info("✅ All security modules initialized")

    def _load_config(self, config_path: Path) -> Dict:
        """Load configuration from file"""
        try:
            if config_path.exists():
                import configparser
                config = configparser.ConfigParser()
                config.read(config_path)
                return {section: dict(config.items(section)) for section in config.sections()}
            else:
                logger.warning(f"Config file not found: {config_path}, using defaults")
                return {
                    'server': {'url': 'http://localhost:5000', 'api_key': 'your-api-key'},
                    'client': {'scan_interval': '300', 'heartbeat_interval': '60'},
                    'apis': {}
                }
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return {}

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication"""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def register(self) -> bool:
        """Register client with the server"""
        try:
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
                "network_segment": network_segment,
                "gateway": gateway,
                "dns_servers": self._get_dns_servers(),
                "version": "3.0.0",
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
                timeout=30,
            )

            if response.status_code == 200:
                result = response.json()
                self.client_id = result.get("client_id")
                logger.info(f"✅ Client registered successfully: {self.client_id}")
                return True
            else:
                logger.error(f"Registration failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Registration error: {e}")
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
            logger.debug(f"Failed to get DNS servers: {e}")
            return []

    # ===== CALLBACK HANDLERS =====

    def _handle_attack(self, attack: Dict):
        """Handle detected attack from IntrusionDetector"""
        logger.critical(f"🚨 ATTACK DETECTED: {attack['type']} from {attack.get('source_ip', 'UNKNOWN')}")
        
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
                logger.error(f"Failed to analyze attack source: {e}")

    def _handle_activity_alert(self, activity: Dict):
        """Handle activity alerts from ActivityLogger"""
        activity_type = activity.get('type')
        
        if activity_type == 'RISKY_WEBSITE':
            logger.warning(f"⚠️  Risky website detected: {activity['url']}")
            
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
                logger.error(f"Failed to analyze website: {e}")

    def _send_defense_event_to_server(self, event: Dict):
        """Send defense events to server"""
        try:
            event['client_id'] = self.client_id
            
            response = requests.post(
                f"{self.server_url}/api/v1/defense/event",
                headers=self._get_headers(),
                json=event,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.debug(f"Defense event sent: {event['event']}")
            else:
                logger.warning(f"Failed to send defense event: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Failed to send defense event: {e}")

    def _handle_prevention_event(self, event: Dict):
        """Handle prevention system events"""
        logger.info(f"Prevention event: {event['event']}")
        
        # Send to server
        self._send_defense_event_to_server(event)

    # ===== MONITORING LOOPS =====

    async def send_heartbeat(self):
        """Send heartbeat to server"""
        while self.running:
            try:
                # Get status from all modules
                status = {
                    'intrusion_detector': self.intrusion_detector.get_statistics(),
                    'activity_logger': self.activity_logger.get_recent_activities(hours=1),
                    'defense_coordinator': self.defense_coordinator.get_status(),
                    'prevention_system': self.prevention_system.get_statistics()
                }
                
                response = requests.post(
                    f"{self.server_url}/api/v1/network/client/heartbeat",
                    params={"client_id": self.client_id},
                    headers=self._get_headers(),
                    json={'status': status},
                    timeout=10,
                )

                if response.status_code == 200:
                    logger.debug("Heartbeat sent successfully")
                else:
                    logger.warning(f"Heartbeat failed: {response.status_code}")

            except Exception as e:
                logger.error(f"Heartbeat error: {e}")

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
                            logger.debug(f"Failed to analyze website {domain}: {e}")
                
                await asyncio.sleep(300)  # Analyze every 5 minutes
                
            except Exception as e:
                logger.error(f"Activity analysis error: {e}")
                await asyncio.sleep(60)

    async def start_monitoring(self):
        """Start all monitoring and defense systems"""
        if not self.client_id:
            logger.error("Client not registered. Call register() first.")
            return

        self.running = True
        
        # Start all security modules
        logger.info("🚀 Starting all security modules...")
        
        self.intrusion_detector.start()
        self.activity_logger.start()
        self.defense_coordinator.start()
        self.prevention_system.start()
        
        logger.info("✅ All security modules running")
        logger.info("="*60)
        logger.info("SENTINEL-AI v3.0 is now protecting your system")
        logger.info("="*60)
        
        # Start background tasks
        tasks = [
            asyncio.create_task(self.send_heartbeat()),
            asyncio.create_task(self.activity_analysis_loop()),
        ]

        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
            self.stop_monitoring()
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
            self.stop_monitoring()

    def stop_monitoring(self):
        """Stop all monitoring and defense systems"""
        self.running = False
        
        logger.info("Stopping security modules...")
        
        self.intrusion_detector.stop()
        self.activity_logger.stop()
        self.defense_coordinator.stop()
        self.prevention_system.stop()
        
        logger.info("✅ All security modules stopped")

    # ===== MANUAL SCAN METHODS (backward compatibility) =====

    async def scan_file(self, file_path: Path) -> Dict:
        """Scan a file for threats"""
        try:
            if not file_path.exists():
                return {"error": "File not found"}

            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            
            # Analyze with AI
            analysis = self.activity_analyzer.analyze_file(str(file_path), file_hash)
            
            # If malicious, quarantine
            if analysis['risk_level'] in ['HIGH', 'CRITICAL']:
                self.prevention_system.block_file(
                    str(file_path),
                    reason=f"Malware detected: {analysis['risk_level']}"
                )
            
            return analysis
            
        except Exception as e:
            logger.error(f"File scan error: {e}")
            return {"error": str(e)}

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
            logger.error(f"URL scan error: {e}")
            return {"error": str(e)}

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
            logger.error(f"IP scan error: {e}")
            return {"error": str(e)}

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
            'client_id': self.client_id,
            'running': self.running,
            'intrusion_detector': self.intrusion_detector.get_statistics(),
            'defense_coordinator': self.defense_coordinator.get_status(),
            'prevention_system': self.prevention_system.get_statistics(),
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
    print("="*70)
    print("           SENTINEL-AI Client v3.0")
    print("     Real-Time Defense & Activity Monitoring")
    print("="*70)
    print()
    print("Features:")
    print("  ✓ Real-time intrusion detection")
    print("  ✓ Website & application monitoring")
    print("  ✓ AI-powered threat analysis (5 APIs + Gemini)")
    print("  ✓ Auto-quarantine on repeated attacks")
    print("  ✓ Proactive blocking & prevention")
    print()
    print("="*70)
    print()

    # Initialize client
    client = SentinelClientV3()

    # Register with server
    print("📡 Registering with server...")
    if await client.register():
        print(f"✅ Registration successful - Client ID: {client.client_id}")
        print()

        # Start monitoring
        print("🚀 Starting real-time protection...")
        print("   Press Ctrl+C to stop")
        print()

        await client.start_monitoring()
    else:
        print("❌ Registration failed. Check configuration and try again.")
        print(f"   Server URL: {client.server_url}")
        print(f"   API Key: {'*' * 10 if client.api_key else 'NOT SET'}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n")
        print("="*70)
        print("SENTINEL-AI v3.0 stopped by user")
        print("="*70)
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
