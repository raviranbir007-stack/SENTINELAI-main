"""
Enhanced SENTINEL-AI Client with Network Monitoring and Auto-Defense
Automatically registers with server, monitors system, and defends against attacks
"""

import asyncio
import hashlib
import json
import logging
import platform
import socket
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import psutil
import requests
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# Configuration
CONFIG_FILE = Path("config.ini")
LOG_FILE = Path("sentinel_client.log")

# Setup logging - REDUCED VERBOSITY
logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
    ],
)

logger = logging.getLogger("SentinelClient")
# Add stdout handler only for CRITICAL and ERROR
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.ERROR)
console_handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(console_handler)


class SentinelClient:
    """Enhanced SENTINEL-AI client with auto-registration and defense"""

    def __init__(self, config_path: Path = CONFIG_FILE):
        self.config = self._load_config(config_path)
        self.server_url = self.config.get("server", {}).get("url", "http://localhost:5000")
        self.api_key = self.config.get("server", {}).get("api_key", "")
        self.client_id = str(uuid.uuid4())  # Generate unique client ID
        self.running = False
        self._scanned_ips = set()

        # Defense configuration
        self.auto_defense = self.config.get("client", {}).get("enable_auto_defense", True)
        self.auto_block_threats = self.config.get("defense", {}).get("auto_block_threats", True)
        self.blocked_ips = set()
        self.blocked_domains = set()

        # Monitoring configuration
        self.scan_interval = int(self.config.get("client", {}).get("scan_interval", 300))
        self.heartbeat_interval = int(self.config.get("client", {}).get("heartbeat_interval", 60))

    def _load_config(self, config_path: Path) -> Dict:
        """Load configuration from file"""
        try:
            if config_path.exists():
                import configparser

                config = configparser.ConfigParser()
                config.read(config_path)
                return {section: dict(config.items(section)) for section in config.sections()}
            else:
                logger.warning(f"Config file not found: {config_path}")
                return {}
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
            try:
                ip_address = socket.gethostbyname(hostname)
            except socket.gaierror:
                ip_address = "127.0.0.1"

            # Get MAC address
            mac_address = "00:00:00:00:00:00"
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == psutil.AF_LINK:
                        mac_address = addr.address
                        break
                if mac_address != "00:00:00:00:00:00":
                    break

            # Get network info
            gateways = psutil.net_if_stats()
            gateway = list(gateways.keys())[0] if gateways else "Unknown"

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
                "version": "2.0.0",
                "client_id": self.client_id,
            }

            response = requests.post(
                f"{self.server_url}/api/v1/network/client/register",
                headers=self._get_headers(),
                json=registration_data,
                timeout=30,
            )

            if response.status_code == 200:
                result = response.json()
                self.client_id = result.get("client_id", self.client_id)
                logger.info(f"✓ Client registered: {self.client_id}")
                return True
            else:
                logger.error(f"✗ Registration failed: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"✗ Registration error")
            return False

    def _get_dns_servers(self) -> List[str]:
        """Get DNS servers"""
        try:
            if platform.system() == "Windows":
                # Windows DNS detection
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
                with open("/etc/resolv.conf", "r") as f:
                    dns_servers = []
                    for line in f:
                        if line.startswith("nameserver"):
                            dns_servers.append(line.split()[1])
                    return dns_servers
        except Exception as e:
            logger.error(f"Failed to get DNS servers: {e}")
            return []

    async def send_heartbeat(self):
        """Send heartbeat to server"""
        while self.running:
            try:
                response = requests.post(
                    f"{self.server_url}/api/v1/network/client/heartbeat",
                    params={"client_id": self.client_id},
                    headers=self._get_headers(),
                    timeout=10,
                )

                if response.status_code == 200:
                    logger.debug("Heartbeat sent successfully")
                else:
                    logger.warning(f"Heartbeat failed: {response.status_code}")

            except Exception as e:
                logger.error(f"Heartbeat error: {e}")

            await asyncio.sleep(self.heartbeat_interval)

    async def scan_file(self, file_path: Path) -> Dict:
        """Scan a file for threats"""
        try:
            if not file_path.exists():
                return {"error": "File not found"}

            # Check file size
            max_size = int(self.config.get("scanning", {}).get("max_file_size", 100)) * 1024 * 1024
            if file_path.stat().st_size > max_size:
                logger.warning(f"File too large to scan: {file_path}")
                return {"error": "File too large"}

            # Upload and scan
            with open(file_path, "rb") as f:
                files = {"file": (file_path.name, f, "application/octet-stream")}
                data = {"include_report": "false", "client_id": self.client_id}

                response = requests.post(
                    f"{self.server_url}/api/v1/scan/file",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    files=files,
                    data=data,
                    timeout=120,
                )

                if response.status_code == 200:
                    result = response.json()
                    logger.info(
                        f"File scan complete: {file_path.name} - Threat Level: {result.get('threat_level')}"
                    )

                    # Auto-defend if threat detected
                    if self.auto_defense and result.get("threat_level") in ["suspicious", "malicious"]:
                        await self._handle_threat_detection(result)

                    return result
                else:
                    logger.error(f"File scan failed: {response.status_code}")
                    return {"error": "Scan failed"}

        except Exception as e:
            logger.error(f"File scan error: {e}")
            return {"error": str(e)}

    async def scan_url(self, url: str) -> Dict:
        """Scan a URL for threats"""
        try:
            response = requests.post(
                f"{self.server_url}/api/v1/scan/url",
                headers=self._get_headers(),
                json={"target": url, "include_report": False, "client_id": self.client_id},
                timeout=60,
            )

            if response.status_code == 200:
                result = response.json()
                logger.info(f"URL scan complete: {url} - Threat Level: {result.get('threat_level')}")

                # Auto-defend if threat detected
                if self.auto_defense and result.get("threat_level") in ["suspicious", "malicious"]:
                    await self._handle_threat_detection(result)

                return result
            else:
                logger.error(f"URL scan failed: {response.status_code}")
                return {"error": "Scan failed"}

        except Exception as e:
            logger.error(f"URL scan error: {e}")
            return {"error": str(e)}

    async def scan_ip(self, ip_address: str) -> Dict:
        """Scan an IP address for threats"""
        try:
            response = requests.post(
                f"{self.server_url}/api/v1/scan/ip",
                headers=self._get_headers(),
                json={"target": ip_address, "include_report": False, "client_id": self.client_id},
                timeout=60,
            )

            if response.status_code == 200:
                result = response.json()
                logger.info(f"IP scan complete: {ip_address} - Threat Level: {result.get('threat_level')}")

                # Auto-defend if threat detected
                if self.auto_defense and result.get("threat_level") in ["suspicious", "malicious"]:
                    await self._handle_threat_detection(result)

                return result
            else:
                logger.error(f"IP scan failed: {response.status_code}")
                return {"error": "Scan failed"}

        except Exception as e:
            logger.error(f"IP scan error: {e}")
            return {"error": str(e)}

    async def report_attack(
        self, attack_type: str, source_ip: Optional[str] = None, severity: str = "medium", description: str = ""
    ) -> bool:
        """Report an attack to the server"""
        try:
            attack_data = {
                "client_id": self.client_id,
                "attack_type": attack_type,
                "source_ip": source_ip,
                "severity": severity,
                "description": description,
                "indicators": {"timestamp": datetime.utcnow().isoformat()},
            }

            response = requests.post(
                f"{self.server_url}/api/v1/network/attack/report",
                headers=self._get_headers(),
                json=attack_data,
                timeout=30,
            )

            if response.status_code == 200:
                result = response.json()
                logger.warning(f"Attack reported: {result.get('event_id')} - {attack_type}")
                return True
            else:
                logger.error(f"Attack report failed: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Attack report error: {e}")
            return False

    async def _handle_threat_detection(self, scan_result: Dict):
        """Handle threat detection with auto-defense"""
        try:
            threat_level = scan_result.get("threat_level")
            target = scan_result.get("url") or scan_result.get("ip") or scan_result.get("hash")

            logger.warning(f"Threat detected: {target} - Level: {threat_level}")

            # Extract IP from URL if present
            source_ip = None
            if scan_result.get("url"):
                try:
                    from urllib.parse import urlparse

                    domain = urlparse(scan_result["url"]).netloc
                    source_ip = socket.gethostbyname(domain)
                except:
                    pass
            elif scan_result.get("ip"):
                source_ip = scan_result["ip"]

            # Report attack to server
            await self.report_attack(
                attack_type="malicious_content",
                source_ip=source_ip,
                severity="high" if threat_level == "malicious" else "medium",
                description=f"Detected {threat_level} content: {target}",
            )

            # Auto-block if enabled and high severity
            if self.auto_block_threats and threat_level == "malicious":
                if source_ip:
                    await self.block_ip(source_ip)

        except Exception as e:
            logger.error(f"Threat handling error: {e}")

    async def block_ip(self, ip_address: str) -> bool:
        """Block an IP address using firewall"""
        try:
            if ip_address in self.blocked_ips:
                logger.info(f"IP already blocked: {ip_address}")
                return True

            logger.warning(f"Blocking IP: {ip_address}")

            # Linux/macOS: use iptables
            if platform.system() in ["Linux", "Darwin"]:
                subprocess.run(
                    ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True
                )

            # Windows: use netsh
            elif platform.system() == "Windows":
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule", f"name=Block {ip_address}", "dir=in", f"remoteip={ip_address}", "action=block"],
                    check=True,
                )

            self.blocked_ips.add(ip_address)
            logger.info(f"IP blocked successfully: {ip_address}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block IP: {e}")
            return False
        except Exception as e:
            logger.error(f"Block IP error: {e}")
            return False

    async def block_domain(self, domain: str) -> bool:
        """Block a domain using hosts file"""
        try:
            if domain in self.blocked_domains:
                logger.info(f"Domain already blocked: {domain}")
                return True

            logger.warning(f"Blocking domain: {domain}")

            # Update hosts file
            hosts_file = Path("/etc/hosts") if platform.system() != "Windows" else Path("C:\\Windows\\System32\\drivers\\etc\\hosts")

            with open(hosts_file, "a") as f:
                f.write(f"\n127.0.0.1 {domain}\n")

            self.blocked_domains.add(domain)
            logger.info(f"Domain blocked successfully: {domain}")
            return True

        except Exception as e:
            logger.error(f"Block domain error: {e}")
            return False

    async def monitor_network_connections(self):
        """Monitor network connections for suspicious activity"""
        while self.running:
            try:
                connections = psutil.net_connections(kind="inet")

                for conn in connections:
                    if conn.status == "ESTABLISHED" and conn.raddr:
                        remote_ip = conn.raddr.ip

                        # Skip local IPs
                        if remote_ip.startswith(("127.", "192.168.", "10.", "172.")):
                            continue

                        # Scan suspicious connections
                        if remote_ip not in self.blocked_ips:
                            # Rate limit: only scan each IP once per session
                            if not hasattr(self, "_scanned_ips"):
                                self._scanned_ips = set()

                            if remote_ip not in self._scanned_ips:
                                logger.debug(f"Scanning connection to: {remote_ip}")
                                await self.scan_ip(remote_ip)
                                self._scanned_ips.add(remote_ip)

            except Exception as e:
                logger.error(f"Network monitoring error: {e}")

            await asyncio.sleep(30)  # Check every 30 seconds

    async def start_monitoring(self):
        """Start continuous monitoring"""
        if not self.client_id:
            logger.error("Client not registered. Call register() first.")
            return

        self.running = True
        logger.info("Starting SENTINEL-AI monitoring...")

        # Start background tasks
        tasks = [
            asyncio.create_task(self.send_heartbeat()),
            asyncio.create_task(self.monitor_network_connections()),
        ]

        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
            self.running = False
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
            self.running = False

    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
        logger.info("Stopping monitoring...")


async def main():
    """Main entry point"""
    client = SentinelClient()
    if await client.register():
        await client.start_monitoring()
    else:
        logger.error("Registration failed")
        sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
