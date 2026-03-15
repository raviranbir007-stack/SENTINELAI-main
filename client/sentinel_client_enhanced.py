"""
Enhanced SENTINEL-AI Client with Network Monitoring and Auto-Defense
Automatically registers with server, monitors system, and defends against attacks
"""

import asyncio
from collections import defaultdict
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
try:
    FileSystemEventHandler = __import__("watchdog.events", fromlist=["FileSystemEventHandler"]).FileSystemEventHandler
    Observer = __import__("watchdog.observers", fromlist=["Observer"]).Observer
    _WATCHDOG_AVAILABLE = True
except ImportError:
    _WATCHDOG_AVAILABLE = False

    class FileSystemEventHandler:  # Fallback no-op class
        pass

    class Observer:  # Fallback no-op observer
        def schedule(self, *args, **kwargs):
            return None

        def start(self):
            return None

        def stop(self):
            return None

        def join(self, timeout=None):
            return None

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
        self._hostname_cache: Dict[str, tuple[float, Optional[str]]] = {}

        # Lightweight IDS heuristics for broad attack monitoring
        self.connection_attempts = defaultdict(list)  # IP -> [timestamps]
        self.port_attempts = defaultdict(list)  # IP -> [(timestamp, local service port)]
        self.alert_cooldown = {}  # IP -> timestamp
        self.time_window = int(self.config.get("defense", {}).get("time_window", 60))
        self.max_scan_ports = int(self.config.get("defense", {}).get("max_scan_ports", 12))
        self.max_bruteforce_attempts = int(self.config.get("defense", {}).get("max_bruteforce_attempts", 20))
        self.max_web_probe_attempts = int(self.config.get("defense", {}).get("max_web_probe_attempts", 35))
        self.alert_cooldown_seconds = int(self.config.get("defense", {}).get("alert_cooldown_seconds", 180))
        self.auth_ports = {21, 22, 23, 25, 110, 143, 445, 993, 995, 1433, 3306, 3389, 5432, 6379}
        self.web_ports = {80, 443, 8080, 8443}
        self.metasploit_ports = {4444, 5555, 6666}

        # Monitoring configuration
        self.scan_interval = int(self.config.get("client", {}).get("scan_interval", 300))
        self.heartbeat_interval = int(self.config.get("client", {}).get("heartbeat_interval", 60))

        if not _WATCHDOG_AVAILABLE:
            logger.warning("watchdog package not available; filesystem realtime hooks are disabled")

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

    def _is_private_or_local_ip(self, ip: str) -> bool:
        """Filter internal addresses from attacker heuristics."""
        try:
            import ipaddress

            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except Exception:
            return ip.startswith(("127.", "192.168.", "10.", "172."))

    def _cleanup_tracking_state(self, now: datetime):
        """Cleanup old timestamps to keep memory bounded."""
        cutoff = now.timestamp() - self.time_window

        for ip in list(self.connection_attempts.keys()):
            recent = [ts for ts in self.connection_attempts[ip] if ts >= cutoff]
            if recent:
                self.connection_attempts[ip] = recent
            else:
                del self.connection_attempts[ip]

        for ip in list(self.port_attempts.keys()):
            if ip in self.port_attempts:
                self.port_attempts[ip] = [
                    (ts, p) for ts, p in self.port_attempts[ip] if ts >= cutoff
                ]
            if ip not in self.connection_attempts or not self.port_attempts[ip]:
                del self.port_attempts[ip]

        for ip in list(self.alert_cooldown.keys()):
            if now.timestamp() - self.alert_cooldown[ip] > max(self.alert_cooldown_seconds * 3, 600):
                del self.alert_cooldown[ip]

    def _resolve_source_hostname(self, ip: Optional[str]) -> Optional[str]:
        """Best-effort reverse DNS lookup with cache."""
        try:
            if not ip or self._is_private_or_local_ip(ip):
                return None

            now = time.time()
            cached = self._hostname_cache.get(ip)
            if cached and (now - cached[0]) < 1800:
                return cached[1]

            try:
                host = socket.gethostbyaddr(ip)[0]
            except Exception:
                host = None

            self._hostname_cache[ip] = (now, host)
            return host
        except Exception:
            return None

    def _predict_attack(self, attack_type: str) -> Dict:
        """Predict likely next step for proactive defense."""
        mapping = {
            "NMAP_RECON": (
                "Likely exploit attempt after reconnaissance",
                "EXPLOIT_OR_BRUTE_FORCE",
                0.82,
            ),
            "BRUTE_FORCE_ATTEMPT": (
                "Likely credential compromise / lateral movement",
                "CREDENTIAL_COMPROMISE",
                0.88,
            ),
            "METASPLOIT_PROBE": (
                "Likely reverse shell or meterpreter session attempt",
                "REMOTE_CODE_EXECUTION",
                0.91,
            ),
            "WEB_INJECTION_RECON": (
                "Likely SQL injection / command injection payload delivery",
                "WEB_APP_COMPROMISE",
                0.79,
            ),
        }
        summary, step, confidence = mapping.get(
            attack_type,
            ("Likely escalation against exposed services", "ESCALATION_ATTEMPT", 0.66),
        )
        return {
            "prediction_summary": summary,
            "predicted_next_step": step,
            "prediction_confidence": round(float(confidence), 2),
        }

    async def _handle_live_connection_pattern(self, remote_ip: str, local_port: int):
        """Detect broad cyber-attack patterns from live connection behavior."""
        now = datetime.utcnow()
        now_ts = now.timestamp()

        if not remote_ip or self._is_private_or_local_ip(remote_ip):
            return

        self.connection_attempts[remote_ip].append(now_ts)
        if local_port > 0:
            self.port_attempts[remote_ip].append((now_ts, local_port))

        # Anti-spam cooldown
        last_alert = self.alert_cooldown.get(remote_ip, 0)
        if now_ts - last_alert < self.alert_cooldown_seconds:
            return

        recent_hits = [ts for ts in self.connection_attempts[remote_ip] if now_ts - ts <= self.time_window]
        recent_ports = [
            port
            for ts, port in self.port_attempts[remote_ip]
            if now_ts - ts <= self.time_window
        ]
        unique_ports = set(recent_ports)

        attack_type = None
        severity = "medium"
        description = ""
        short_description = ""
        mitigation_commands: List[str] = []
        tool_signature = None
        attack_family = None
        recommended_action = None

        auth_hits = sum(1 for p in recent_ports if p in self.auth_ports)
        web_hits = sum(1 for p in recent_ports if p in self.web_ports)
        metasploit_hits = sorted(list(unique_ports.intersection(self.metasploit_ports)))

        if metasploit_hits:
            attack_type = "METASPLOIT_PROBE"
            severity = "critical"
            attack_family = "METASPLOIT_PROBE"
            tool_signature = "METASPLOIT_PATTERN"
            description = f"Potential Metasploit probe detected on listener/payload ports: {metasploit_hits}"
            short_description = f"Metasploit-like activity on port {metasploit_hits[0]}"
            mitigation_commands = [
                f"sudo iptables -I INPUT -s {remote_ip} -j DROP",
                "sudo ss -tulpen | grep -E ':(4444|5555|6666)\\b'",
            ]
            recommended_action = "Block source IP and inspect host for reverse-shell callbacks"
        elif len(unique_ports) >= self.max_scan_ports:
            attack_type = "NMAP_RECON"
            severity = "high"
            attack_family = "RECONNAISSANCE"
            tool_signature = "NMAP_RECON"
            description = f"Port scan detected: {len(unique_ports)} service ports probed in {self.time_window}s"
            short_description = "Likely Nmap-style reconnaissance"
            mitigation_commands = [
                f"sudo iptables -I INPUT -s {remote_ip} -j DROP",
                "sudo apt install -y fail2ban && sudo systemctl enable --now fail2ban",
            ]
            recommended_action = "Block attacker IP and enable recon/burst rate-limits"
        elif auth_hits >= self.max_bruteforce_attempts:
            attack_type = "BRUTE_FORCE_ATTEMPT"
            severity = "high"
            attack_family = "BRUTE_FORCE"
            tool_signature = "HYDRA_MEDUSA_STYLE"
            description = f"Possible brute-force detected: {auth_hits} auth-port attempts in {self.time_window}s"
            short_description = "Likely brute-force login attack"
            mitigation_commands = [
                f"sudo iptables -I INPUT -s {remote_ip} -j DROP",
                "sudo systemctl restart ssh || true",
            ]
            recommended_action = "Block source IP and enforce MFA/lockout controls"
        elif web_hits >= self.max_web_probe_attempts:
            attack_type = "WEB_INJECTION_RECON"
            severity = "high"
            attack_family = "WEB_INJECTION_RECON"
            tool_signature = "WEB_RECON_PATTERN"
            description = f"High-rate web probing detected ({web_hits} hits): possible SQL injection/XSS recon"
            short_description = "Possible SQL injection reconnaissance"
            mitigation_commands = [
                f"sudo iptables -I INPUT -s {remote_ip} -j DROP",
                "sudo iptables -I INPUT -p tcp -m multiport --dports 80,443,8080,8443 -m conntrack --ctstate NEW -m recent --set",
            ]
            recommended_action = "Enable WAF + strict input validation for web endpoints"

        if not attack_type:
            return

        prediction = self._predict_attack(attack_type)
        source_hostname = self._resolve_source_hostname(remote_ip)
        indicators = {
            "source_hostname": source_hostname,
            "short_description": short_description,
            "attack_family": attack_family,
            "tool_signature": tool_signature,
            "mitigation_commands": mitigation_commands,
            "recommended_action": recommended_action,
            "attempt_count": len(recent_hits),
            "ports": sorted(list(unique_ports))[:20],
            **prediction,
            "timestamp": now.isoformat(),
        }

        await self.report_attack(
            attack_type=attack_type,
            source_ip=remote_ip,
            source_domain=source_hostname,
            severity=severity,
            description=description,
            indicators=indicators,
        )

        self.alert_cooldown[remote_ip] = now_ts
        if self.auto_block_threats and severity in {"high", "critical"}:
            await self.block_ip(remote_ip)

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
                data = {
                    "include_report": "false",
                    "client_id": self.client_id,
                    "scan_source": "client_protection",
                }

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
                json={
                    "target": url,
                    "include_report": False,
                    "client_id": self.client_id,
                    "scan_source": "client_protection",
                },
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
                json={
                    "target": ip_address,
                    "include_report": False,
                    "client_id": self.client_id,
                    "scan_source": "client_protection",
                },
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
        self,
        attack_type: str,
        source_ip: Optional[str] = None,
        source_domain: Optional[str] = None,
        severity: str = "medium",
        description: str = "",
        indicators: Optional[Dict] = None,
    ) -> bool:
        """Report an attack to the server"""
        try:
            attack_data = {
                "client_id": self.client_id,
                "attack_type": attack_type,
                "source_ip": source_ip,
                "source_domain": source_domain,
                "severity": severity,
                "description": description,
                "indicators": indicators or {"timestamp": datetime.utcnow().isoformat()},
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
            source_hostname = self._resolve_source_hostname(source_ip)
            await self.report_attack(
                attack_type="malicious_content",
                source_ip=source_ip,
                source_domain=source_hostname,
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

            system = platform.system()

            # Linux: use iptables/ip6tables (both INPUT and OUTPUT)
            if system == "Linux":
                is_ipv6 = ":" in ip_address
                fw_cmd = "ip6tables" if is_ipv6 else "iptables"
                subprocess.run(["sudo", fw_cmd, "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
                subprocess.run(["sudo", fw_cmd, "-A", "OUTPUT", "-d", ip_address, "-j", "DROP"], check=True)

            # macOS: use pfctl table if available, fallback to route blackhole
            elif system == "Darwin":
                try:
                    subprocess.run(["sudo", "pfctl", "-E"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["sudo", "pfctl", "-t", "blocklist", "-T", "add", ip_address], check=True)
                except Exception:
                    subprocess.run(["sudo", "route", "-n", "add", "-host", ip_address, "127.0.0.1"], check=True)

            # Windows: use netsh
            elif system == "Windows":
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule", f"name=Block {ip_address}", "dir=in", f"remoteip={ip_address}", "action=block"],
                    check=True,
                )
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule", f"name=Block {ip_address} OUT", "dir=out", f"remoteip={ip_address}", "action=block"],
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

            existing = ""
            try:
                existing = hosts_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                existing = ""

            entry = f"127.0.0.1 {domain}"
            if entry not in existing:
                with open(hosts_file, "a", encoding="utf-8") as f:
                    marker = "# SentinelAI blocked domains"
                    if marker not in existing:
                        f.write(f"\n{marker}\n")
                    f.write(f"{entry}\n")

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
                        local_port = conn.laddr.port if conn.laddr else 0

                        # Skip local IPs
                        if self._is_private_or_local_ip(remote_ip):
                            continue

                        # Behavioral attack detection and prediction
                        await self._handle_live_connection_pattern(remote_ip, local_port)

                        # Scan suspicious connections
                        if remote_ip not in self.blocked_ips:
                            # Rate limit: only scan each IP once per session
                            if not hasattr(self, "_scanned_ips"):
                                self._scanned_ips = set()

                            if remote_ip not in self._scanned_ips:
                                logger.debug(f"Scanning connection to: {remote_ip}")
                                await self.scan_ip(remote_ip)
                                self._scanned_ips.add(remote_ip)

                self._cleanup_tracking_state(datetime.utcnow())

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
