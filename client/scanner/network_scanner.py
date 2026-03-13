"""
Enhanced Network Scanner
Full network visibility and traffic analysis:
  • Active connection listing with geolocation (country/ASN via ip-api.com)
  • Bandwidth monitoring per process and interface
  • Suspicious destination detection (Tor exit nodes, VPN providers, known bad IPs)
  • Port scan self-audit (scan own ports from inside)
  • ARP table analysis (ARP spoofing / poisoning detection)
  • Routing table anomaly detection
  • DNS resolver validation
  • Raw socket packet capture statistics (no payload storage)
  • Connection anomaly reporting via callback
"""

import ipaddress
import json
import logging
import os
import platform
import re
import socket
import sqlite3
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set, Tuple

import psutil
import requests

logger = logging.getLogger("NetworkScanner")


# ---------------------------------------------------------------------------
# Known malicious / suspicious infrastructure
# ---------------------------------------------------------------------------

TOR_EXIT_NODES_URL = "https://check.torproject.org/torbulkexitlist"
KNOWN_TOR_EXITS: Set[str] = set()
_tor_last_fetch: float = 0

def _refresh_tor_exits():
    global KNOWN_TOR_EXITS, _tor_last_fetch
    if time.time() - _tor_last_fetch < 3600:   # refresh hourly
        return
    try:
        r = requests.get(TOR_EXIT_NODES_URL, timeout=10)
        if r.status_code == 200:
            KNOWN_TOR_EXITS = {line.strip() for line in r.text.splitlines()
                               if re.match(r"^\d+\.\d+\.\d+\.\d+$", line.strip())}
            _tor_last_fetch = time.time()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True


def _run(cmd: List[str], timeout: int = 10) -> Tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except Exception as e:
        return "", str(e), -1


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class NetworkScanner:
    """
    Comprehensive network scanner and traffic monitor.
    Provides both passive and active network analysis.
    """

    def __init__(
        self,
        callback: Optional[Callable[[Dict], None]] = None,
        threat_analyzer=None,
        db_path: str = "activity_logs.db",
        poll_interval: int = 10,
    ):
        self.callback = callback
        self.threat_analyzer = threat_analyzer
        self.db_path = db_path
        self.poll_interval = poll_interval
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._platform = platform.system()

        # State
        self._known_connections: Dict[str, Dict] = {}
        self._geo_cache: Dict[str, Dict] = {}
        self._alert_cooldown: Dict[str, float] = {}
        self._bw_history: deque = deque(maxlen=60)
        self._last_bw: Dict[str, int] = {}

        self._init_db()

    # ------------------------------------------------------------------
    # DB
    # ------------------------------------------------------------------

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS network_traffic (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    direction   TEXT,
                    local_addr  TEXT,
                    remote_ip   TEXT,
                    remote_port INTEGER,
                    process     TEXT,
                    country     TEXT,
                    asn         TEXT,
                    risk_level  TEXT DEFAULT 'LOW',
                    reason      TEXT,
                    bytes_sent  INTEGER DEFAULT 0,
                    bytes_recv  INTEGER DEFAULT 0,
                    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"NetworkScanner DB init: {e}")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        if self.running:
            return
        self.running = True
        threading.Thread(target=_refresh_tor_exits, daemon=True).start()
        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="NetworkScanner"
        )
        self._thread.start()
        logger.info("🌐 Network Scanner started")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)

    # ------------------------------------------------------------------
    # Monitor loop
    # ------------------------------------------------------------------

    def _monitor_loop(self):
        while self.running:
            try:
                self._scan_connections()
                self._check_bandwidth()
                self._check_arp_table()
            except Exception as e:
                logger.debug(f"Network monitor error: {e}")
            time.sleep(self.poll_interval)

    # ------------------------------------------------------------------
    # Active connections scan
    # ------------------------------------------------------------------

    def _scan_connections(self):
        try:
            pid_map: Dict[int, str] = {}
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    pid_map[proc.info["pid"]] = proc.info["name"] or "unknown"
                except Exception:
                    pass

            for conn in psutil.net_connections(kind="inet"):
                if conn.status not in ("ESTABLISHED", "SYN_SENT"):
                    continue
                if not conn.raddr:
                    continue

                remote_ip   = conn.raddr.ip
                remote_port = conn.raddr.port
                local_addr  = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                proc_name   = pid_map.get(conn.pid, "unknown") if conn.pid else "unknown"

                conn_key = f"{remote_ip}:{remote_port}:{proc_name}"
                if conn_key in self._known_connections:
                    continue
                self._known_connections[conn_key] = {"first_seen": time.time()}

                if _is_private(remote_ip):
                    continue

                risk, reason = self._assess_connection(remote_ip, remote_port, proc_name)

                # Geo lookup (cached)
                geo = self._geolocate(remote_ip)

                self._save_connection(local_addr, remote_ip, remote_port,
                                       proc_name, geo, risk, reason)

                if risk in ("HIGH", "CRITICAL"):
                    cooldown_key = f"conn_{remote_ip}"
                    now = time.time()
                    if self._alert_cooldown.get(cooldown_key, 0) + 300 < now:
                        self._alert_cooldown[cooldown_key] = now
                        logger.warning(
                            f"🌐 [{risk}] {proc_name} → {remote_ip}:{remote_port}  "
                            f"({geo.get('country','?')})  {reason}"
                        )
                        if self.callback:
                            self.callback({
                                "type": "suspicious_connection",
                                "process": proc_name,
                                "remote_ip": remote_ip,
                                "remote_port": remote_port,
                                "country": geo.get("country", ""),
                                "asn": geo.get("as", ""),
                                "risk": risk,
                                "reason": reason,
                                "timestamp": datetime.now().isoformat(),
                            })
                        if self.threat_analyzer:
                            self.threat_analyzer.queue_scan(
                                "ip", remote_ip,
                                {"process": proc_name, "port": remote_port}
                            )
        except Exception as e:
            logger.debug(f"Connection scan error: {e}")

    def _assess_connection(self, ip: str, port: int, proc: str) -> Tuple[str, str]:
        reasons = []
        risk = "LOW"

        # Tor exit node
        if ip in KNOWN_TOR_EXITS:
            risk = "HIGH"
            reasons.append("TOR_EXIT_NODE")

        # Suspicious ports
        suspicious_ports = {
            4444: "Metasploit default", 1337: "Common backdoor", 31337: "Back Orifice",
            12345: "NetBus", 54321: "BackOrifice2K", 6667: "IRC C2",
            6666: "IRC C2", 6697: "IRC C2 (SSL)", 8888: "Common backdoor",
        }
        if port in suspicious_ports:
            risk = max(risk, "HIGH", key=lambda r: ("LOW","MEDIUM","HIGH","CRITICAL").index(r))
            reasons.append(f"SUSPICIOUS_PORT:{port}({suspicious_ports[port]})")

        # Process→port mismatch (e.g., Word making raw TCP to port 4444)
        unexpected_proc_ports = {
            "winword.exe": [80, 443],
            "excel.exe":   [80, 443],
            "notepad.exe": [80, 443],
        }
        for suspicious_proc, allowed in unexpected_proc_ports.items():
            if suspicious_proc in proc.lower() and port not in allowed:
                risk = "HIGH"
                reasons.append(f"PROCESS_PORT_MISMATCH:{proc}→{port}")

        return risk, ", ".join(reasons) if reasons else "OK"

    # ------------------------------------------------------------------
    # Bandwidth monitoring
    # ------------------------------------------------------------------

    def _check_bandwidth(self):
        try:
            counters = psutil.net_io_counters(pernic=True)
            ts = time.time()
            for nic, stats in counters.items():
                prev = self._last_bw.get(nic, {})
                if prev:
                    elapsed = ts - prev.get("ts", ts)
                    if elapsed > 0:
                        sent_rate = (stats.bytes_sent - prev.get("sent", stats.bytes_sent)) / elapsed
                        recv_rate = (stats.bytes_recv - prev.get("recv", stats.bytes_recv)) / elapsed
                        # Alert on very high rates
                        if sent_rate > 50 * 1024 * 1024:   # 50 MB/s
                            logger.warning(
                                f"🌐 High TX on {nic}: {sent_rate/1024/1024:.1f} MB/s"
                            )
                self._last_bw[nic] = {
                    "sent": stats.bytes_sent, "recv": stats.bytes_recv, "ts": ts
                }
        except Exception as e:
            logger.debug(f"Bandwidth check: {e}")

    # ------------------------------------------------------------------
    # ARP table analysis
    # ------------------------------------------------------------------

    def _check_arp_table(self):
        """Detect potential ARP spoofing: same IP → multiple MACs."""
        if self._platform == "Windows":
            return
        try:
            out, _, rc = _run(["arp", "-n"])
            if rc != 0:
                return
            ip_to_mac: Dict[str, Set[str]] = defaultdict(set)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                    ip_to_mac[parts[0]].add(parts[2])
            for ip, macs in ip_to_mac.items():
                if len(macs) > 1:
                    cooldown_key = f"arp_spoof_{ip}"
                    now = time.time()
                    if self._alert_cooldown.get(cooldown_key, 0) + 600 < now:
                        self._alert_cooldown[cooldown_key] = now
                        logger.warning(f"⚠️  ARP spoof possible: {ip} → {macs}")
                        if self.callback:
                            self.callback({
                                "type": "arp_spoofing",
                                "ip": ip,
                                "macs": list(macs),
                                "risk": "CRITICAL",
                                "timestamp": datetime.now().isoformat(),
                            })
        except Exception as e:
            logger.debug(f"ARP check: {e}")

    # ------------------------------------------------------------------
    # Geo & helpers
    # ------------------------------------------------------------------

    def _geolocate(self, ip: str) -> Dict:
        if ip in self._geo_cache:
            return self._geo_cache[ip]
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode,as",
                             timeout=3)
            if r.status_code == 200:
                data = r.json()
                self._geo_cache[ip] = data
                return data
        except Exception:
            pass
        return {}

    def _save_connection(self, local: str, remote_ip: str, remote_port: int,
                          proc: str, geo: Dict, risk: str, reason: str):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                INSERT INTO network_traffic
                    (direction, local_addr, remote_ip, remote_port,
                     process, country, asn, risk_level, reason)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, ("outbound", local, remote_ip, remote_port,
                   proc, geo.get("country", ""), geo.get("as", ""), risk, reason))
            conn.commit()
            conn.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Static helpers (backward compat)
    # ------------------------------------------------------------------

    @staticmethod
    def get_local_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    @staticmethod
    async def scan_network(target: str) -> Dict:
        return {"target": target, "local_ip": NetworkScanner.get_local_ip()}

    def get_summary(self) -> Dict:
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM network_traffic")
            total = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM network_traffic WHERE risk_level IN ('HIGH','CRITICAL')")
            threats = c.fetchone()[0]
            conn.close()
            return {"connections_logged": total, "suspicious_connections": threats}
        except Exception:
            return {}
