"""
Real-time Intrusion Detection System (IDS)
Monitors incoming network traffic and detects attacks
"""

import json
import logging
import os
import socket
import struct
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Optional
import psutil

logger = logging.getLogger("IntrusionDetector")

# Shared quarantine index path — same file read by /dashboard/quarantine-inventory
_QUARANTINE_INDEX = Path.home() / ".sentinelai_quarantine" / "quarantine_index.json"


class IntrusionDetector:
    """Real-time intrusion detection and monitoring"""

    def __init__(self, callback=None):
        self.callback = callback
        self.running = False
        self.monitor_thread = None
        
        # Attack tracking
        self.connection_attempts = defaultdict(list)  # IP -> [timestamps] (inbound only)
        self.failed_auth_attempts = defaultdict(int)  # IP -> count
        self.suspicious_ports = defaultdict(list)  # IP -> [ports]
        self.blocked_ips = set()
        self.attack_cooldown = {}  # IP -> last_alert_time to prevent spam
        self._hostname_cache: Dict[str, tuple[float, Optional[str]]] = {}

        # Multi-signal confirmation: IP -> set of attack types seen
        self.attack_signals: Dict[str, Set[str]] = defaultdict(set)
        # Confirmation requirements before auto-block (number of distinct signals)
        self.MULTI_SIGNAL_THRESHOLD = 2

        # Listening port cache (refreshed every 30s)
        self._listening_ports_cache: Set[int] = set()
        self._listening_ports_cache_time: float = 0.0
        self._refresh_listening_ports()  # populate immediately

        # Detection thresholds (tuned to reduce false positives)
        # Soft limit: contributes one signal; hard limit: immediate block
        self.MAX_CONNECTIONS_PER_MINUTE = self._env_int("SENTINEL_IDS_SOFT_FLOOD", 300, minimum=50)
        self.FLOOD_HARD_THRESHOLD = self._env_int("SENTINEL_IDS_HARD_FLOOD", 600, minimum=100)
        self.MAX_FAILED_AUTH = self._env_int("SENTINEL_IDS_MAX_FAILED_AUTH", 5, minimum=1)
        self.SUSPICIOUS_PORT_THRESHOLD = self._env_int("SENTINEL_IDS_SUSPICIOUS_PORTS", 10, minimum=3)
        self.BRUTE_FORCE_CONN_THRESHOLD = self._env_int("SENTINEL_IDS_BRUTE_FORCE_CONN", 20, minimum=5)
        self.WEB_ATTACK_CONN_THRESHOLD = self._env_int("SENTINEL_IDS_WEB_ATTACK_CONN", 35, minimum=10)
        self.TIME_WINDOW = self._env_int("SENTINEL_IDS_TIME_WINDOW", 60, minimum=10)
        self.ALERT_COOLDOWN = self._env_int("SENTINEL_IDS_ALERT_COOLDOWN", 300, minimum=30)
        
        # Whitelisted IPs and networks
        self.WHITELISTED_IPS = self._load_ip_whitelist()
        self.WHITELISTED_NETWORKS = self._load_network_whitelist()
        
        # Attack patterns
        self.COMMON_ATTACK_PORTS = {
            80: "HTTP Web Attack",
            443: "HTTPS Web Attack",
            22: "SSH Brute Force",
            23: "Telnet Attack",
            445: "SMB/RDP Attack",
            3389: "RDP Brute Force",
            3306: "MySQL Attack",
            5432: "PostgreSQL Attack",
            6379: "Redis Attack",
            27017: "MongoDB Attack",
            1433: "MSSQL Attack",
            8080: "Web Server Attack",
            8443: "HTTPS Attack"
        }

        # Authentication-focused service ports commonly abused by brute-force tools
        self.AUTH_TARGET_PORTS = {21, 22, 23, 25, 110, 143, 445, 993, 995, 1433, 3306, 3389, 5432, 6379}

        # Common payload/listener ports often seen in Metasploit workflows
        self.METASPLOIT_PORT_SIGNATURES = {4444, 5555, 6666}
        
        # Known malicious patterns
        self.MALICIOUS_PATTERNS = [
            "SYN flood",
            "Port scan",
            "Brute force",
            "DDoS",
            "SQL injection attempt",
            "XSS attempt",
            "Buffer overflow",
            "Directory traversal"
        ]

        # Ensure hard threshold is always higher than soft threshold.
        if self.FLOOD_HARD_THRESHOLD <= self.MAX_CONNECTIONS_PER_MINUTE:
            self.FLOOD_HARD_THRESHOLD = self.MAX_CONNECTIONS_PER_MINUTE + max(50, self.MAX_CONNECTIONS_PER_MINUTE // 2)

        # Restore blocked IP memory from persisted quarantine inventory.
        self._load_persisted_blocked_ips()

    def _env_int(self, name: str, default: int, minimum: int = 1) -> int:
        """Read an integer from environment with safe fallback and minimum clamp."""
        raw = os.getenv(name)
        if raw is None:
            return default
        try:
            value = int(raw.strip())
            return value if value >= minimum else default
        except Exception:
            return default

    def _load_persisted_blocked_ips(self):
        """Restore blocked IPs from quarantine index to survive client restarts."""
        try:
            if not _QUARANTINE_INDEX.exists():
                return

            loaded = json.loads(_QUARANTINE_INDEX.read_text(encoding='utf-8'))
            if not isinstance(loaded, list):
                return

            restored = 0
            for item in loaded:
                if not isinstance(item, dict):
                    continue
                if (item.get('type') or '').lower() != 'ip_block':
                    continue
                ip = item.get('source_ip') or item.get('ip')
                if not ip or self._is_whitelisted_ip(ip):
                    continue
                self.blocked_ips.add(ip)
                restored += 1

            if restored:
                logger.info(f"Restored {restored} blocked IP(s) from quarantine index")
        except Exception as e:
            logger.debug(f"Failed to restore blocked IPs: {e}")

    def _load_ip_whitelist(self) -> set:
        """Load whitelist of legitimate IP addresses and services"""
        return {
            '127.0.0.1',
            '::1',  # IPv6 localhost
            '0.0.0.0',
            'localhost'
        }
    
    def _load_network_whitelist(self) -> set:
        """Load whitelist of legitimate network ranges (CIDR notation)"""
        return {
            # Private networks (RFC1918)
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            # Loopback
            '127.0.0.0/8',
            '::1/128',
            # Link-local
            '169.254.0.0/16',
            'fe80::/10',
            # RFC 5737 documentation/example ranges — never real traffic
            '192.0.2.0/24',    # TEST-NET-1
            '198.51.100.0/24', # TEST-NET-2
            '203.0.113.0/24',  # TEST-NET-3
            # RFC 3849 IPv6 documentation range
            '2001:db8::/32',
            # Shared address space (RFC 6598 CGNAT)
            '100.64.0.0/10',
        }
    
    def _persist_ip_block(self, ip: str, attack_type: str, severity: str, description: str):
        """Persist a blocked IP to the shared quarantine index so the dashboard shows it."""
        try:
            _QUARANTINE_INDEX.parent.mkdir(parents=True, exist_ok=True)
            records = []
            if _QUARANTINE_INDEX.exists():
                try:
                    records = json.loads(_QUARANTINE_INDEX.read_text(encoding='utf-8'))
                    if not isinstance(records, list):
                        records = []
                except Exception:
                    records = []
            ts = datetime.now()
            entry = {
                'quarantine_id': f"IDS_{ts.strftime('%Y%m%d%H%M%S')}_{ip.replace('.', '_')}",
                'type': 'ip_block',
                'source': 'intrusion_detector',
                'attack_type': attack_type,
                'source_ip': ip,
                'severity': severity,
                'description': description,
                'timestamp': ts.isoformat(),
                'action': 'ip_blocked',
            }
            # Avoid duplicate entries for same IP within the same minute
            already = any(
                r.get('source_ip') == ip and
                r.get('type') == 'ip_block' and
                r.get('timestamp', '')[:16] == entry['timestamp'][:16]
                for r in records
            )
            if not already:
                records.append(entry)
                tmp = _QUARANTINE_INDEX.with_suffix('.json.tmp')
                tmp.write_text(json.dumps(records, indent=2), encoding='utf-8')
                tmp.replace(_QUARANTINE_INDEX)
                logger.info(f"IP block persisted to quarantine index: {ip} ({attack_type})")
        except Exception as e:
            logger.error(f"Failed to persist IP block to quarantine index: {e}")

    def _refresh_listening_ports(self):
        """Refresh the cache of ports this machine is actively listening on.
        Only connections TO these ports are inbound (potential attacks).
        Outbound connections use ephemeral ports and must NOT be counted.
        """
        now = time.time()
        if now - self._listening_ports_cache_time < 30:
            return  # cache still fresh
        try:
            listening = set()
            for conn in psutil.net_connections(kind='inet'):
                if getattr(conn, 'status', '') == 'LISTEN' and conn.laddr:
                    listening.add(conn.laddr.port)
            self._listening_ports_cache = listening
            self._listening_ports_cache_time = now
            logger.debug(f"Listening ports refreshed: {sorted(listening)}")
        except Exception as e:
            logger.debug(f"Could not refresh listening ports: {e}")

    def _is_inbound_connection(self, local_port: int) -> bool:
        """Return True if the local port is a listening port (inbound connection).
        Outbound connections use ephemeral ports (>1023) that are NOT in the
        listening set — those represent connections WE initiated, not attacks.
        """
        # Port 0 or negative = unknown, treat conservatively
        if local_port <= 0:
            return False
        # Well-known service ports (1-1023) that are NOT in LISTEN state
        # are still likely inbound, but we play safe and only count LISTEN ports
        return local_port in self._listening_ports_cache

    def _is_whitelisted_ip(self, ip: str) -> bool:
        """Check if IP is whitelisted or in private/local range"""
        if not ip:
            return False
            
        # Direct whitelist check
        if ip in self.WHITELISTED_IPS:
            return True
        
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if private, loopback, or link-local
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return True

            # Reserved/documentation/special-use addresses are never real attackers
            # Covers RFC 5737 TEST-NETs (192.0.2.x, 198.51.100.x, 203.0.113.x),
            # multicast, unspecified, etc.
            if (
                getattr(ip_obj, 'is_reserved', False)
                or getattr(ip_obj, 'is_unspecified', False)
                or getattr(ip_obj, 'is_multicast', False)
            ):
                return True
            
            # Check against whitelisted networks
            for network_str in self.WHITELISTED_NETWORKS:
                try:
                    network = ipaddress.ip_network(network_str)
                    if ip_obj in network:
                        return True
                except ValueError:
                    continue
            
            # Known legitimate service IP ranges (Google, Cloudflare, etc.)
            # Google: 142.250.0.0/15, 172.217.0.0/16, 216.58.192.0/19, 34.64.0.0/10
            # Cloudflare: 104.16.0.0/13, 172.64.0.0/13
            # These are frequently flagged as false positives
            legitimate_ranges = [
                '142.250.0.0/15',  # Google
                '172.217.0.0/16',  # Google
                '216.58.192.0/19', # Google
                '34.64.0.0/10',    # Google Cloud
                '35.184.0.0/13',   # Google Cloud
                '104.16.0.0/13',   # Cloudflare
                '172.64.0.0/13',   # Cloudflare
                '151.101.0.0/16',  # Fastly CDN
                '199.232.0.0/16',  # Cloudflare
            ]
            
            for range_str in legitimate_ranges:
                try:
                    network = ipaddress.ip_network(range_str)
                    if ip_obj in network:
                        logger.debug(f"IP {ip} is in legitimate service range: {range_str}")
                        return True
                except ValueError:
                    continue
                    
        except (ValueError, AttributeError) as e:
            logger.debug(f"Error checking IP whitelist for {ip}: {e}")
            return False
        
        return False
    
    def _is_in_alert_cooldown(self, ip: str) -> bool:
        """Check if we recently alerted about this IP to prevent spam"""
        if ip not in self.attack_cooldown:
            return False
        
        time_since_last = time.time() - self.attack_cooldown[ip]
        return time_since_last < self.ALERT_COOLDOWN

    def _resolve_source_hostname(self, ip: str) -> Optional[str]:
        """Best-effort reverse DNS lookup with caching for monitoring UX."""
        try:
            if not ip or ip == 'MULTIPLE' or self._is_whitelisted_ip(ip):
                return None

            now = time.time()
            cached = self._hostname_cache.get(ip)
            if cached and (now - cached[0]) < 1800:  # 30 min TTL
                return cached[1]

            try:
                host = socket.gethostbyaddr(ip)[0]
            except Exception:
                host = None

            self._hostname_cache[ip] = (now, host)
            return host
        except Exception:
            return None

    def _build_mitigation_commands(self, ip: str, attack_family: str, target_port: Optional[int] = None) -> List[str]:
        """Build actionable mitigation commands shown in alerts/dashboard."""
        commands = [
            f"sudo iptables -I INPUT -s {ip} -j DROP",
            f"sudo iptables -I OUTPUT -d {ip} -j DROP",
        ]

        if target_port:
            commands.append(
                f"sudo iptables -I INPUT -p tcp --dport {target_port} -m conntrack --ctstate NEW -m recent --set"
            )
            commands.append(
                f"sudo iptables -I INPUT -p tcp --dport {target_port} -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 20 -j DROP"
            )

        if attack_family == 'NMAP_RECON':
            commands.append("sudo apt install -y fail2ban && sudo systemctl enable --now fail2ban")
        elif attack_family == 'BRUTE_FORCE':
            commands.append("sudo systemctl restart ssh || true")
        elif attack_family == 'WEB_INJECTION_RECON':
            commands.append("sudo iptables -I INPUT -p tcp -m multiport --dports 80,443,8080,8443 -m conntrack --ctstate NEW -m recent --set")
        elif attack_family == 'METASPLOIT_PROBE':
            commands.append("sudo ss -tulpen | grep -E ':(4444|5555|6666)\\b'")

        return commands

    def _predict_attack_progression(self, attack: Dict) -> Dict:
        """Predict probable next attacker action for proactive defense."""
        attack_type = str(attack.get('type', 'UNKNOWN')).upper()

        mapping = {
            'PORT_SCAN': (
                'Likely follow-up exploit or brute-force attempt after reconnaissance',
                'EXPLOIT_OR_BRUTE_FORCE',
                0.81,
            ),
            'BRUTE_FORCE_ATTEMPT': (
                'Likely credential stuffing or lateral movement if authentication succeeds',
                'CREDENTIAL_COMPROMISE',
                0.87,
            ),
            'METASPLOIT_PROBE': (
                'Likely reverse shell/session establishment attempt',
                'REMOTE_CODE_EXECUTION',
                0.90,
            ),
            'TARGETED_ATTACK': (
                'Likely service exploitation against exposed ports',
                'SERVICE_COMPROMISE',
                0.84,
            ),
            'DDOS_ATTACK': (
                'Likely sustained service disruption and volumetric flood',
                'AVAILABILITY_OUTAGE',
                0.79,
            ),
            'WEB_INJECTION_RECON': (
                'Likely SQL injection or command injection payload delivery',
                'WEB_APP_COMPROMISE',
                0.78,
            ),
        }

        summary, next_step, confidence = mapping.get(
            attack_type,
            (
                'Likely escalation attempt against exposed services',
                'ESCALATION_ATTEMPT',
                0.65,
            ),
        )

        return {
            'prediction_summary': summary,
            'predicted_next_step': next_step,
            'prediction_confidence': round(float(confidence), 2),
        }

    def _with_prediction(self, attack: Dict) -> Dict:
        """Attach predictive fields to attack payload."""
        try:
            enriched = dict(attack)
            enriched.update(self._predict_attack_progression(attack))
            return enriched
        except Exception:
            return attack

    def start(self):
        """Start the intrusion detection system"""
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            logger.info("🛡️  Intrusion Detection System started")

    def stop(self):
        """Stop the intrusion detection system"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Intrusion Detection System stopped")

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Monitor network connections
                connections = self._get_active_connections()
                
                # Analyze connections for threats
                for conn in connections:
                    self._analyze_connection(conn)
                
                # Check for attack patterns
                attacks = self._detect_attacks()
                
                # Report attacks if callback is set
                if attacks and self.callback:
                    for attack in attacks:
                        self.callback(attack)
                
                # Clean old entries
                self._cleanup_old_data()
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                logger.error(f"Error in intrusion detection loop: {e}")
                time.sleep(5)

    def _get_active_connections(self) -> List[Dict]:
        """Get all active network connections"""
        connections = []
        try:
            # Try with 'all' kind first, fall back to 'inet' if access denied
            try:
                conn_list = psutil.net_connections(kind='inet')
            except psutil.AccessDenied:
                # If access denied, try without filtering (less info but works)
                logger.warning("Access denied for full connection list, using limited view")
                conn_list = psutil.net_connections(kind='inet')
            
            for conn in conn_list:
                try:
                    if conn.status == 'ESTABLISHED' or conn.status == 'SYN_RECV':
                        if conn.raddr:  # Remote address exists
                            connections.append({
                                'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "unknown",
                                'local_port': conn.laddr.port if conn.laddr else 0,
                                'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "unknown",
                                'remote_ip': conn.raddr.ip,
                                'remote_port': conn.raddr.port,
                                'status': conn.status,
                                'pid': conn.pid if hasattr(conn, 'pid') else None,
                                'timestamp': datetime.now()
                            })
                except (AttributeError, TypeError):
                    continue
        except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError) as e:
            # Log once per minute to avoid spam
            if not hasattr(self, '_last_permission_warning') or \
               time.time() - self._last_permission_warning > 60:
                logger.warning(f"Limited network monitoring due to permissions: {e}")
                logger.info("Run with sudo for full IDS capabilities")
                self._last_permission_warning = time.time()
        except Exception as e:
            logger.error(f"Error getting network connections: {e}")
        return connections

    def _analyze_connection(self, conn: Dict):
        """Analyze a connection for suspicious activity.

        IMPORTANT: Only INBOUND connections count toward flood/attack detection.
        An inbound connection is one where our local port is a listening (server)
        port.  Outbound connections (where WE are the client, using an ephemeral
        local port) must be ignored — otherwise legitimate outbound traffic to any
        remote server inflates that server's "attack" counter and causes false
        positives.
        """
        remote_ip = conn['remote_ip']
        remote_port = conn['remote_port']
        local_port = conn.get('local_port', 0)
        timestamp = conn['timestamp']

        # Skip whitelisted IPs
        if self._is_whitelisted_ip(remote_ip):
            return

        # Refresh listening port cache if stale
        self._refresh_listening_ports()

        # Only count as a potential attack if the remote IP connected TO us
        # (inbound connection on a listening port).  Outbound connections mean
        # we are the client — the remote IP is a server, not an attacker.
        if not self._is_inbound_connection(local_port):
            return

        # Track inbound connection attempts from this IP
        self.connection_attempts[remote_ip].append(timestamp)

        # Track suspicious target ports (attacker hitting known attack ports on us)
        # NOTE: local_port is the destination port on this machine.
        if local_port in self.COMMON_ATTACK_PORTS:
            self.suspicious_ports[remote_ip].append(local_port)

    def _detect_attacks(self) -> List[Dict]:
        """Detect various attack patterns"""
        attacks = []
        current_time = datetime.now()
        
        # Check each IP for attack patterns
        for ip, timestamps in list(self.connection_attempts.items()):
            # Skip whitelisted IPs
            if self._is_whitelisted_ip(ip):
                continue
                
            # Skip if already blocked
            if ip in self.blocked_ips:
                continue
            
            # Skip if in cooldown period (prevent alert spam)
            if self._is_in_alert_cooldown(ip):
                continue
            
            # Count recent connections
            recent = [t for t in timestamps if (current_time - t).seconds < self.TIME_WINDOW]
            
            # Detect connection flooding (DDoS/Port Scan) — INBOUND connections only.
            # Hard threshold: single overwhelming burst → immediate alert+block.
            # Soft threshold: first signal; only raise alert once multi-signal
            # threshold is also met to reduce false positives.
            if len(recent) > self.FLOOD_HARD_THRESHOLD:
                # Extreme burst — block immediately without waiting for 2nd signal
                desc = f'Severe connection flood: {len(recent)} inbound connections in {self.TIME_WINDOW}s'
                family = 'CONNECTION_FLOOD'
                attacks.append(self._with_prediction({
                    'type': 'CONNECTION_FLOOD',
                    'severity': 'CRITICAL',
                    'source_ip': ip,
                    'source_hostname': self._resolve_source_hostname(ip),
                    'description': desc,
                    'short_description': f'High-rate inbound flood from {ip}',
                    'count': len(recent),
                    'attack_family': family,
                    'mitigation_commands': self._build_mitigation_commands(ip, family),
                    'recommended_action': 'Block source IP and enable flood/rate limiting rules',
                    'timestamp': current_time,
                    'action_required': True
                }))
                self.blocked_ips.add(ip)
                self._persist_ip_block(ip, 'CONNECTION_FLOOD', 'CRITICAL', desc)
                self.attack_cooldown[ip] = time.time()
            elif len(recent) > self.MAX_CONNECTIONS_PER_MINUTE:
                # Soft threshold hit — record signal, only alert if multi-signal confirmed
                self.attack_signals[ip].add('CONNECTION_FLOOD')
                if len(self.attack_signals[ip]) >= self.MULTI_SIGNAL_THRESHOLD:
                    desc = f'Connection flood detected: {len(recent)} inbound connections in {self.TIME_WINDOW}s (multi-signal confirmed)'
                    family = 'CONNECTION_FLOOD'
                    attacks.append(self._with_prediction({
                        'type': 'CONNECTION_FLOOD',
                        'severity': 'HIGH',
                        'source_ip': ip,
                        'source_hostname': self._resolve_source_hostname(ip),
                        'description': desc,
                        'short_description': f'Inbound flood pattern detected from {ip}',
                        'count': len(recent),
                        'signals': list(self.attack_signals[ip]),
                        'attack_family': family,
                        'mitigation_commands': self._build_mitigation_commands(ip, family),
                        'recommended_action': 'Block source IP and inspect edge firewall logs',
                        'timestamp': current_time,
                        'action_required': True
                    }))
                    self.blocked_ips.add(ip)
                    self._persist_ip_block(ip, 'CONNECTION_FLOOD', 'HIGH', desc)
                    self.attack_cooldown[ip] = time.time()
            
            # Detect port scanning
            if ip in self.suspicious_ports:
                unique_ports = set(self.suspicious_ports[ip])

                # Detect brute-force bursts against auth-related ports
                auth_port_hits = {
                    p: self.suspicious_ports[ip].count(p)
                    for p in set(self.suspicious_ports[ip])
                    if p in self.AUTH_TARGET_PORTS
                }
                if auth_port_hits:
                    top_port, top_hits = max(auth_port_hits.items(), key=lambda item: item[1])
                    if top_hits >= self.BRUTE_FORCE_CONN_THRESHOLD:
                        desc = (
                            f'Possible brute-force: {top_hits} attempts against service port {top_port} '
                            f'within monitoring window'
                        )
                        attacks.append(self._with_prediction({
                            'type': 'BRUTE_FORCE_ATTEMPT',
                            'severity': 'CRITICAL' if top_hits >= self.BRUTE_FORCE_CONN_THRESHOLD * 2 else 'HIGH',
                            'source_ip': ip,
                            'source_hostname': self._resolve_source_hostname(ip),
                            'description': desc,
                            'short_description': f'Likely brute-force on port {top_port}',
                            'target_port': top_port,
                            'attempt_count': top_hits,
                            'tool_signature': 'HYDRA_MEDUSA_STYLE',
                            'attack_family': 'BRUTE_FORCE',
                            'mitigation_commands': self._build_mitigation_commands(ip, 'BRUTE_FORCE', top_port),
                            'recommended_action': 'Block source IP and enforce MFA/strong auth for exposed services',
                            'timestamp': current_time,
                            'action_required': True
                        }))
                        self.blocked_ips.add(ip)
                        self._persist_ip_block(ip, 'BRUTE_FORCE_ATTEMPT', 'HIGH', desc)
                        self.attack_cooldown[ip] = time.time()

                if len(unique_ports) > self.SUSPICIOUS_PORT_THRESHOLD:
                    tool_signature = 'NMAP_RECON' if len(unique_ports) >= max(12, self.SUSPICIOUS_PORT_THRESHOLD) else 'PORT_RECON'
                    desc = f'Port scan detected: {len(unique_ports)} different ports scanned'
                    attacks.append(self._with_prediction({
                        'type': 'PORT_SCAN',
                        'severity': 'HIGH',
                        'source_ip': ip,
                        'source_hostname': self._resolve_source_hostname(ip),
                        'description': desc,
                        'short_description': f'Likely {"Nmap" if tool_signature == "NMAP_RECON" else "recon"} scan against multiple ports',
                        'ports': list(unique_ports)[:20],  # First 20 ports
                        'tool_signature': tool_signature,
                        'attack_family': 'RECONNAISSANCE',
                        'mitigation_commands': self._build_mitigation_commands(ip, 'NMAP_RECON'),
                        'recommended_action': 'Block source IP and enable IDS signatures for reconnaissance patterns',
                        'timestamp': current_time,
                        'action_required': True
                    }))
                    self.blocked_ips.add(ip)
                    self._persist_ip_block(ip, 'PORT_SCAN', 'HIGH', desc)
                    self.attack_cooldown[ip] = time.time()  # Set cooldown

                # Detect Metasploit-like probes (common listener/payload ports)
                metasploit_ports = sorted(list(unique_ports.intersection(self.METASPLOIT_PORT_SIGNATURES)))
                if metasploit_ports:
                    probe_port = metasploit_ports[0]
                    desc = f'Potential Metasploit activity: probe on known payload/listener port(s) {metasploit_ports}'
                    attacks.append(self._with_prediction({
                        'type': 'METASPLOIT_PROBE',
                        'severity': 'CRITICAL',
                        'source_ip': ip,
                        'source_hostname': self._resolve_source_hostname(ip),
                        'description': desc,
                        'short_description': f'Metasploit-like probe observed on port {probe_port}',
                        'ports': metasploit_ports,
                        'tool_signature': 'METASPLOIT_PATTERN',
                        'attack_family': 'METASPLOIT_PROBE',
                        'mitigation_commands': self._build_mitigation_commands(ip, 'METASPLOIT_PROBE', probe_port),
                        'recommended_action': 'Block source IP and inspect endpoint for reverse-shell sessions',
                        'timestamp': current_time,
                        'action_required': True
                    }))
                    self.blocked_ips.add(ip)
                    self._persist_ip_block(ip, 'METASPLOIT_PROBE', 'CRITICAL', desc)
                    self.attack_cooldown[ip] = time.time()

                # Summarize targeted service attacks instead of one alert per port
                targeted_ports = sorted([port for port in unique_ports if port in self.COMMON_ATTACK_PORTS])
                if targeted_ports:
                    port_labels = [f"{p}:{self.COMMON_ATTACK_PORTS[p]}" for p in targeted_ports[:6]]
                    desc = f'Targeted attack against exposed services: {", ".join(port_labels)}'
                    attacks.append(self._with_prediction({
                        'type': 'TARGETED_ATTACK',
                        'severity': 'CRITICAL',
                        'source_ip': ip,
                        'source_hostname': self._resolve_source_hostname(ip),
                        'description': desc,
                        'short_description': f'Targeted service probing on {len(targeted_ports)} critical ports',
                        'target_ports': targeted_ports,
                        'attack_type': 'SERVICE_TARGETING',
                        'attack_family': 'TARGETED_ATTACK',
                        'mitigation_commands': self._build_mitigation_commands(ip, 'TARGETED_ATTACK', targeted_ports[0]),
                        'recommended_action': 'Restrict exposed services by IP allowlist and verify brute-force protections',
                        'timestamp': current_time,
                        'action_required': True
                    }))

                # Detect web attack reconnaissance likely to precede SQLi/XSS/RCE attempts
                web_hits = sum(1 for p in self.suspicious_ports[ip] if p in {80, 443, 8080, 8443})
                if web_hits >= self.WEB_ATTACK_CONN_THRESHOLD:
                    desc = (
                        f'High-rate web probing detected: {web_hits} inbound attempts on web service ports '
                        f'within monitoring window (possible SQL injection/recon)'
                    )
                    attacks.append(self._with_prediction({
                        'type': 'WEB_INJECTION_RECON',
                        'severity': 'HIGH',
                        'source_ip': ip,
                        'source_hostname': self._resolve_source_hostname(ip),
                        'description': desc,
                        'short_description': 'Potential web attack reconnaissance (SQLi/XSS pre-stage)',
                        'attempt_count': web_hits,
                        'attack_family': 'WEB_INJECTION_RECON',
                        'tool_signature': 'WEB_RECON_PATTERN',
                        'mitigation_commands': self._build_mitigation_commands(ip, 'WEB_INJECTION_RECON', 80),
                        'recommended_action': 'Enable WAF rules, strict input validation, and rate limits on web endpoints',
                        'timestamp': current_time,
                        'action_required': True
                    }))
                    self.blocked_ips.add(ip)
                    self._persist_ip_block(ip, 'WEB_INJECTION_RECON', 'HIGH', desc)
                    self.attack_cooldown[ip] = time.time()
        
        # Detect unusual network activity
        network_stats = psutil.net_io_counters()
        if hasattr(self, '_last_network_stats'):
            bytes_recv_diff = network_stats.bytes_recv - self._last_network_stats.bytes_recv
            packets_recv_diff = network_stats.packets_recv - self._last_network_stats.packets_recv
            
            # Detect abnormal traffic (potential DDoS)
            if bytes_recv_diff > 100_000_000:  # 100MB in 1 second
                attacks.append(self._with_prediction({
                    'type': 'DDOS_ATTACK',
                    'severity': 'CRITICAL',
                    'source_ip': 'MULTIPLE',
                    'description': f'Possible DDoS attack: {bytes_recv_diff / 1_000_000:.2f} MB/s incoming traffic',
                    'short_description': 'Abnormal volumetric traffic spike detected',
                    'attack_family': 'DDOS_ATTACK',
                    'mitigation_commands': [
                        'sudo iptables -I INPUT -p tcp --syn -m limit --limit 20/s --limit-burst 40 -j ACCEPT',
                        'sudo iptables -A INPUT -p tcp --syn -j DROP',
                    ],
                    'recommended_action': 'Apply edge rate limits and upstream DDoS mitigation profile',
                    'bytes_received': bytes_recv_diff,
                    'packets_received': packets_recv_diff,
                    'timestamp': current_time,
                    'action_required': True
                }))
        
        self._last_network_stats = network_stats
        
        return attacks

    def _cleanup_old_data(self):
        """Clean up old tracking data"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.TIME_WINDOW * 2)
        
        # Clean old connection attempts
        for ip in list(self.connection_attempts.keys()):
            self.connection_attempts[ip] = [
                t for t in self.connection_attempts[ip] if t > cutoff_time
            ]
            if not self.connection_attempts[ip]:
                del self.connection_attempts[ip]
        
        # Clean old suspicious ports
        for ip in list(self.suspicious_ports.keys()):
            if ip not in self.connection_attempts:
                del self.suspicious_ports[ip]

    def get_blocked_ips(self) -> Set[str]:
        """Get set of blocked IPs"""
        return self.blocked_ips.copy()

    def unblock_ip(self, ip: str):
        """Unblock an IP address"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            logger.info(f"Unblocked IP: {ip}")

    def get_statistics(self) -> Dict:
        """Get detection statistics"""
        return {
            'monitored_ips': len(self.connection_attempts),
            'blocked_ips': len(self.blocked_ips),
            'suspicious_ips': len(self.suspicious_ports),
            'total_connections': sum(len(v) for v in self.connection_attempts.values()),
            'blocked_ips_list': list(self.blocked_ips)
        }
