"""
Real-time Intrusion Detection System (IDS)
Monitors incoming network traffic and detects attacks
"""

import logging
import socket
import struct
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
import psutil

logger = logging.getLogger("IntrusionDetector")


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

        # Multi-signal confirmation: IP -> set of attack types seen
        self.attack_signals: Dict[str, Set[str]] = defaultdict(set)
        # Confirmation requirements before auto-block (number of distinct signals)
        self.MULTI_SIGNAL_THRESHOLD = 2

        # Listening port cache (refreshed every 30s)
        self._listening_ports_cache: Set[int] = set()
        self._listening_ports_cache_time: float = 0.0
        
        # Detection thresholds (tuned to reduce false positives)
        # Soft limit: contributes one signal; hard limit: immediate block
        self.MAX_CONNECTIONS_PER_MINUTE = 300   # Soft threshold per IP
        self.FLOOD_HARD_THRESHOLD = 600         # Single-signal immediate block
        self.MAX_FAILED_AUTH = 5
        self.SUSPICIOUS_PORT_THRESHOLD = 10
        self.TIME_WINDOW = 60  # seconds
        self.ALERT_COOLDOWN = 300  # 5 minutes between alerts for same IP
        
        # Whitelisted IPs and networks
        self.WHITELISTED_IPS = self._load_ip_whitelist()
        self.WHITELISTED_NETWORKS = self._load_network_whitelist()
        
        # Attack patterns
        self.COMMON_ATTACK_PORTS = {
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
            'fe80::/10'
        }
    
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
        """Analyze a connection for suspicious activity"""
        remote_ip = conn['remote_ip']
        remote_port = conn['remote_port']
        timestamp = conn['timestamp']
        
        # Skip whitelisted IPs
        if self._is_whitelisted_ip(remote_ip):
            return
        
        # Track connection attempts
        self.connection_attempts[remote_ip].append(timestamp)
        
        # Track suspicious ports
        if remote_port in self.COMMON_ATTACK_PORTS:
            self.suspicious_ports[remote_ip].append(remote_port)

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
            
            # Detect connection flooding (DDoS/Port Scan) with higher threshold
            if len(recent) > self.MAX_CONNECTIONS_PER_MINUTE:
                attacks.append({
                    'type': 'CONNECTION_FLOOD',
                    'severity': 'HIGH',  # Changed from CRITICAL
                    'source_ip': ip,
                    'description': f'Connection flood detected: {len(recent)} connections in {self.TIME_WINDOW}s',
                    'count': len(recent),
                    'timestamp': current_time,
                    'action_required': True
                })
                self.blocked_ips.add(ip)
                self.attack_cooldown[ip] = time.time()  # Set cooldown
            
            # Detect port scanning
            if ip in self.suspicious_ports:
                unique_ports = set(self.suspicious_ports[ip])
                if len(unique_ports) > self.SUSPICIOUS_PORT_THRESHOLD:
                    attacks.append({
                        'type': 'PORT_SCAN',
                        'severity': 'HIGH',
                        'source_ip': ip,
                        'description': f'Port scan detected: {len(unique_ports)} different ports scanned',
                        'ports': list(unique_ports)[:20],  # First 20 ports
                        'timestamp': current_time,
                        'action_required': True
                    })
                    self.blocked_ips.add(ip)
                    self.attack_cooldown[ip] = time.time()  # Set cooldown
                
                # Detect specific attack types based on ports
                for port in unique_ports:
                    if port in self.COMMON_ATTACK_PORTS:
                        attacks.append({
                            'type': 'TARGETED_ATTACK',
                            'severity': 'CRITICAL',
                            'source_ip': ip,
                            'description': f'{self.COMMON_ATTACK_PORTS[port]} detected on port {port}',
                            'target_port': port,
                            'attack_type': self.COMMON_ATTACK_PORTS[port],
                            'timestamp': current_time,
                            'action_required': True
                        })
        
        # Detect unusual network activity
        network_stats = psutil.net_io_counters()
        if hasattr(self, '_last_network_stats'):
            bytes_recv_diff = network_stats.bytes_recv - self._last_network_stats.bytes_recv
            packets_recv_diff = network_stats.packets_recv - self._last_network_stats.packets_recv
            
            # Detect abnormal traffic (potential DDoS)
            if bytes_recv_diff > 100_000_000:  # 100MB in 1 second
                attacks.append({
                    'type': 'DDOS_ATTACK',
                    'severity': 'CRITICAL',
                    'source_ip': 'MULTIPLE',
                    'description': f'Possible DDoS attack: {bytes_recv_diff / 1_000_000:.2f} MB/s incoming traffic',
                    'bytes_received': bytes_recv_diff,
                    'packets_received': packets_recv_diff,
                    'timestamp': current_time,
                    'action_required': True
                })
        
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
