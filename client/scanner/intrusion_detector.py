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
        self.connection_attempts = defaultdict(list)  # IP -> [timestamps]
        self.failed_auth_attempts = defaultdict(int)  # IP -> count
        self.suspicious_ports = defaultdict(list)  # IP -> [ports]
        self.blocked_ips = set()
        
        # Detection thresholds
        self.MAX_CONNECTIONS_PER_MINUTE = 50
        self.MAX_FAILED_AUTH = 5
        self.SUSPICIOUS_PORT_THRESHOLD = 10
        self.TIME_WINDOW = 60  # seconds
        
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
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' or conn.status == 'SYN_RECV':
                    if conn.raddr:  # Remote address exists
                        connections.append({
                            'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'remote_ip': conn.raddr.ip,
                            'remote_port': conn.raddr.port,
                            'status': conn.status,
                            'pid': conn.pid,
                            'timestamp': datetime.now()
                        })
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        return connections

    def _analyze_connection(self, conn: Dict):
        """Analyze a connection for suspicious activity"""
        remote_ip = conn['remote_ip']
        remote_port = conn['remote_port']
        timestamp = conn['timestamp']
        
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
            # Skip if already blocked
            if ip in self.blocked_ips:
                continue
            
            # Count recent connections
            recent = [t for t in timestamps if (current_time - t).seconds < self.TIME_WINDOW]
            
            # Detect connection flooding (DDoS/Port Scan)
            if len(recent) > self.MAX_CONNECTIONS_PER_MINUTE:
                attacks.append({
                    'type': 'CONNECTION_FLOOD',
                    'severity': 'CRITICAL',
                    'source_ip': ip,
                    'description': f'Connection flood detected: {len(recent)} connections in {self.TIME_WINDOW}s',
                    'count': len(recent),
                    'timestamp': current_time,
                    'action_required': True
                })
                self.blocked_ips.add(ip)
            
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
