"""
Automatic Network Traffic Monitor
Captures and extracts URLs, IPs, domains from all network activity
Automatically sends artifacts for threat analysis
"""

import asyncio
import logging
import re
import socket
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

try:
    import psutil
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger("TrafficMonitor")
logger.setLevel(logging.WARNING)


class NetworkArtifact:
    """Represents a network artifact (URL, IP, domain) extracted from traffic"""
    
    def __init__(self, artifact_type: str, value: str, source: str, metadata: Dict = None):
        self.type = artifact_type  # 'url', 'ip', 'domain'
        self.value = value
        self.source = source  # 'dns', 'http', 'https', 'connection'
        self.timestamp = datetime.utcnow()
        self.metadata = metadata or {}
        self.scan_status = 'pending'  # pending, scanning, scanned, failed
        self.threat_level = 'unknown'
        self.scan_result = None
        
    def to_dict(self) -> Dict:
        return {
            'type': self.type,
            'value': self.value,
            'source': self.source,
            'timestamp': self.timestamp.isoformat(),
            'metadata': self.metadata,
            'scan_status': self.scan_status,
            'threat_level': self.threat_level
        }


class AutomaticTrafficMonitor:
    """
    Automatically monitors all network traffic and extracts security artifacts
    - Captures DNS queries (domains)
    - Extracts HTTP/HTTPS URLs from traffic
    - Monitors all IP connections
    - Automatically queues artifacts for threat analysis
    """
    
    def __init__(self, scan_callback=None, config: Dict = None):
        self.running = False
        self.scan_callback = scan_callback  # Callback to send artifacts for scanning
        self.config = config or {}
        
        # Artifact tracking
        self.artifacts: Dict[str, NetworkArtifact] = {}  # key: artifact_value
        self.scan_queue = deque()  # Queue of artifacts to scan
        self.scanned_artifacts = set()  # Already scanned to avoid duplicates
        
        # Traffic statistics
        self.dns_queries = deque(maxlen=1000)
        self.http_requests = deque(maxlen=1000)
        self.ip_connections = deque(maxlen=1000)
        
        # Rate limiting
        self.artifact_timestamps = defaultdict(list)  # Track artifact appearance
        self.scan_interval = config.get('scan_interval', 60)  # Min seconds between scans
        self.batch_size = config.get('batch_size', 10)  # Max artifacts per batch
        
        # Whitelist for common safe services
        self.whitelisted_domains = self._load_whitelist()
        self.whitelisted_ips = self._load_ip_whitelist()
        
        # Threads
        self.capture_thread = None
        self.scan_thread = None
        self.connection_thread = None
        
        # Statistics
        self.stats = {
            'total_artifacts': 0,
            'domains_extracted': 0,
            'urls_extracted': 0,
            'ips_extracted': 0,
            'artifacts_scanned': 0,
            'threats_detected': 0,
            'scan_errors': 0
        }
        
        logger.info("🔍 Automatic Traffic Monitor initialized")
    
    def _load_whitelist(self) -> Set[str]:
        """Load commonly safe domains to reduce noise"""
        return {
            # Common CDNs
            'cloudflare.com', 'akamai.net', 'fastly.net', 'cdn.jsdelivr.net',
            # Major tech companies
            'google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com',
            'microsoft.com', 'windows.com', 'office.com', 'live.com',
            'apple.com', 'icloud.com', 'mzstatic.com',
            'amazon.com', 'amazonaws.com', 'cloudfront.net',
            # System updates
            'ubuntu.com', 'debian.org', 'fedoraproject.org', 'kernel.org',
            'mozilla.org', 'firefox.com',
            # Development
            'github.com', 'githubusercontent.com', 'gitlab.com',
            'stackoverflow.com', 'npmjs.com', 'pypi.org'
        }
    
    def _load_ip_whitelist(self) -> Set[str]:
        """Load commonly safe IP ranges"""
        return {
            # Private networks
            '127.0.0.1', '0.0.0.0',
            # Will also check for RFC1918 ranges dynamically
        }
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except:
            return False
    
    def _is_whitelisted(self, value: str, artifact_type: str) -> bool:
        """Check if artifact should be skipped"""
        if artifact_type == 'domain':
            # Check if domain or parent domain is whitelisted
            for whitelisted in self.whitelisted_domains:
                if value.endswith(whitelisted):
                    return True
        elif artifact_type == 'ip':
            if value in self.whitelisted_ips or self._is_private_ip(value):
                return True
        elif artifact_type == 'url':
            parsed = urlparse(value)
            domain = parsed.netloc
            return self._is_whitelisted(domain, 'domain')
        
        return False
    
    def _should_scan_artifact(self, artifact: NetworkArtifact) -> bool:
        """Determine if artifact should be scanned based on frequency and timing"""
        value = artifact.value
        
        # Skip whitelisted
        if self._is_whitelisted(value, artifact.type):
            return False
        
        # Already scanned recently?
        if value in self.scanned_artifacts:
            return False
        
        # Rate limiting: check frequency
        now = datetime.utcnow()
        timestamps = self.artifact_timestamps[value]
        
        # Remove old timestamps (older than 1 hour)
        timestamps[:] = [ts for ts in timestamps if now - ts < timedelta(hours=1)]
        
        # Add current timestamp
        timestamps.append(now)
        
        # If seen multiple times in short period, prioritize
        if len(timestamps) >= 3:
            artifact.metadata['frequency'] = 'high'
            return True
        
        # If it's a new artifact, scan it
        return True
    
    def _extract_domain_from_dns(self, packet):
        """Extract domain from DNS query"""
        try:
            if packet.haslayer(DNSQR):
                query = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                
                if query and not self._is_whitelisted(query, 'domain'):
                    artifact = NetworkArtifact(
                        artifact_type='domain',
                        value=query,
                        source='dns',
                        metadata={'query_type': 'DNS'}
                    )
                    self._add_artifact(artifact)
                    self.dns_queries.append({
                        'domain': query,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
        except Exception as e:
            logger.debug(f"Error extracting DNS domain: {e}")
    
    def _extract_http_artifacts(self, packet):
        """Extract URLs and domains from HTTP traffic"""
        try:
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # Extract HTTP Host header
                host_match = re.search(r'Host:\s*([^\r\n]+)', payload, re.IGNORECASE)
                if host_match:
                    host = host_match.group(1).strip()
                    
                    # Extract path from GET/POST request
                    request_match = re.search(r'(GET|POST)\s+([^\s]+)', payload)
                    if request_match:
                        path = request_match.group(2)
                        url = f"http://{host}{path}"
                        
                        artifact = NetworkArtifact(
                            artifact_type='url',
                            value=url,
                            source='http',
                            metadata={'host': host, 'path': path}
                        )
                        self._add_artifact(artifact)
                        self.http_requests.append({
                            'url': url,
                            'timestamp': datetime.utcnow().isoformat()
                        })
                    
                    # Also add domain
                    domain_artifact = NetworkArtifact(
                        artifact_type='domain',
                        value=host,
                        source='http',
                        metadata={'protocol': 'http'}
                    )
                    self._add_artifact(domain_artifact)
                    
        except Exception as e:
            logger.debug(f"Error extracting HTTP artifacts: {e}")
    
    def _extract_ip_from_connection(self, packet):
        """Extract IP addresses from network connections"""
        try:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Focus on destination IPs (where traffic is going)
                if dst_ip and not self._is_private_ip(dst_ip):
                    artifact = NetworkArtifact(
                        artifact_type='ip',
                        value=dst_ip,
                        source='connection',
                        metadata={
                            'src_ip': src_ip,
                            'protocol': packet[IP].proto
                        }
                    )
                    
                    # Add port information if TCP/UDP
                    if packet.haslayer(TCP):
                        artifact.metadata['dst_port'] = packet[TCP].dport
                        artifact.metadata['transport'] = 'TCP'
                    elif packet.haslayer(UDP):
                        artifact.metadata['dst_port'] = packet[UDP].dport
                        artifact.metadata['transport'] = 'UDP'
                    
                    self._add_artifact(artifact)
                    self.ip_connections.append({
                        'ip': dst_ip,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
        except Exception as e:
            logger.debug(f"Error extracting IP: {e}")
    
    def _add_artifact(self, artifact: NetworkArtifact):
        """Add artifact to tracking system"""
        value = artifact.value
        
        if value not in self.artifacts:
            self.artifacts[value] = artifact
            self.stats['total_artifacts'] += 1
            
            # Update type-specific counters
            if artifact.type == 'domain':
                self.stats['domains_extracted'] += 1
            elif artifact.type == 'url':
                self.stats['urls_extracted'] += 1
            elif artifact.type == 'ip':
                self.stats['ips_extracted'] += 1
            
            # Add to scan queue if should scan
            if self._should_scan_artifact(artifact):
                self.scan_queue.append(artifact)
                logger.debug(f"📋 Queued for scan: {artifact.type} - {value}")
        else:
            # Update existing artifact metadata
            existing = self.artifacts[value]
            existing.metadata['last_seen'] = datetime.utcnow().isoformat()
            if 'frequency' not in existing.metadata:
                existing.metadata['frequency'] = 1
            else:
                existing.metadata['frequency'] += 1
    
    def _packet_handler(self, packet):
        """Main packet handler for traffic capture"""
        try:
            # Extract DNS queries
            if packet.haslayer(DNS):
                self._extract_domain_from_dns(packet)
            
            # Extract HTTP traffic
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                # Check for HTTP traffic (port 80 or typical web ports)
                if hasattr(packet[TCP], 'dport'):
                    if packet[TCP].dport in [80, 8080, 8000, 8888]:
                        self._extract_http_artifacts(packet)
            
            # Extract IP connections
            self._extract_ip_from_connection(packet)
            
        except Exception as e:
            logger.debug(f"Error in packet handler: {e}")
    
    def _capture_traffic_loop(self):
        """Main traffic capture loop using Scapy"""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available. Cannot capture traffic.")
            return
        
        logger.info("🌐 Starting packet capture (requires root/admin privileges)...")
        
        try:
            # Start sniffing - filter for DNS, HTTP, and HTTPS
            sniff(
                filter="tcp port 80 or tcp port 443 or udp port 53",
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            logger.error("❌ Permission denied. Packet capture requires root/admin privileges.")
            logger.info("💡 Run with: sudo python3 script.py")
            # Fall back to connection monitoring
            self._monitor_connections_fallback()
        except Exception as e:
            logger.error(f"Error in traffic capture: {e}")
            self._monitor_connections_fallback()
    
    def _monitor_connections_fallback(self):
        """Fallback: Monitor connections using psutil (no root required)"""
        logger.info("📡 Using connection monitoring (fallback mode)")
        
        seen_connections = set()
        
        while self.running:
            try:
                # Get all network connections
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port
                        
                        conn_key = f"{remote_ip}:{remote_port}"
                        
                        if conn_key not in seen_connections:
                            seen_connections.add(conn_key)
                            
                            if not self._is_private_ip(remote_ip):
                                artifact = NetworkArtifact(
                                    artifact_type='ip',
                                    value=remote_ip,
                                    source='connection',
                                    metadata={
                                        'port': remote_port,
                                        'status': conn.status
                                    }
                                )
                                self._add_artifact(artifact)
                
                # Clean old connections
                if len(seen_connections) > 10000:
                    seen_connections.clear()
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in connection monitoring: {e}")
                time.sleep(10)
    
    async def _scan_artifacts_loop(self):
        """Process scan queue and send artifacts for analysis"""
        logger.info("🔬 Starting artifact scanning loop")
        
        while self.running:
            try:
                # Collect batch of artifacts to scan
                batch = []
                while len(batch) < self.batch_size and self.scan_queue:
                    artifact = self.scan_queue.popleft()
                    batch.append(artifact)
                
                if batch:
                    logger.info(f"🔍 Scanning batch of {len(batch)} artifacts...")
                    
                    # Send batch for scanning
                    for artifact in batch:
                        try:
                            artifact.scan_status = 'scanning'
                            
                            # Call the scan callback if provided
                            if self.scan_callback:
                                result = await self.scan_callback(artifact)
                                
                                artifact.scan_status = 'scanned'
                                artifact.scan_result = result
                                artifact.threat_level = result.get('verdict', 'unknown')
                                
                                # Mark as scanned
                                self.scanned_artifacts.add(artifact.value)
                                self.stats['artifacts_scanned'] += 1
                                
                                # Track threats
                                if artifact.threat_level in ['malicious', 'suspicious']:
                                    self.stats['threats_detected'] += 1
                                    logger.warning(
                                        f"⚠️ THREAT DETECTED: {artifact.type} - {artifact.value} "
                                        f"[{artifact.threat_level.upper()}]"
                                    )
                                else:
                                    logger.info(f"✅ Clean: {artifact.type} - {artifact.value}")
                            else:
                                logger.warning("No scan callback configured")
                                artifact.scan_status = 'failed'
                                
                        except Exception as e:
                            logger.error(f"Error scanning artifact {artifact.value}: {e}")
                            artifact.scan_status = 'failed'
                            self.stats['scan_errors'] += 1
                    
                    # Wait between batches
                    await asyncio.sleep(self.scan_interval)
                else:
                    # No artifacts to scan, wait
                    await asyncio.sleep(10)
                    
            except Exception as e:
                logger.error(f"Error in scanning loop: {e}")
                await asyncio.sleep(10)
    
    def start(self):
        """Start automatic traffic monitoring and scanning"""
        if self.running:
            logger.warning("Traffic monitor already running")
            return
        
        self.running = True
        
        # Start capture thread
        self.capture_thread = threading.Thread(target=self._capture_traffic_loop, daemon=True)
        self.capture_thread.start()
        
        # Start scan loop in asyncio
        logger.info("✅ Automatic Traffic Monitor started")
        logger.info(f"📊 Scan interval: {self.scan_interval}s, Batch size: {self.batch_size}")
    
    async def start_scan_loop(self):
        """Start the async scanning loop"""
        await self._scan_artifacts_loop()
    
    def stop(self):
        """Stop traffic monitoring"""
        self.running = False
        
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        
        logger.info("🛑 Automatic Traffic Monitor stopped")
        self._print_stats()
    
    def _print_stats(self):
        """Print monitoring statistics"""
        logger.info("=" * 60)
        logger.info("📊 TRAFFIC MONITORING STATISTICS")
        logger.info("=" * 60)
        logger.info(f"Total Artifacts Extracted: {self.stats['total_artifacts']}")
        logger.info(f"  - Domains: {self.stats['domains_extracted']}")
        logger.info(f"  - URLs: {self.stats['urls_extracted']}")
        logger.info(f"  - IPs: {self.stats['ips_extracted']}")
        logger.info(f"Artifacts Scanned: {self.stats['artifacts_scanned']}")
        logger.info(f"Threats Detected: {self.stats['threats_detected']}")
        logger.info(f"Scan Errors: {self.stats['scan_errors']}")
        logger.info("=" * 60)
    
    def get_statistics(self) -> Dict:
        """Get current statistics"""
        return {
            **self.stats,
            'queue_size': len(self.scan_queue),
            'total_tracked_artifacts': len(self.artifacts),
            'scanned_artifacts_count': len(self.scanned_artifacts)
        }
    
    def get_pending_scans(self) -> List[Dict]:
        """Get list of pending scans"""
        return [artifact.to_dict() for artifact in self.scan_queue]
    
    def get_threats(self) -> List[Dict]:
        """Get detected threats"""
        return [
            artifact.to_dict() 
            for artifact in self.artifacts.values()
            if artifact.threat_level in ['malicious', 'suspicious']
        ]
    
    def manual_scan(self, value: str, artifact_type: str = None) -> bool:
        """
        Manually queue an artifact for scanning
        Useful for re-analysis or user-submitted artifacts
        """
        if not artifact_type:
            # Auto-detect type
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
                artifact_type = 'ip'
            elif value.startswith('http://') or value.startswith('https://'):
                artifact_type = 'url'
            else:
                artifact_type = 'domain'
        
        artifact = NetworkArtifact(
            artifact_type=artifact_type,
            value=value,
            source='manual',
            metadata={'manual_submission': True}
        )
        
        self.scan_queue.append(artifact)
        self.artifacts[value] = artifact
        
        logger.info(f"📝 Manually queued: {artifact_type} - {value}")
        return True
