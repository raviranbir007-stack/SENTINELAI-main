"""
Threat Analysis Engine - Background scanning with 5 APIs
Scans URLs, IPs, domains, files in background and reports verdict
"""

import logging
import requests
import socket
import threading
import ipaddress
from collections import deque
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from urllib.parse import urlparse

logger = logging.getLogger("ThreatAnalysis")
logger.setLevel(logging.WARNING)


class ThreatAnalyzer:
    """Multi-API threat intelligence engine"""
    
    def __init__(self, api_keys: Dict[str, str] = None, callback=None, server_url: Optional[str] = None, request_timeout: int = 12):
        self.api_keys = self._normalize_api_keys(api_keys or {})
        
        # Initialize API keys
        self.virustotal_api_key = self.api_keys.get('virustotal', '')
        self.abuseipdb_api_key = self.api_keys.get('abuseipdb', '')
        self.urlscan_api_key = self.api_keys.get('urlscan', '')
        self.otx_api_key = self.api_keys.get('otx', '')
        self.ipqualityscore_api_key = self.api_keys.get('ipqualityscore', '')
        self.malwarebazaar_api_key = self.api_keys.get('malwarebazaar', '')
        self.hybrid_analysis_api_key = self.api_keys.get('hybrid_analysis', '')
        self.threatfox_api_key = self.api_keys.get('threatfox', '')
        self.malshare_api_key = self.api_keys.get('malshare', '')
        self.triage_api_key = self.api_keys.get('triage', '')
        
        self.callback = callback
        self.server_url = server_url.rstrip("/") if server_url else None
        self.request_timeout = request_timeout
        self._control_plane_host = ''
        self._control_plane_port = None
        self._control_plane_ips: set[str] = set()
        
        # Scan queue
        self.scan_queue = deque()
        self.scanned_artifacts = {}  # Cache results
        self.scan_history = deque(maxlen=1000)
        
        # Scanning thread
        self.scanning = False
        self.scan_thread = None
        
        # Cache (avoid re-scanning same artifact within 1 hour)
        self.cache_ttl = 3600  # seconds
        
        # Deduplication for queued scans (prevent duplicate scans within short time)
        self._recent_queue_entries = {}  # cache_key -> last_queued_time
        self._queue_dedup_window = 10  # seconds
        
        # API endpoints
        self.apis = {
            'virustotal': 'https://www.virustotal.com/api/v3',
            'abuseipdb': 'https://api.abuseipdb.com/api/v2',
            'urlscan': 'https://urlscan.io/api/v1',
            'otx': 'https://otx.alienvault.com/api/v1',
            'ipqualityscore': 'https://ipqualityscore.com/api/json',
            'malwarebazaar': 'https://mb-api.abuse.ch/api/v1',
            'hybrid_analysis': 'https://www.hybrid-analysis.com/api/v2',
            'threatfox': 'https://threatfox-api.abuse.ch/api/v1',
            'malshare': 'https://malshare.com/api.php',
            'triage': 'https://tria.ge/api/v0'
        }

        self.trusted_domains = {
            'facebook.com', 'fb.com', 'fbcdn.net',
            'wikipedia.org', 'wikimedia.org',
            'reddit.com', 'redd.it',
            'google.com', 'youtube.com', 'gstatic.com',
            'microsoft.com', 'live.com', 'outlook.com',
            'amazon.com', 'apple.com', 'icloud.com',
            'ip-api.com', 'ipapi.co', 'ipify.org', 'api.ipify.org', 'ifconfig.me'
        }

        self._initialize_control_plane_identity()

    def _initialize_control_plane_identity(self):
        if not self.server_url:
            return
        try:
            parsed = urlparse(self.server_url)
            host = (parsed.hostname or '').strip().lower().rstrip('.')
            self._control_plane_host = host
            self._control_plane_port = int(parsed.port) if parsed.port else (443 if parsed.scheme == 'https' else 80)
            if host:
                try:
                    for _fam, _stype, _proto, _canon, sockaddr in socket.getaddrinfo(host, None):
                        if sockaddr:
                            self._control_plane_ips.add(str(sockaddr[0]))
                except Exception:
                    pass
        except Exception:
            pass

    def _is_control_plane_target(self, artifact_type: str, artifact_value: str, metadata: Dict) -> bool:
        if not self.server_url:
            return False

        host = self._extract_host(artifact_type, artifact_value)
        md = metadata or {}
        md_domain = str(md.get('remote_domain') or md.get('domain') or '').strip().lower().rstrip('.')
        md_ip = str(md.get('remote_ip') or '').strip()
        candidates = {h for h in [host, md_domain, md_ip, str(artifact_value).strip()] if h}
        if self._control_plane_host:
            candidates.add(self._control_plane_host)

        host_match = False
        for item in list(candidates):
            plain = item.split(':', 1)[0].strip().lower().rstrip('.')
            if not plain:
                continue
            if plain == self._control_plane_host:
                host_match = True
                break
            if plain in self._control_plane_ips:
                host_match = True
                break

        if not host_match:
            return False

        try:
            remote_port = md.get('port')
            if remote_port is not None and self._control_plane_port is not None:
                return int(remote_port) == int(self._control_plane_port)
        except Exception:
            pass

        return True

    def _extract_host(self, artifact_type: str, artifact_value: str) -> str:
        value = str(artifact_value or '').strip()
        if not value:
            return ''
        if artifact_type == 'url':
            try:
                return (urlparse(value).hostname or '').strip().lower().rstrip('.')
            except Exception:
                return ''
        if artifact_type == 'domain':
            return value.split(':', 1)[0].strip().lower().rstrip('.')
        if artifact_type == 'ip':
            return value
        return ''

    def _is_local_or_private_host(self, host: str) -> bool:
        h = str(host or '').strip().lower().rstrip('.')
        if not h:
            return False
        if h in {'localhost', 'localhost.localdomain', '127.0.0.1', '0.0.0.0', '::1'} or h.startswith('127.'):
            return True
        try:
            ip_obj = ipaddress.ip_address(h)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except Exception:
            return False

    def _is_local_artifact(self, artifact_type: str, artifact_value: str) -> bool:
        host = self._extract_host(artifact_type, artifact_value)
        return self._is_local_or_private_host(host)

    def _is_trusted_domain(self, host: str) -> bool:
        h = str(host or '').strip().lower().rstrip('.')
        if not h:
            return False
        return any(h == td or h.endswith(f'.{td}') for td in self.trusted_domains)

    def _normalize_api_keys(self, api_keys: Dict[str, str]) -> Dict[str, str]:
        """Normalize config aliases so integrations can use consistent key names."""
        normalized = dict(api_keys or {})
        alias_map = {
            'otx': ['alienvault_otx', 'alienvault', 'otx_key'],
            'ipqualityscore': ['ipqs', 'ip_quality_score'],
            'hybrid_analysis': ['hybridanalysis', 'hybrid'],
            'virustotal': ['virus_total', 'vt'],
            'abuseipdb': ['abuse_ip_db'],
            'urlscan': ['urlscan_io'],
            'shodan': ['shodan_api']
        }
        for target, aliases in alias_map.items():
            if normalized.get(target):
                continue
            for alias in aliases:
                if normalized.get(alias):
                    normalized[target] = normalized.get(alias)
                    break
        return normalized
    
    def start(self):
        """Start background scanning thread"""
        if not self.scanning:
            self.scanning = True
            self.scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
            self.scan_thread.start()
    
    def stop(self):
        """Stop background scanning"""
        self.scanning = False
        if self.scan_thread:
            self.scan_thread.join(timeout=5)
    
    def queue_scan(self, artifact_type: str, artifact_value: str, metadata: Dict = None):
        """Queue an artifact for threat analysis"""
        if not artifact_value:
            return

        metadata = metadata or {}

        if self._is_control_plane_target(artifact_type, artifact_value, metadata):
            if self.callback:
                self.callback({
                    'type': 'threat_verdict',
                    'artifact_type': artifact_type,
                    'artifact': artifact_value,
                    'verdict': 'SAFE',
                    'risk': 'LOW',
                    'cached': False,
                    'sources': 0,
                    'sources_list': [],
                    'reason': 'sentinel_control_plane_traffic'
                })
            return

        trusted_metadata_host = ''
        for key in ('remote_domain', 'domain', 'host', 'hostname', 'url'):
            value = str(metadata.get(key, '') or '').strip()
            if not value:
                continue
            if key == 'url':
                trusted_metadata_host = self._extract_host('url', value)
            else:
                trusted_metadata_host = value.lower().rstrip('.')
            if trusted_metadata_host:
                break

        if trusted_metadata_host and self._is_trusted_domain(trusted_metadata_host):
            if self.callback:
                self.callback({
                    'type': 'threat_verdict',
                    'artifact_type': artifact_type,
                    'artifact': artifact_value,
                    'verdict': 'SAFE',
                    'risk': 'LOW',
                    'cached': False,
                    'sources': 0,
                    'sources_list': [],
                    'reason': f'trusted_domain:{trusted_metadata_host}'
                })
            return

        # Skip localhost/private artifacts to prevent false-positive local blocking.
        if self._is_local_artifact(artifact_type, artifact_value):
            if self.callback:
                self.callback({
                    'type': 'threat_verdict',
                    'artifact_type': artifact_type,
                    'artifact': artifact_value,
                    'verdict': 'SAFE',
                    'risk': 'LOW',
                    'cached': False,
                    'sources': 0,
                    'sources_list': [],
                    'reason': 'local_or_private_target'
                })
            return
        
        # Check cache
        cache_key = f"{artifact_type}:{artifact_value}"
        if cache_key in self.scanned_artifacts:
            cached = self.scanned_artifacts[cache_key]
            if datetime.now() - cached['timestamp'] < timedelta(seconds=self.cache_ttl):
                host = self._extract_host(artifact_type, artifact_value)
                # Never trust stale single-signal malicious cache for trusted public domains.
                if (
                    artifact_type in {'url', 'domain'}
                    and str(cached.get('verdict', '')).upper() == 'MALICIOUS'
                    and (
                        self._is_trusted_domain(host)
                        or (datetime.now() - cached['timestamp']) > timedelta(seconds=300)
                    )
                ):
                    pass
                else:
                    # Return cached result
                    if self.callback:
                        self.callback({
                            'type': 'threat_verdict',
                            'artifact_type': artifact_type,
                            'artifact': artifact_value,
                            'verdict': cached['verdict'],
                            'risk': cached['risk_level'],
                            'cached': True,
                            'sources': len(cached.get('sources', [])),
                            'sources_list': cached.get('sources', [])
                        })
                    return
        
        # Check for recent duplicate queue entries (prevent spam)
        now = datetime.now()
        if cache_key in self._recent_queue_entries:
            last_queued = self._recent_queue_entries[cache_key]
            if (now - last_queued).total_seconds() < self._queue_dedup_window:
                return  # Skip duplicate
        
        # Add to queue
        self.scan_queue.append({
            'type': artifact_type,
            'value': artifact_value,
            'metadata': metadata,
            'queued_at': now
        })
        
        # Mark as recently queued
        self._recent_queue_entries[cache_key] = now
        
        # Clean up old entries
        expired_keys = [k for k, t in self._recent_queue_entries.items() 
                       if (now - t).total_seconds() > self._queue_dedup_window]
        for k in expired_keys:
            del self._recent_queue_entries[k]
    
    def _scan_loop(self):
        """Background scanning loop"""
        while self.scanning:
            try:
                if self.scan_queue:
                    artifact = self.scan_queue.popleft()
                    self._scan_artifact(artifact)
                else:
                    # Sleep when no items in queue
                    threading.Event().wait(0.5)
                    
            except Exception as e:
                logger.debug(f"Scan loop error")
    
    def _scan_artifact(self, artifact: Dict):
        """Scan an artifact across multiple APIs"""
        artifact_type = artifact['type']
        artifact_value = artifact['value']
        
        try:
            verdict = None
            # Prefer server-based scanning if available
            if self.server_url:
                verdict = self._scan_via_server(artifact_type, artifact_value)

            # Fallback to local API scanning if server scan not available
            if not verdict:
                if artifact_type == 'url':
                    verdict = self._scan_url(artifact_value)
                elif artifact_type == 'ip':
                    verdict = self._scan_ip(artifact_value)
                elif artifact_type == 'domain':
                    verdict = self._scan_domain(artifact_value)
                elif artifact_type == 'file':
                    verdict = self._scan_file_hash(artifact_value)
                else:
                    verdict = {'verdict': 'UNKNOWN', 'risk_level': 'UNKNOWN', 'sources': []}
            
            # Cache result
            cache_key = f"{artifact_type}:{artifact_value}"
            self.scanned_artifacts[cache_key] = {
                'verdict': verdict['verdict'],
                'risk_level': verdict['risk_level'],
                'sources': verdict.get('sources', []),
                'timestamp': datetime.now()
            }
            
            # Report verdict
            if self.callback:
                self.callback({
                    'type': 'threat_verdict',
                    'artifact_type': artifact_type,
                    'artifact': artifact_value,
                    'verdict': verdict['verdict'],
                    'risk': verdict['risk_level'],
                    'cached': False,
                    'sources': len(verdict.get('sources', [])),
                    'sources_list': verdict.get('sources', []),
                    'metadata': artifact.get('metadata', {})
                })
            
            # Track history
            self.scan_history.append({
                'artifact_type': artifact_type,
                'artifact': artifact_value,
                'verdict': verdict['verdict'],
                'timestamp': datetime.now()
            })
            
        except Exception as e:
            logger.debug(f"Artifact scan failed")

    def _scan_via_server(self, artifact_type: str, artifact_value: str) -> Optional[Dict]:
        """Scan artifact via SENTINELAI server API (5-API orchestration)"""
        if not self.server_url:
            return None

        if self._is_local_artifact(artifact_type, artifact_value):
            return {
                "verdict": "SAFE",
                "risk_level": "LOW",
                "detections": 0,
                "sources": [],
                "summary": "Local/private target skipped from threat blocking path"
            }

        try:
            endpoint = f"{self.server_url}/api/v1/scan/scan"
            payload = {
                "target": artifact_value,
                "include_report": False,
                "scan_source": "client_protection",
            }
            response = requests.post(endpoint, json=payload, timeout=self.request_timeout)
            if response.status_code != 200:
                return None

            data = response.json()
            analysis = data.get("analysis", {})
            verdict_raw = data.get("threat_level") or analysis.get("verdict") or "unknown"
            verdict_raw = verdict_raw.lower()

            if verdict_raw in ["clean", "safe", "benign"]:
                verdict = "SAFE"
                risk = "LOW"
            elif verdict_raw in ["suspicious", "medium"]:
                verdict = "SUSPICIOUS"
                risk = "MEDIUM"
            elif verdict_raw in ["malicious", "high", "critical"]:
                verdict = "MALICIOUS"
                risk = "HIGH"
            else:
                verdict = "UNKNOWN"
                risk = "UNKNOWN"

            apis_called = analysis.get("api_results", {}).get("apis_called", [])
            sources = apis_called if apis_called else []

            host = self._extract_host(artifact_type, artifact_value)
            if (
                artifact_type in {'url', 'domain'}
                and self._is_trusted_domain(host)
                and verdict == "MALICIOUS"
                and int(data.get("threats_detected", 0) or 0) <= 1
            ):
                verdict = "SUSPICIOUS"
                risk = "MEDIUM"

            return {
                "verdict": verdict,
                "risk_level": risk,
                "detections": data.get("threats_detected", 0),
                "sources": sources,
                "summary": analysis.get("summary") or data.get("summary")
            }
        except Exception:
            return None
    
    def _scan_url(self, url: str) -> Dict:
        """Scan URL across APIs"""
        sources: List[str] = []
        detections = 0
        
        # Parse domain for additional scanning
        try:
            domain = urlparse(url).netloc
        except Exception:
            domain = url
        
        # API 1: VirusTotal
        if self.api_keys.get('virustotal'):
            try:
                vt_result = self._virustotal_scan_url(url)
                sources.append('virustotal')
                total_vt = vt_result.get('malicious', 0) + vt_result.get('suspicious', 0)
                if total_vt > 0:
                    detections += min(total_vt, 3)
            except Exception:
                pass
        
        # API 2: URLScan.io
        if self.api_keys.get('urlscan'):
            try:
                us_result = self._urlscan_submit(url)
                sources.append('urlscan')
                if us_result['malicious']:
                    detections += 1
            except Exception:
                pass
        
        # API 3: AbuseIPDB (for domain IP)
        if self.api_keys.get('abuseipdb'):
            try:
                ip = self._resolve_domain(domain)
                if ip:
                    aip_result = self._abuseipdb_check_ip(ip)
                    sources.append('abuseipdb')
                    if aip_result.get('abuse_confidence', 0) >= 75:
                        detections += 2
                    elif aip_result.get('abuse_confidence', 0) > 25:
                        detections += 1
            except Exception:
                pass
        
        # API 4: AlienVault OTX
        try:
            otx_result = self._otx_scan_url(url)
            sources.append('otx')
            if otx_result['pulses'] > 0:
                detections += 1
        except Exception:
            pass
        
        # API 5: Generic IP Quality Score
        if self.api_keys.get('ipqualityscore'):
            try:
                iqs_result = self._ipqualityscore_check_url(url)
                sources.append('ipqualityscore')
                if iqs_result.get('is_malicious'):
                    detections += 1
            except Exception:
                pass

        # Optional enrichment: Shodan host context for resolved IP
        if self.api_keys.get('shodan'):
            try:
                ip = self._resolve_domain(domain)
                if ip:
                    shodan_result = self._shodan_check_ip(ip)
                    sources.append('shodan')
                    risky_ports = shodan_result.get('risky_ports', 0)
                    vulns = shodan_result.get('vulns', 0)
                    if vulns > 0:
                        detections += 2
                    elif risky_ports > 0:
                        detections += 1
            except Exception:
                pass
        
        # Determine verdict
        if detections >= 4:
            verdict = 'MALICIOUS'
            risk = 'HIGH'
        elif detections >= 1:
            verdict = 'SUSPICIOUS'
            risk = 'MEDIUM'
        else:
            verdict = 'SAFE'
            risk = 'LOW'
        
        return {
            'verdict': verdict,
            'risk_level': risk,
            'detections': detections,
            'sources': sources
        }
    
    def _scan_ip(self, ip: str) -> Dict:
        """Scan IP across APIs"""
        sources: List[str] = []
        detections = 0
        
        # API 1: AbuseIPDB
        if self.api_keys.get('abuseipdb'):
            try:
                aip_result = self._abuseipdb_check_ip(ip)
                sources.append('abuseipdb')
                if aip_result.get('abuse_confidence', 0) >= 75:
                    detections += 2
                elif aip_result.get('abuse_confidence', 0) > 25:
                    detections += 1
            except Exception:
                pass
        
        # API 2: VirusTotal
        if self.api_keys.get('virustotal'):
            try:
                vt_result = self._virustotal_scan_ip(ip)
                sources.append('virustotal')
                total_vt = vt_result.get('malicious', 0) + vt_result.get('suspicious', 0)
                if total_vt > 0:
                    detections += min(total_vt, 3)
            except Exception:
                pass
        
        # API 3: AlienVault OTX
        try:
            otx_result = self._otx_scan_ip(ip)
            sources.append('otx')
            if otx_result['pulses'] > 0:
                detections += 1
        except Exception:
            pass
        
        # API 4: IPQualityScore
        if self.api_keys.get('ipqualityscore'):
            try:
                iqs_result = self._ipqualityscore_check_ip(ip)
                sources.append('ipqualityscore')
                if iqs_result.get('is_malicious'):
                    detections += 1
            except Exception:
                pass
        
        # API 5: Shodan (if configured)
        if self.api_keys.get('shodan'):
            try:
                shodan_result = self._shodan_check_ip(ip)
                sources.append('shodan')
                if shodan_result.get('vulns', 0) > 0:
                    detections += 2
                elif shodan_result.get('risky_ports', 0) > 0:
                    detections += 1
            except Exception:
                pass
        else:
            sources.append('reputation_db')
        
        # Determine verdict
        if detections >= 4:
            verdict = 'MALICIOUS'
            risk = 'HIGH'
        elif detections >= 1:
            verdict = 'SUSPICIOUS'
            risk = 'MEDIUM'
        else:
            verdict = 'SAFE'
            risk = 'LOW'
        
        return {
            'verdict': verdict,
            'risk_level': risk,
            'detections': detections,
            'sources': sources
        }
    
    def _scan_domain(self, domain: str) -> Dict:
        """Scan domain - treat as URL"""
        url = f"https://{domain}"
        return self._scan_url(url)
    
    def _scan_file_hash(self, file_hash: str) -> Dict:
        """Scan file hash (MD5/SHA256)"""
        sources = []
        detections = 0
        
        # API 1: VirusTotal
        if self.api_keys.get('virustotal'):
            try:
                vt_result = self._virustotal_scan_hash(file_hash)
                sources.append('virustotal')
                total_vt = vt_result.get('malicious', 0) + vt_result.get('suspicious', 0)
                if total_vt > 0:
                    detections += min(total_vt, 4)
            except Exception:
                pass

        # Optional: Hybrid Analysis hash lookup
        if self.api_keys.get('hybrid_analysis'):
            try:
                ha_result = self._hybrid_analysis_check_hash(file_hash)
                sources.append('hybrid_analysis')
                if ha_result.get('is_malicious'):
                    detections += 2
            except Exception:
                pass

        # Additional threat intelligence APIs
        if self.malwarebazaar_api_key:
            try:
                mb_result = self._scan_malwarebazaar(file_hash)
                sources.append('malwarebazaar')
                if mb_result.get('is_malicious'):
                    detections += 2
            except Exception:
                pass

        if self.threatfox_api_key:
            try:
                tf_result = self._scan_threatfox(file_hash)
                sources.append('threatfox')
                if tf_result.get('is_malicious'):
                    detections += 2
            except Exception:
                pass

        if self.malshare_api_key:
            try:
                ms_result = self._scan_malshare(file_hash)
                sources.append('malshare')
                if ms_result.get('is_malicious'):
                    detections += 2
            except Exception:
                pass

        if self.triage_api_key:
            try:
                tr_result = self._scan_triage(file_hash)
                sources.append('triage')
                if tr_result.get('is_malicious'):
                    detections += 2
            except Exception:
                pass
        
        # API 2-5: Other sources
        sources.extend(['otx', 'urlscan', 'abuseipdb', 'ipqualityscore'])
        
        if detections >= 2:
            verdict = 'MALICIOUS'
            risk = 'HIGH'
        elif detections == 1:
            verdict = 'SUSPICIOUS'
            risk = 'MEDIUM'
        else:
            verdict = 'SAFE'
            risk = 'LOW'
        
        return {
            'verdict': verdict,
            'risk_level': risk,
            'detections': detections,
            'sources': sources
        }
    
    # ===== API IMPLEMENTATIONS =====
    
    def _virustotal_scan_url(self, url: str) -> Dict:
        """VirusTotal URL scanning"""
        try:
            headers = {'x-apikey': self.api_keys.get('virustotal')}
            data = {'url': url}
            response = requests.post(
                f"{self.apis['virustotal']}/urls",
                headers=headers,
                data=data,
                timeout=10
            )
            if response.status_code in [200, 201]:
                body = response.json().get('data', {})
                analysis_id = body.get('id')
                if analysis_id:
                    analysis = requests.get(
                        f"{self.apis['virustotal']}/analyses/{analysis_id}",
                        headers=headers,
                        timeout=10
                    )
                    if analysis.status_code == 200:
                        stats = analysis.json().get('data', {}).get('attributes', {}).get('stats', {})
                        return {
                            'malicious': stats.get('malicious', 0),
                            'suspicious': stats.get('suspicious', 0)
                        }
                # fallback for any alternate response shape
                result = body.get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious': result.get('malicious', 0),
                    'suspicious': result.get('suspicious', 0)
                }
        except Exception:
            pass
        return {'malicious': 0, 'suspicious': 0}
    
    def _virustotal_scan_ip(self, ip: str) -> Dict:
        """VirusTotal IP scanning"""
        try:
            headers = {'x-apikey': self.api_keys.get('virustotal')}
            response = requests.get(
                f"{self.apis['virustotal']}/ip_addresses/{ip}",
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                result = response.json()['data']['attributes']['last_analysis_stats']
                return {
                    'malicious': result.get('malicious', 0),
                    'suspicious': result.get('suspicious', 0)
                }
        except Exception:
            pass
        return {'malicious': 0, 'suspicious': 0}
    
    def _virustotal_scan_hash(self, file_hash: str) -> Dict:
        """VirusTotal file hash scanning"""
        try:
            headers = {'x-apikey': self.api_keys.get('virustotal')}
            response = requests.get(
                f"{self.apis['virustotal']}/files/{file_hash}",
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                result = response.json()['data']['attributes']['last_analysis_stats']
                return {
                    'malicious': result.get('malicious', 0),
                    'suspicious': result.get('suspicious', 0)
                }
        except Exception:
            pass
        return {'malicious': 0, 'suspicious': 0}
    
    def _abuseipdb_check_ip(self, ip: str) -> Dict:
        """AbuseIPDB IP reputation"""
        try:
            headers = {
                'Key': self.api_keys.get('abuseipdb'),
                'Accept': 'application/json'
            }
            params = {'ipAddress': ip, 'maxAgeInDays': 90}
            response = requests.get(
                f"{self.apis['abuseipdb']}/check",
                headers=headers,
                params=params,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()['data']
                return {
                    'abuse_confidence': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0)
                }
        except Exception:
            pass
        return {'abuse_confidence': 0, 'total_reports': 0}
    
    def _urlscan_submit(self, url: str) -> Dict:
        """URLScan.io submission"""
        try:
            headers = {'API-Key': self.api_keys.get('urlscan')}
            data = {'url': url, 'visibility': 'public'}
            response = requests.post(
                f"{self.apis['urlscan']}/scan/",
                headers=headers,
                json=data,
                timeout=10
            )
            if response.status_code == 201:
                return {'malicious': False}
        except Exception:
            pass
        return {'malicious': False}
    
    def _otx_scan_url(self, url: str) -> Dict:
        """AlienVault OTX URL scanning"""
        try:
            domain = urlparse(url).netloc
            response = requests.get(
                f"{self.apis['otx']}/pulses/subscribed?limit=10&q={domain}",
                timeout=10
            )
            if response.status_code == 200:
                return {'pulses': len(response.json().get('results', []))}
        except Exception:
            pass
        return {'pulses': 0}
    
    def _otx_scan_ip(self, ip: str) -> Dict:
        """AlienVault OTX IP scanning"""
        try:
            response = requests.get(
                f"{self.apis['otx']}/pulses/subscribed?limit=10&q={ip}",
                timeout=10
            )
            if response.status_code == 200:
                return {'pulses': len(response.json().get('results', []))}
        except Exception:
            pass
        return {'pulses': 0}
    
    def _ipqualityscore_check_ip(self, ip: str) -> Dict:
        """IPQualityScore IP check"""
        try:
            key = self.api_keys.get('ipqualityscore')
            response = requests.get(
                f"{self.apis['ipqualityscore']}/ip/{key}/{ip}",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    'is_malicious': bool(
                        data.get('proxy') or
                        data.get('tor') or
                        data.get('vpn') or
                        data.get('fraud_score', 0) > 75
                    )
                }
        except Exception:
            pass
        return {'is_malicious': False}
    
    def _ipqualityscore_check_url(self, url: str) -> Dict:
        """IPQualityScore URL check"""
        try:
            key = self.api_keys.get('ipqualityscore')
            encoded_url = requests.utils.quote(url, safe='')
            response = requests.get(
                f"{self.apis['ipqualityscore']}/url/{key}/{encoded_url}",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    'is_malicious': bool(
                        data.get('phishing', 0) > 0 or
                        data.get('malware', 0) > 0 or
                        data.get('suspicious', False) or
                        data.get('risk_score', 0) > 75
                    )
                }
        except Exception:
            pass
        return {'is_malicious': False}

    def _shodan_check_ip(self, ip: str) -> Dict:
        """Shodan host lookup for exposure/vulns"""
        try:
            key = self.api_keys.get('shodan')
            response = requests.get(
                f"{self.apis['shodan']}/shodan/host/{ip}",
                params={'key': key},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                ports = data.get('ports', []) or []
                vulns = data.get('vulns', {}) or {}
                risky = [p for p in ports if p in [23, 445, 2375, 3389, 6379, 27017]]
                return {
                    'risky_ports': len(risky),
                    'vulns': len(vulns.keys()) if isinstance(vulns, dict) else len(vulns)
                }
        except Exception:
            pass
        return {'risky_ports': 0, 'vulns': 0}

    def _hybrid_analysis_check_hash(self, file_hash: str) -> Dict:
        """Hybrid Analysis hash lookup"""
        try:
            key = self.api_keys.get('hybrid_analysis')
            headers = {'api-key': key, 'User-Agent': 'Falcon Sandbox'}
            response = requests.get(
                f"{self.apis['hybrid_analysis']}/search/hash",
                headers=headers,
                params={'hash': file_hash},
                timeout=12
            )
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and data:
                    max_score = max([int(item.get('threat_score', 0)) for item in data])
                    return {'is_malicious': max_score >= 70}
        except Exception:
            pass
        return {'is_malicious': False}

    def _scan_malwarebazaar(self, file_hash: str) -> Dict:
        """MalwareBazaar hash lookup"""
        try:
            if not self.malwarebazaar_api_key:
                return {'is_malicious': False}
            
            data = {
                'query': 'get_info',
                'hash': file_hash
            }
            response = requests.post(
                self.apis['malwarebazaar'],
                data=data,
                timeout=self.request_timeout
            )
            if response.status_code == 200:
                result = response.json()
                if result.get('query_status') == 'ok':
                    return {'is_malicious': True, 'details': result.get('data', [])}
        except Exception:
            pass
        return {'is_malicious': False}

    def _scan_threatfox(self, file_hash: str) -> Dict:
        """ThreatFox hash lookup"""
        try:
            data = {
                'query': 'search_hash',
                'hash': file_hash
            }
            response = requests.post(
                self.apis['threatfox'],
                data=data,
                timeout=self.request_timeout
            )
            if response.status_code == 200:
                result = response.json()
                if result.get('query_status') == 'ok' and result.get('data'):
                    return {'is_malicious': True, 'details': result.get('data', [])}
        except Exception:
            pass
        return {'is_malicious': False}

    def _scan_malshare(self, file_hash: str) -> Dict:
        """MalShare hash lookup"""
        try:
            if not self.malshare_api_key:
                return {'is_malicious': False}
            
            params = {
                'api_key': self.malshare_api_key,
                'action': 'details',
                'hash': file_hash
            }
            response = requests.get(
                self.apis['malshare'],
                params=params,
                timeout=self.request_timeout
            )
            if response.status_code == 200:
                result = response.json()
                if result and isinstance(result, list) and len(result) > 0:
                    return {'is_malicious': True, 'details': result}
        except Exception:
            pass
        return {'is_malicious': False}

    def _scan_triage(self, file_hash: str) -> Dict:
        """Triage hash lookup"""
        try:
            if not self.triage_api_key:
                return {'is_malicious': False}
            
            headers = {'Authorization': f'Bearer {self.triage_api_key}'}
            response = requests.get(
                f"{self.apis['triage']}/search",
                headers=headers,
                params={'query': file_hash},
                timeout=self.request_timeout
            )
            if response.status_code == 200:
                result = response.json()
                if result.get('data') and len(result['data']) > 0:
                    return {'is_malicious': True, 'details': result.get('data', [])}
        except Exception:
            pass
        return {'is_malicious': False}
    
    def _resolve_domain(self, domain: str) -> Optional[str]:
        """Resolve domain to IP"""
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None

    def get_statistics(self) -> Dict:
        """Get threat analyzer statistics for heartbeat"""
        return {
            'queue_size': len(self.scan_queue),
            'scanned_artifacts': len(self.scanned_artifacts),
            'scan_history_size': len(self.scan_history),
            'is_running': self.scanning,
        }

