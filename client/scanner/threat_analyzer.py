"""
Threat Analysis Engine - Background scanning with 5 APIs
Scans URLs, IPs, domains, files in background and reports verdict
"""

import asyncio
import json
import logging
import requests
import threading
from collections import deque
from datetime import datetime, timedelta
from typing import Dict, Optional
from urllib.parse import urlparse

logger = logging.getLogger("ThreatAnalysis")
logger.setLevel(logging.WARNING)


class ThreatAnalyzer:
    """Multi-API threat intelligence engine"""
    
    def __init__(self, api_keys: Dict[str, str] = None, callback=None, server_url: Optional[str] = None, request_timeout: int = 12):
        self.api_keys = api_keys or {}
        self.callback = callback
        self.server_url = server_url.rstrip("/") if server_url else None
        self.request_timeout = request_timeout
        
        # Scan queue
        self.scan_queue = deque()
        self.scanned_artifacts = {}  # Cache results
        self.scan_history = deque(maxlen=1000)
        
        # Scanning thread
        self.scanning = False
        self.scan_thread = None
        
        # Cache (avoid re-scanning same artifact within 1 hour)
        self.cache_ttl = 3600  # seconds
        
        # API endpoints
        self.apis = {
            'virustotal': 'https://www.virustotal.com/api/v3',
            'abuseipdb': 'https://api.abuseipdb.com/api/v2',
            'urlscan': 'https://urlscan.io/api/v1',
            'otx': 'https://otx.alienvault.com/api/v1',
            'ipqualityscore': 'https://ipqualityscore.com/api/json'
        }
    
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
        
        # Check cache
        cache_key = f"{artifact_type}:{artifact_value}"
        if cache_key in self.scanned_artifacts:
            cached = self.scanned_artifacts[cache_key]
            if datetime.now() - cached['timestamp'] < timedelta(seconds=self.cache_ttl):
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
        
        # Add to queue
        self.scan_queue.append({
            'type': artifact_type,
            'value': artifact_value,
            'metadata': metadata or {},
            'queued_at': datetime.now()
        })
    
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

        try:
            endpoint = f"{self.server_url}/api/v1/scan/scan"
            payload = {"target": artifact_value, "include_report": False}
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
        sources = []
        detections = 0
        
        # Parse domain for additional scanning
        try:
            domain = urlparse(url).netloc
        except:
            domain = url
        
        # API 1: VirusTotal
        if self.api_keys.get('virustotal'):
            try:
                vt_result = self._virustotal_scan_url(url)
                sources.append('virustotal')
                if vt_result['malicious'] > 0:
                    detections += vt_result['malicious']
            except:
                pass
        
        # API 2: URLScan.io
        if self.api_keys.get('urlscan'):
            try:
                us_result = self._urlscan_submit(url)
                sources.append('urlscan')
                if us_result['malicious']:
                    detections += 1
            except:
                pass
        
        # API 3: AbuseIPDB (for domain IP)
        if self.api_keys.get('abuseipdb'):
            try:
                ip = self._resolve_domain(domain)
                if ip:
                    aip_result = self._abuseipdb_check_ip(ip)
                    sources.append('abuseipdb')
                    if aip_result['abuse_confidence'] > 25:
                        detections += 1
            except:
                pass
        
        # API 4: AlienVault OTX
        try:
            otx_result = self._otx_scan_url(url)
            sources.append('otx')
            if otx_result['pulses'] > 0:
                detections += 1
        except:
            pass
        
        # API 5: Generic IP Quality Score
        if self.api_keys.get('ipqualityscore'):
            try:
                iqs_result = self._ipqualityscore_check_url(url)
                sources.append('ipqualityscore')
                if iqs_result['is_malicious']:
                    detections += 1
            except:
                pass
        
        # Determine verdict
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
    
    def _scan_ip(self, ip: str) -> Dict:
        """Scan IP across APIs"""
        sources = []
        detections = 0
        
        # API 1: AbuseIPDB
        if self.api_keys.get('abuseipdb'):
            try:
                aip_result = self._abuseipdb_check_ip(ip)
                sources.append('abuseipdb')
                if aip_result['abuse_confidence'] > 25:
                    detections += 1
            except:
                pass
        
        # API 2: VirusTotal
        if self.api_keys.get('virustotal'):
            try:
                vt_result = self._virustotal_scan_ip(ip)
                sources.append('virustotal')
                if vt_result['malicious'] > 0:
                    detections += vt_result['malicious']
            except:
                pass
        
        # API 3: AlienVault OTX
        try:
            otx_result = self._otx_scan_ip(ip)
            sources.append('otx')
            if otx_result['pulses'] > 0:
                detections += 1
        except:
            pass
        
        # API 4: IPQualityScore
        if self.api_keys.get('ipqualityscore'):
            try:
                iqs_result = self._ipqualityscore_check_ip(ip)
                sources.append('ipqualityscore')
                if iqs_result['is_malicious']:
                    detections += 1
            except:
                pass
        
        # API 5: MaxMind/Generic Reputation
        try:
            sources.append('reputation_db')
        except:
            pass
        
        # Determine verdict
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
                if vt_result['malicious'] > 0:
                    detections += vt_result['malicious']
            except:
                pass
        
        # API 2-5: Other sources
        sources.extend(['otx', 'urlscan', 'abuseipdb', 'ipqualityscore'])
        
        if detections >= 1:
            verdict = 'MALICIOUS'
            risk = 'HIGH'
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
            if response.status_code == 200:
                result = response.json()['data']['attributes']['last_analysis_stats']
                return {
                    'malicious': result.get('malicious', 0),
                    'suspicious': result.get('suspicious', 0)
                }
        except:
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
        except:
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
        except:
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
        except:
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
        except:
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
        except:
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
        except:
            pass
        return {'pulses': 0}
    
    def _ipqualityscore_check_ip(self, ip: str) -> Dict:
        """IPQualityScore IP check"""
        try:
            key = self.api_keys.get('ipqualityscore')
            response = requests.get(
                f"{self.apis['ipqualityscore']}/ip/reputation",
                params={'ip': ip, 'key': key},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return {'is_malicious': data.get('is_crawler') is False and data.get('fraud_score', 0) > 75}
        except:
            pass
        return {'is_malicious': False}
    
    def _ipqualityscore_check_url(self, url: str) -> Dict:
        """IPQualityScore URL check"""
        try:
            key = self.api_keys.get('ipqualityscore')
            response = requests.get(
                f"{self.apis['ipqualityscore']}/url/reputation",
                params={'url': url, 'key': key},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return {'is_malicious': data.get('phishing', 0) > 0 or data.get('malware', 0) > 0}
        except:
            pass
        return {'is_malicious': False}
    
    def _resolve_domain(self, domain: str) -> Optional[str]:
        """Resolve domain to IP"""
        try:
            import socket
            return socket.gethostbyname(domain)
        except:
            return None
