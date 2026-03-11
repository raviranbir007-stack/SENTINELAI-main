"""
AI-Powered Activity Analyzer
Analyzes user activities using 5 threat intelligence APIs and Gemini AI
Provides real-time risk assessment and recommendations
"""

import asyncio
import hashlib
import logging
import requests
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse
import json

logger = logging.getLogger("ActivityAnalyzer")


class ActivityAnalyzer:
    """
    Analyzes activities using multiple threat intelligence sources:
    - VirusTotal
    - AbuseIPDB
    - URLScan.io
    - Shodan
    - Hybrid Analysis
    - Gemini AI
    """

    def __init__(self, server_url: str, api_key: str, api_keys: Dict[str, str] = None):
        self.server_url = server_url
        self.api_key = api_key
        self.api_keys = api_keys or {}
        
        # API endpoints
        self.virustotal_api_key = self.api_keys.get('virustotal', '')
        self.abuseipdb_api_key = self.api_keys.get('abuseipdb', '')
        self.urlscan_api_key = self.api_keys.get('urlscan', '')
        self.shodan_api_key = self.api_keys.get('shodan', '')
        self.hybrid_analysis_api_key = self.api_keys.get('hybrid_analysis', '')
        
        # Cache for results (to avoid repeated API calls)
        self.cache = {}
        self.CACHE_TIMEOUT = 3600  # 1 hour

    def analyze_website(self, url: str, domain: str) -> Dict:
        """
        Analyze website using multiple threat intelligence APIs
        Returns comprehensive risk assessment
        """
        logger.info(f"Analyzing website: {domain}")
        
        results = {
            'url': url,
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'risk_score': 0,
            'risk_level': 'UNKNOWN',
            'threats_detected': [],
            'recommendations': [],
            'api_results': {}
        }
        
        # Check cache
        cache_key = f"url_{domain}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if (datetime.now() - cached['timestamp']).seconds < self.CACHE_TIMEOUT:
                logger.debug(f"Using cached result for {domain}")
                return cached['result']
        
        # 1. VirusTotal URL scan
        vt_result = self._check_virustotal_url(url)
        results['api_results']['virustotal'] = vt_result
        if vt_result.get('malicious', 0) > 0:
            results['risk_score'] += 50
            results['threats_detected'].append(f"VirusTotal: {vt_result['malicious']} engines detected malicious")
        
        # 2. URLScan.io
        urlscan_result = self._check_urlscan(url)
        results['api_results']['urlscan'] = urlscan_result
        if urlscan_result.get('malicious', False):
            results['risk_score'] += 30
            results['threats_detected'].append(f"URLScan: Malicious behavior detected")
        
        # 3. Check IP reputation (AbuseIPDB)
        ip_address = self._resolve_domain(domain)
        if ip_address:
            abuseipdb_result = self._check_abuseipdb(ip_address)
            results['api_results']['abuseipdb'] = abuseipdb_result
            if abuseipdb_result.get('abuse_confidence_score', 0) > 50:
                results['risk_score'] += 40
                results['threats_detected'].append(f"AbuseIPDB: High abuse score ({abuseipdb_result['abuse_confidence_score']})")
        
        # 4. Shodan lookup
        if ip_address:
            shodan_result = self._check_shodan(ip_address)
            results['api_results']['shodan'] = shodan_result
            if shodan_result.get('vulnerable', False):
                results['risk_score'] += 20
                results['threats_detected'].append(f"Shodan: Known vulnerabilities detected")
        
        # 5. Gemini AI Analysis
        gemini_result = self._analyze_with_gemini(url, domain, results['api_results'])
        results['api_results']['gemini'] = gemini_result
        results['recommendations'] = gemini_result.get('recommendations', [])
        
        # Adjust risk score based on Gemini analysis
        if gemini_result.get('risk_level') == 'CRITICAL':
            results['risk_score'] += 50
        elif gemini_result.get('risk_level') == 'HIGH':
            results['risk_score'] += 30
        elif gemini_result.get('risk_level') == 'MEDIUM':
            results['risk_score'] += 15
        
        # Determine final risk level
        results['risk_level'] = self._calculate_risk_level(results['risk_score'])
        
        # Generate recommendations if not from Gemini
        if not results['recommendations']:
            results['recommendations'] = self._generate_recommendations(results)
        
        # Cache result
        self.cache[cache_key] = {
            'timestamp': datetime.now(),
            'result': results
        }
        
        logger.info(f"Analysis complete for {domain}: {results['risk_level']} (score: {results['risk_score']})")
        
        return results

    def analyze_ip(self, ip_address: str) -> Dict:
        """Analyze IP address for threats"""
        logger.info(f"Analyzing IP: {ip_address}")
        
        results = {
            'ip_address': ip_address,
            'timestamp': datetime.now().isoformat(),
            'risk_score': 0,
            'risk_level': 'UNKNOWN',
            'threats_detected': [],
            'recommendations': [],
            'api_results': {}
        }
        
        # Check cache
        cache_key = f"ip_{ip_address}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if (datetime.now() - cached['timestamp']).seconds < self.CACHE_TIMEOUT:
                return cached['result']
        
        # 1. AbuseIPDB
        abuseipdb_result = self._check_abuseipdb(ip_address)
        results['api_results']['abuseipdb'] = abuseipdb_result
        if abuseipdb_result.get('abuse_confidence_score', 0) > 50:
            results['risk_score'] += 60
            results['threats_detected'].append(f"AbuseIPDB: High abuse score")
        
        # 2. VirusTotal IP
        vt_result = self._check_virustotal_ip(ip_address)
        results['api_results']['virustotal'] = vt_result
        if vt_result.get('malicious', 0) > 0:
            results['risk_score'] += 40
            results['threats_detected'].append(f"VirusTotal: Malicious activity detected")
        
        # 3. Shodan
        shodan_result = self._check_shodan(ip_address)
        results['api_results']['shodan'] = shodan_result
        if shodan_result.get('vulnerable', False):
            results['risk_score'] += 30
            results['threats_detected'].append(f"Shodan: Vulnerabilities detected")
        
        # 4. Gemini AI Analysis
        gemini_result = self._analyze_ip_with_gemini(ip_address, results['api_results'])
        results['api_results']['gemini'] = gemini_result
        results['recommendations'] = gemini_result.get('recommendations', [])
        
        # Determine risk level
        results['risk_level'] = self._calculate_risk_level(results['risk_score'])
        
        # Cache result
        self.cache[cache_key] = {
            'timestamp': datetime.now(),
            'result': results
        }
        
        return results

    def analyze_file(self, file_path: str, file_hash: str) -> Dict:
        """Analyze file for malware"""
        logger.info(f"Analyzing file: {file_path}")
        
        results = {
            'file_path': file_path,
            'file_hash': file_hash,
            'timestamp': datetime.now().isoformat(),
            'risk_score': 0,
            'risk_level': 'UNKNOWN',
            'threats_detected': [],
            'recommendations': [],
            'api_results': {}
        }
        
        # Check cache
        cache_key = f"file_{file_hash}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if (datetime.now() - cached['timestamp']).seconds < self.CACHE_TIMEOUT:
                return cached['result']
        
        # 1. VirusTotal file scan
        vt_result = self._check_virustotal_file(file_hash)
        results['api_results']['virustotal'] = vt_result
        if vt_result.get('malicious', 0) > 0:
            results['risk_score'] += 80
            results['threats_detected'].append(f"VirusTotal: {vt_result['malicious']} engines detected malware")
        
        # 2. Hybrid Analysis
        ha_result = self._check_hybrid_analysis(file_hash)
        results['api_results']['hybrid_analysis'] = ha_result
        if ha_result.get('threat_score', 0) > 50:
            results['risk_score'] += 60
            results['threats_detected'].append(f"Hybrid Analysis: High threat score")
        
        # 3. Gemini AI Analysis
        gemini_result = self._analyze_file_with_gemini(file_path, file_hash, results['api_results'])
        results['api_results']['gemini'] = gemini_result
        results['recommendations'] = gemini_result.get('recommendations', [])
        
        # Determine risk level
        results['risk_level'] = self._calculate_risk_level(results['risk_score'])
        
        # Cache result
        self.cache[cache_key] = {
            'timestamp': datetime.now(),
            'result': results
        }
        
        return results

    def _check_virustotal_url(self, url: str) -> Dict:
        """Check URL with VirusTotal"""
        if not self.virustotal_api_key:
            return {'error': 'API key not configured'}
        
        try:
            # URL for scanning
            url_id = hashlib.sha256(url.encode()).hexdigest()
            
            headers = {'x-apikey': self.virustotal_api_key}
            response = requests.get(
                f'https://www.virustotal.com/api/v3/urls/{url_id}',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0)
                }
            else:
                return {'error': f'API returned {response.status_code}'}
                
        except Exception as e:
            logger.error(f"VirusTotal URL check failed: {e}")
            return {'error': str(e)}

    def _check_virustotal_ip(self, ip_address: str) -> Dict:
        """Check IP with VirusTotal"""
        if not self.virustotal_api_key:
            return {'error': 'API key not configured'}
        
        try:
            headers = {'x-apikey': self.virustotal_api_key}
            response = requests.get(
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0)
                }
            else:
                return {'error': f'API returned {response.status_code}'}
                
        except Exception as e:
            logger.error(f"VirusTotal IP check failed: {e}")
            return {'error': str(e)}

    def _check_virustotal_file(self, file_hash: str) -> Dict:
        """Check file hash with VirusTotal"""
        if not self.virustotal_api_key:
            return {'error': 'API key not configured'}
        
        try:
            headers = {'x-apikey': self.virustotal_api_key}
            response = requests.get(
                f'https://www.virustotal.com/api/v3/files/{file_hash}',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0)
                }
            else:
                return {'error': f'API returned {response.status_code}'}
                
        except Exception as e:
            logger.error(f"VirusTotal file check failed: {e}")
            return {'error': str(e)}

    def _check_abuseipdb(self, ip_address: str) -> Dict:
        """Check IP with AbuseIPDB"""
        if not self.abuseipdb_api_key:
            return {'error': 'API key not configured'}
        
        try:
            headers = {'Key': self.abuseipdb_api_key, 'Accept': 'application/json'}
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params={'ipAddress': ip_address, 'maxAgeInDays': 90},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'is_whitelisted': data.get('isWhitelisted', False)
                }
            else:
                return {'error': f'API returned {response.status_code}'}
                
        except Exception as e:
            logger.error(f"AbuseIPDB check failed: {e}")
            return {'error': str(e)}

    def _check_urlscan(self, url: str) -> Dict:
        """Check URL with URLScan.io"""
        if not self.urlscan_api_key:
            return {'error': 'API key not configured'}
        
        try:
            headers = {'API-Key': self.urlscan_api_key}
            # Submit scan
            response = requests.post(
                'https://urlscan.io/api/v1/scan/',
                headers=headers,
                json={'url': url, 'visibility': 'unlisted'},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                # In production, you'd wait and fetch results
                # For now, return submission status
                return {
                    'submitted': True,
                    'uuid': data.get('uuid'),
                    'result': data.get('result')
                }
            else:
                return {'error': f'API returned {response.status_code}'}
                
        except Exception as e:
            logger.error(f"URLScan check failed: {e}")
            return {'error': str(e)}

    def _check_shodan(self, ip_address: str) -> Dict:
        """Check IP with Shodan"""
        if not self.shodan_api_key:
            return {'error': 'API key not configured'}
        
        try:
            response = requests.get(
                f'https://api.shodan.io/shodan/host/{ip_address}',
                params={'key': self.shodan_api_key},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'vulnerable': len(data.get('vulns', [])) > 0,
                    'open_ports': data.get('ports', []),
                    'organization': data.get('org', 'Unknown'),
                    'country': data.get('country_name', 'Unknown')
                }
            else:
                return {'error': f'API returned {response.status_code}'}
                
        except Exception as e:
            logger.error(f"Shodan check failed: {e}")
            return {'error': str(e)}

    def _check_hybrid_analysis(self, file_hash: str) -> Dict:
        """Check file with Hybrid Analysis"""
        if not self.hybrid_analysis_api_key:
            return {'error': 'API key not configured'}
        
        try:
            headers = {'api-key': self.hybrid_analysis_api_key, 'accept': 'application/json'}
            response = requests.get(
                f'https://www.hybrid-analysis.com/api/v2/search/hash',
                headers=headers,
                params={'hash': file_hash},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data:
                    first_result = data[0]
                    return {
                        'threat_score': first_result.get('threat_score', 0),
                        'verdict': first_result.get('verdict', 'unknown'),
                        'malware_family': first_result.get('vx_family', 'None')
                    }
                else:
                    return {'threat_score': 0, 'verdict': 'unknown'}
            else:
                return {'error': f'API returned {response.status_code}'}
                
        except Exception as e:
            logger.error(f"Hybrid Analysis check failed: {e}")
            return {'error': str(e)}

    def _analyze_with_gemini(self, url: str, domain: str, api_results: Dict) -> Dict:
        """Analyze website with Gemini AI"""
        try:
            # Call server's Gemini endpoint
            response = requests.post(
                f'{self.server_url}/api/v1/analyze/url-safety',
                headers={'Authorization': f'Bearer {self.api_key}'},
                json={
                    'url': url,
                    'domain': domain,
                    'api_results': api_results
                },
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'Gemini API returned {response.status_code}'}
                
        except Exception as e:
            logger.error(f"Gemini analysis failed: {e}")
            return {'error': str(e)}

    def _analyze_ip_with_gemini(self, ip_address: str, api_results: Dict) -> Dict:
        """Analyze IP with Gemini AI"""
        try:
            response = requests.post(
                f'{self.server_url}/api/v1/analyze/ip-reputation',
                headers={'Authorization': f'Bearer {self.api_key}'},
                json={
                    'ip_address': ip_address,
                    'api_results': api_results
                },
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'Gemini API returned {response.status_code}'}
                
        except Exception as e:
            logger.error(f"Gemini IP analysis failed: {e}")
            return {'error': str(e)}

    def _analyze_file_with_gemini(self, file_path: str, file_hash: str, api_results: Dict) -> Dict:
        """Analyze file with Gemini AI"""
        try:
            response = requests.post(
                f'{self.server_url}/api/v1/analyze/file-safety',
                headers={'Authorization': f'Bearer {self.api_key}'},
                json={
                    'file_path': file_path,
                    'file_hash': file_hash,
                    'api_results': api_results
                },
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'Gemini API returned {response.status_code}'}
                
        except Exception as e:
            logger.error(f"Gemini file analysis failed: {e}")
            return {'error': str(e)}

    def _resolve_domain(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address"""
        try:
            import socket
            return socket.gethostbyname(domain)
        except Exception as e:
            logger.debug(f"Failed to resolve {domain}: {e}")
            return None

    def _calculate_risk_level(self, risk_score: int) -> str:
        """Calculate risk level from score"""
        if risk_score >= 80:
            return 'CRITICAL'
        elif risk_score >= 60:
            return 'HIGH'
        elif risk_score >= 40:
            return 'MEDIUM'
        elif risk_score >= 20:
            return 'LOW'
        else:
            return 'SAFE'

    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        risk_level = analysis['risk_level']
        
        if risk_level in ['CRITICAL', 'HIGH']:
            recommendations.append("🚫 BLOCK this website/resource immediately")
            recommendations.append("🔍 Run full system scan for potential compromise")
            recommendations.append("🔒 Change passwords if credentials were entered")
        elif risk_level == 'MEDIUM':
            recommendations.append("⚠️  Exercise extreme caution")
            recommendations.append("🛡️  Do not enter sensitive information")
            recommendations.append("📊 Monitor system for unusual activity")
        elif risk_level == 'LOW':
            recommendations.append("⚡ Proceed with caution")
            recommendations.append("🔍 Verify SSL certificate if entering data")
        else:
            recommendations.append("✅ No immediate threats detected")
            recommendations.append("🛡️  Continue following security best practices")
        
        return recommendations
