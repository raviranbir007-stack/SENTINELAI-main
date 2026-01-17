"""
Unified Threat Analysis Orchestrator with AI-Enhanced Detection
Coordinates all threat detection APIs, ML models, and AI analysis
"""

import logging
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List

from ..services.abuseipdb import AbuseIPDBService
from ..services.hybrid_analysis import HybridAnalysisService
from ..services.shodan import ShodanService
from ..services.urlscan import URLScanService
from ..services.virus_total import VirusTotalService
from .input_detector import InputDetector, InputType

# Import ML models
try:
    from ..ml_models import get_anomaly_model, get_threat_model
    ML_MODELS_AVAILABLE = True
except ImportError:
    ML_MODELS_AVAILABLE = False
    logging.warning("ML models not available")

# Import AI analyzer
try:
    from ..ai_engine.analyzer import ThreatAnalyzer as AIAnalyzer
    AI_ANALYZER_AVAILABLE = True
except ImportError:
    AI_ANALYZER_AVAILABLE = False
    logging.warning("AI analyzer not available")

logger = logging.getLogger(__name__)


class ThreatLevel(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class ThreatAnalyzer:
    """
    Unified threat analyzer that:
    - Detects input type automatically
    - Calls appropriate APIs
    - Analyzes responses
    - Returns threat verdict
    """

    def __init__(self):
        self.detector = InputDetector()
        self.shodan = ShodanService()
        self.virustotal = VirusTotalService()
        self.abuseipdb = AbuseIPDBService()
        self.urlscan = URLScanService()
        self.hybrid_analysis = HybridAnalysisService()
        
        # Initialize ML models if available
        if ML_MODELS_AVAILABLE:
            try:
                self.anomaly_model = get_anomaly_model()
                self.threat_model = get_threat_model()
                logger.info("ML models initialized successfully")
            except Exception as e:
                logger.warning(f"Failed to initialize ML models: {e}")
                self.anomaly_model = None
                self.threat_model = None
        else:
            self.anomaly_model = None
            self.threat_model = None
        
        # Initialize AI analyzer if available
        if AI_ANALYZER_AVAILABLE:
            try:
                self.ai_analyzer = AIAnalyzer()
                logger.info("AI analyzer initialized successfully")
            except Exception as e:
                logger.warning(f"Failed to initialize AI analyzer: {e}")
                self.ai_analyzer = None
        else:
            self.ai_analyzer = None

    async def analyze(self, value: str) -> Dict[str, Any]:
        """
        Main analysis method that orchestrates all threat detection

        Args:
            value: Input to analyze (IP, URL, domain, file hash, etc.)

        Returns:
            Dict with threat analysis results
        """
        # Detect input type
        input_type, metadata = self.detector.detect(value)

        analysis_result = {
            "input": value,
            "input_type": input_type.value,
            "metadata": metadata,
            "timestamp": datetime.utcnow().isoformat(),
            "api_results": {},
            "threat_indicators": [],
            "verdict": ThreatLevel.CLEAN,
            "confidence": 0.0,
            "summary": "",
        }

        try:
            # Route to appropriate analysis based on input type
            if input_type == InputType.IP:
                analysis_result = await self._analyze_ip(value, analysis_result)

            elif input_type == InputType.URL:
                analysis_result = await self._analyze_url(value, analysis_result)

            elif input_type == InputType.DOMAIN:
                analysis_result = await self._analyze_domain(value, analysis_result)

            elif input_type == InputType.FILE_HASH:
                hash_type = metadata.get("hash_type")
                analysis_result = await self._analyze_file_hash(
                    value, hash_type, analysis_result
                )

            else:
                analysis_result["verdict"] = ThreatLevel.SUSPICIOUS
                analysis_result["summary"] = (
                    "Input type could not be determined. Please provide a valid IP, URL, domain, or file hash."
                )
            
            # Apply AI-enhanced analysis if primary analysis completed
            if analysis_result.get("verdict") and not analysis_result.get("ai_analysis"):
                logger.info("Applying AI-enhanced analysis to results")
                analysis_result = await self._apply_ai_analysis(analysis_result)

        except Exception as e:
            logger.error(f"Error analyzing {value}: {str(e)}")
            analysis_result["verdict"] = ThreatLevel.SUSPICIOUS
            analysis_result["summary"] = f"Error during analysis: {str(e)}"

        return analysis_result

    def _analyze_ip_heuristics(self, ip: str) -> List[Dict]:
        """
        Comprehensive IP address heuristic analysis for malicious patterns
        """
        threats = []
        
        try:
            import ipaddress
            
            ip_obj = ipaddress.ip_address(ip)
            octets = [int(x) for x in ip.split('.')]
            
            # ============================================
            # 1. RESERVED & SPECIAL IP RANGES
            # ============================================
            if ip_obj.is_private:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "low",
                    "indicator": f"Private IP address ({ip}) - not routable on internet",
                    "type": "private_ip",
                    "confidence": 0.2
                })
            elif ip_obj.is_loopback:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "low",
                    "indicator": "Loopback address (localhost)",
                    "type": "loopback",
                    "confidence": 0.1
                })
            elif ip_obj.is_multicast:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": "Multicast address (unusual for web traffic)",
                    "type": "multicast",
                    "confidence": 0.4
                })
            elif ip_obj.is_reserved:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": "Reserved IP address",
                    "type": "reserved_ip",
                    "confidence": 0.5
                })
            
            # ============================================
            # 2. KNOWN MALICIOUS IP RANGES
            # ============================================
            # Check against commonly abused ranges
            suspicious_ranges = [
                ('185.0.0.0/8', 'Frequently used for malware hosting'),
                ('45.0.0.0/8', 'Common in C2 infrastructure'),
                ('103.0.0.0/8', 'Frequently abused for phishing'),
                ('91.0.0.0/8', 'Eastern Europe - high abuse rate'),
                ('92.0.0.0/8', 'Eastern Europe - high abuse rate'),
                ('93.0.0.0/8', 'Eastern Europe - high abuse rate'),
                ('194.0.0.0/8', 'Bullet-proof hosting region'),
            ]
            
            for range_str, description in suspicious_ranges:
                if ip_obj in ipaddress.ip_network(range_str):
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "medium",
                        "indicator": f"IP in frequently abused range: {description}",
                        "type": "suspicious_range",
                        "confidence": 0.6
                    })
                    break
            
            # ============================================
            # 3. UNUSUAL IP PATTERNS
            # ============================================
            # Sequential pattern detection (common in scanning/botnet)
            if octets[1] == octets[2] == octets[3]:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "low",
                    "indicator": f"Sequential IP pattern (x.{octets[1]}.{octets[2]}.{octets[3]})",
                    "type": "pattern_ip",
                    "confidence": 0.3
                })
            
            # Network/broadcast addresses
            if octets[3] in [0, 1, 255]:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "low",
                    "indicator": f"IP ends in {octets[3]} (network scanning pattern)",
                    "type": "scanning_pattern",
                    "confidence": 0.3
                })
                    
        except Exception as e:
            logger.warning(f"IP heuristic analysis failed: {str(e)}")
        
        return threats

    async def _analyze_ip(self, ip: str, result: Dict) -> Dict:
        """Analyze IP address using AbuseIPDB, Shodan, and heuristic analysis"""
        logger.info(f"Analyzing IP: {ip}")

        threats = []
        apis_called = []
        
        # Run heuristic analysis first
        heuristic_threats = self._analyze_ip_heuristics(ip)
        if heuristic_threats:
            threats.extend(heuristic_threats)
            logger.info(f"IP heuristic analysis found {len(heuristic_threats)} indicator(s)")

        try:
            # Check AbuseIPDB for abuse/malicious activity
            logger.info(f"Checking AbuseIPDB for {ip}")
            abuseipdb_result = await self.abuseipdb.check_ip(ip)
            result["api_results"]["abuseipdb"] = abuseipdb_result
            apis_called.append("AbuseIPDB")

            if abuseipdb_result and abuseipdb_result.get("data"):
                data = abuseipdb_result.get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)

                if abuse_score > 75:
                    threats.append(
                        {
                            "source": "AbuseIPDB",
                            "severity": "critical",
                            "indicator": f"High abuse confidence score: {abuse_score}%",
                            "score": abuse_score,
                        }
                    )
                elif abuse_score > 25:
                    threats.append(
                        {
                            "source": "AbuseIPDB",
                            "severity": "medium",
                            "indicator": f"Moderate abuse confidence score: {abuse_score}%",
                            "score": abuse_score,
                        }
                    )

        except Exception as e:
            logger.warning(f"AbuseIPDB check failed for {ip}: {str(e)}")

        try:
            # Check Shodan for exposed services/vulnerabilities
            logger.info(f"Checking Shodan for {ip}")
            shodan_result = await self.shodan.search_ip(ip)
            result["api_results"]["shodan"] = shodan_result
            apis_called.append("Shodan")

            if shodan_result and not shodan_result.get("error"):
                # Analyze exposed ports and services
                ports = shodan_result.get("ports", [])
                vulns = shodan_result.get("vulns", [])

                if vulns:
                    critical_vulns = [v for v in vulns if "critical" in v.lower()]
                    if critical_vulns:
                        threats.append(
                            {
                                "source": "Shodan",
                                "severity": "critical",
                                "indicator": f"Critical vulnerabilities found: {len(critical_vulns)}",
                                "details": critical_vulns[:5],  # Show first 5
                            }
                        )
                    else:
                        threats.append(
                            {
                                "source": "Shodan",
                                "severity": "medium",
                                "indicator": f"Vulnerabilities found: {len(vulns)}",
                                "details": vulns[:5],
                            }
                        )

                if len(ports) > 10:
                    threats.append(
                        {
                            "source": "Shodan",
                            "severity": "low",
                            "indicator": f"Many open ports detected: {len(ports)}",
                        }
                    )

        except Exception as e:
            logger.warning(f"Shodan search failed for {ip}: {str(e)}")

        result["api_results"]["apis_called"] = apis_called
        result["threat_indicators"] = threats
        result = self._calculate_verdict(result)

        return result

    def _analyze_url_heuristics(self, url: str) -> List[Dict]:
        """
        Comprehensive URL analysis for suspicious patterns using advanced heuristics
        This catches threats that might not be in external API databases yet
        """
        threats = []
        
        try:
            from urllib.parse import urlparse, unquote
            import re
            
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
            full_url = url.lower()
            
            # Decode URL-encoded strings to catch obfuscation
            decoded_url = unquote(full_url)
            decoded_path = unquote(path)
            decoded_query = unquote(query)
            
            # ============================================
            # 1. IP-BASED URL DETECTION (HIGH RISK)
            # ============================================
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            if re.match(ip_pattern, domain.split(':')[0]):
                port = parsed.port
                # Suspicious ports commonly used by malware
                high_risk_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 4321, 12345, 54321]
                medium_risk_ports = [8080, 8443, 3389, 5900, 1433, 3306, 5432, 27017]
                
                if port in high_risk_ports:
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "critical",
                        "indicator": f"Direct IP with high-risk port {port} (common in malware C2 and backdoors)",
                        "type": "suspicious_port",
                        "confidence": 0.9
                    })
                elif port in medium_risk_ports:
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "medium",
                        "indicator": f"Direct IP with exposed service port {port}",
                        "type": "exposed_port",
                        "confidence": 0.6
                    })
                else:
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "medium",
                        "indicator": "Direct IP address instead of domain (suspicious for web content)",
                        "type": "ip_address",
                        "confidence": 0.5
                    })
            
            # ============================================
            # 2. MALICIOUS FILE EXTENSIONS
            # ============================================
            dangerous_extensions = [
                '.exe', '.dll', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', 
                '.ps1', '.scr', '.com', '.pif', '.reg', '.msi', '.jar', '.app',
                '.deb', '.rpm', '.dmg', '.pkg', '.sh', '.bash', '.zsh', '.run'
            ]
            
            for ext in dangerous_extensions:
                if path.endswith(ext) or decoded_path.endswith(ext):
                    # Check for highly suspicious paths
                    critical_paths = [
                        '/cmd/', '/shell/', '/payload/', '/backdoor/', '/exploit/', 
                        '/hack/', '/malware/', '/virus/', '/trojan/', '/c2/', '/c&c/',
                        '/reverse/', '/meterpreter/', '/beacon/', '/implant/', '/rat/',
                        '/keylog/', '/stealer/', '/ransomware/', '/crypter/', '/loader/'
                    ]
                    
                    suspicious_paths = [
                        '/download/', '/get/', '/file/', '/upload/', '/tmp/', '/temp/',
                        '/pub/', '/public/', '/share/', '/data/', '/bin/', '/exe/'
                    ]
                    
                    if any(crit in path for crit in critical_paths):
                        threats.append({
                            "source": "Heuristic Analysis",
                            "severity": "critical",
                            "indicator": f"Executable file ({ext}) in malware-related path: {path[:50]}",
                            "type": "malicious_file",
                            "confidence": 0.95
                        })
                    elif any(susp in path for susp in suspicious_paths):
                        threats.append({
                            "source": "Heuristic Analysis",
                            "severity": "critical",
                            "indicator": f"Executable file ({ext}) in suspicious download path",
                            "type": "suspicious_executable",
                            "confidence": 0.75
                        })
                    else:
                        threats.append({
                            "source": "Heuristic Analysis",
                            "severity": "medium",
                            "indicator": f"Executable file detected: {ext}",
                            "type": "executable",
                            "confidence": 0.5
                        })
            
            # ============================================
            # 3. PHISHING & CREDENTIAL THEFT DETECTION
            # ============================================
            phishing_keywords = [
                'steal', 'phish', 'fake', 'scam', 'fraud', 'spoof',
                'verify-account', 'verify_account', 'account-verify', 'account_verify',
                'login-secure', 'secure-login', 'securelogin', 
                'update-password', 'update_password', 'reset-password',
                'confirm-identity', 'confirm_identity', 'validate-account',
                'suspended-account', 'locked-account', 'security-alert',
                'unusual-activity', 'suspicious-activity',
                'billing-problem', 'payment-failed', 'expire',
                'urgent', 'immediate', 'action-required'
            ]
            
            brand_impersonation = [
                'paypal', 'amazon', 'ebay', 'facebook', 'instagram', 'twitter',
                'microsoft', 'apple', 'google', 'netflix', 'spotify', 'linkedin',
                'bank', 'banking', 'wells-fargo', 'chase', 'citibank', 'usbank',
                'outlook', 'office365', 'o365', 'dropbox', 'icloud', 'gmail'
            ]
            
            for keyword in phishing_keywords:
                if keyword in domain or keyword in decoded_path or keyword in decoded_query:
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "critical",
                        "indicator": f"Phishing pattern detected: '{keyword}' in URL",
                        "type": "phishing",
                        "confidence": 0.85
                    })
                    break
            
            # Check for brand impersonation
            for brand in brand_impersonation:
                if brand in domain:
                    # Check if it's NOT the legitimate domain
                    legitimate_domains = {
                        'paypal': ['paypal.com', 'paypal.co'],
                        'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de'],
                        'microsoft': ['microsoft.com', 'live.com', 'outlook.com'],
                        'google': ['google.com', 'gmail.com', 'youtube.com'],
                        'apple': ['apple.com', 'icloud.com'],
                        'facebook': ['facebook.com', 'fb.com'],
                        'netflix': ['netflix.com'],
                    }
                    
                    is_legitimate = False
                    if brand in legitimate_domains:
                        for legit_domain in legitimate_domains[brand]:
                            if domain.endswith(legit_domain):
                                is_legitimate = True
                                break
                    
                    if not is_legitimate:
                        threats.append({
                            "source": "Heuristic Analysis",
                            "severity": "critical",
                            "indicator": f"Possible brand impersonation: '{brand}' in suspicious domain",
                            "type": "brand_impersonation",
                            "confidence": 0.8
                        })
            
            # ============================================
            # 4. CREDENTIAL HARVESTING DETECTION
            # ============================================
            credential_params = [
                'user=', 'pass=', 'password=', 'passwd=', 'pwd=',
                'username=', 'login=', 'email=', 'credential=',
                'uname=', 'pword=', 'auth=', 'token=', 'session='
            ]
            
            credential_paths = [
                '/steal', '/phish', '/capture', '/harvest', '/grab',
                '/get', '/collect', '/logger', '/log', '/auth'
            ]
            
            has_cred_params = any(param in query for param in credential_params)
            has_cred_path = any(cpath in path for cpath in credential_paths)
            
            if has_cred_params and has_cred_path:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "critical",
                    "indicator": "Credential parameters with malicious path (credential theft)",
                    "type": "credential_theft",
                    "confidence": 0.9
                })
            elif has_cred_params and any(keyword in domain for keyword in phishing_keywords):
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "critical",
                    "indicator": "Credential parameters in suspicious domain",
                    "type": "credential_theft",
                    "confidence": 0.8
                })
            
            # ============================================
            # 5. SUSPICIOUS TLD DETECTION
            # ============================================
            high_risk_tlds = ['.xyz', '.top', '.cc', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.click']
            medium_risk_tlds = ['.info', '.biz', '.su', '.ru', '.cn', '.ws', '.vg', '.buzz']
            
            domain_has_high_risk_tld = any(domain.endswith(tld) for tld in high_risk_tlds)
            domain_has_medium_risk_tld = any(domain.endswith(tld) for tld in medium_risk_tlds)
            
            if domain_has_high_risk_tld:
                # Check if combined with other suspicious indicators
                if any(keyword in domain for keyword in phishing_keywords + brand_impersonation):
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "critical",
                        "indicator": f"High-risk TLD combined with suspicious keywords",
                        "type": "suspicious_tld",
                        "confidence": 0.85
                    })
                else:
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "medium",
                        "indicator": f"Domain uses high-risk TLD (frequently used in malware/phishing)",
                        "type": "suspicious_tld",
                        "confidence": 0.5
                    })
            elif domain_has_medium_risk_tld and any(keyword in domain for keyword in brand_impersonation):
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": f"Medium-risk TLD with brand keywords",
                    "type": "suspicious_tld",
                    "confidence": 0.6
                })
            
            # ============================================
            # 6. TYPOSQUATTING & HOMOGRAPH DETECTION
            # ============================================
            # Common typosquatting patterns
            typosquat_patterns = [
                (r'paypa1', 'paypal'), (r'micros0ft', 'microsoft'),
                (r'g00gle', 'google'), (r'amaz0n', 'amazon'),
                (r'faceboo[k0]', 'facebook'), (r'app1e', 'apple'),
            ]
            
            for pattern, original in typosquat_patterns:
                if re.search(pattern, domain):
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "critical",
                        "indicator": f"Typosquatting detected: impersonating '{original}'",
                        "type": "typosquatting",
                        "confidence": 0.9
                    })
            
            # ============================================
            # 7. DOUBLE EXTENSION DETECTION
            # ============================================
            double_ext_patterns = [
                r'\.pdf\.exe$', r'\.doc\.exe$', r'\.jpg\.exe$',
                r'\.png\.exe$', r'\.txt\.exe$', r'\.zip\.exe$',
                r'\.[a-z]{3,4}\.(exe|dll|bat|cmd|scr)$'
            ]
            
            for pattern in double_ext_patterns:
                if re.search(pattern, path):
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "critical",
                        "indicator": "Double file extension detected (common malware obfuscation)",
                        "type": "double_extension",
                        "confidence": 0.95
                    })
                    break
            
            # ============================================
            # 8. SUSPICIOUS ENCODING & OBFUSCATION
            # ============================================
            # Check for excessive URL encoding (obfuscation)
            encoding_count = full_url.count('%')
            if encoding_count > 5:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": f"Excessive URL encoding detected ({encoding_count} encoded chars - possible obfuscation)",
                    "type": "obfuscation",
                    "confidence": 0.6
                })
            
            # Check for suspicious encoded strings
            suspicious_encoded = ['%2e%2e', '..%2f', '%00', 'javascript:', 'data:', 'vbscript:']
            for encoded in suspicious_encoded:
                if encoded in full_url:
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "critical",
                        "indicator": f"Malicious encoded pattern detected: {encoded}",
                        "type": "malicious_encoding",
                        "confidence": 0.85
                    })
            
            # ============================================
            # 9. DATA EXFILTRATION PATTERNS
            # ============================================
            if len(query) > 200:
                exfil_indicators = ['data=', 'info=', 'content=', 'output=', 'result=', 'dump=']
                if any(indicator in query for indicator in exfil_indicators):
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "medium",
                        "indicator": "Unusually long query string with data parameters (possible exfiltration)",
                        "type": "data_exfiltration",
                        "confidence": 0.65
                    })
            
            # ============================================
            # 10. SUSPICIOUS SUBDOMAINS
            # ============================================
            subdomain_count = domain.count('.')
            if subdomain_count > 3:  # e.g., a.b.c.example.com
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "low",
                    "indicator": f"Excessive subdomains ({subdomain_count} levels - possible DGA or evasion)",
                    "type": "suspicious_subdomain",
                    "confidence": 0.4
                })
            
            # ============================================
            # 11. SHORTENED URL DETECTION
            # ============================================
            url_shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
            if any(shortener in domain for shortener in url_shorteners):
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "low",
                    "indicator": "URL shortener detected (could hide malicious destination)",
                    "type": "url_shortener",
                    "confidence": 0.3
                })
            
            # ============================================
            # 12. SUSPICIOUS PATH PATTERNS
            # ============================================
            malicious_path_keywords = [
                'admin', 'administrator', 'root', 'system', 'config',
                'backup', 'database', 'db', 'sql', 'dump', 'export',
                'shell', 'webshell', 'c99', 'r57', 'b374k'
            ]
            
            for keyword in malicious_path_keywords:
                if f'/{keyword}' in path or f'{keyword}.php' in path:
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "medium",
                        "indicator": f"Suspicious path keyword: '{keyword}' (potential unauthorized access)",
                        "type": "suspicious_path",
                        "confidence": 0.55
                    })
                    break
                    
        except Exception as e:
            logger.warning(f"Heuristic analysis failed: {str(e)}")
        
        return threats

    async def _analyze_url(self, url: str, result: Dict) -> Dict:
        """Analyze URL using VirusTotal, urlscan.io, and heuristic analysis"""
        logger.info(f"Analyzing URL: {url}")

        threats = []
        apis_called = []
        warnings = []
        
        # FIRST: Run heuristic analysis (doesn't require API calls)
        logger.info(f"Running heuristic analysis on URL: {url}")
        heuristic_threats = self._analyze_url_heuristics(url)
        if heuristic_threats:
            threats.extend(heuristic_threats)
            logger.info(f"Heuristic analysis found {len(heuristic_threats)} threat indicator(s)")

        try:
            # Scan with VirusTotal
            logger.info(f"Scanning URL with VirusTotal: {url}")
            vt_result = await self.virustotal.scan_url(url)
            result["api_results"]["virustotal"] = vt_result
            
            # Check if API is configured
            if vt_result and vt_result.get("error"):
                if "not configured" in vt_result.get("error", ""):
                    warnings.append("VirusTotal API key not configured")
                    logger.warning("VirusTotal API key not configured")
                else:
                    apis_called.append("VirusTotal")
            else:
                apis_called.append("VirusTotal")

            if vt_result and not vt_result.get("error"):
                # Check if URL already has analysis results
                if "data" in vt_result:
                    attributes = vt_result.get("data", {}).get("attributes", {})
                    
                    # Try both "stats" and "last_analysis_stats" (different API responses)
                    analysis = attributes.get("stats") or attributes.get("last_analysis_stats", {})
                    
                    malicious = analysis.get("malicious", 0)
                    suspicious = analysis.get("suspicious", 0)
                    harmless = analysis.get("harmless", 0)
                    undetected = analysis.get("undetected", 0)
                    total_engines = sum([malicious, suspicious, harmless, undetected])

                    logger.info(f"VirusTotal results: {malicious} malicious, {suspicious} suspicious out of {total_engines} engines")

                    # Only flag as threat if multiple vendors detect it (reduces false positives)
                    if malicious >= 5:  # At least 5 vendors consider it malicious
                        threats.append(
                            {
                                "source": "VirusTotal",
                                "severity": "critical",
                                "indicator": f"Malicious detection: {malicious}/{total_engines} vendor(s)",
                                "count": malicious,
                            }
                        )
                    elif malicious >= 2:  # 2-4 vendors - suspicious
                        threats.append(
                            {
                                "source": "VirusTotal",
                                "severity": "medium",
                                "indicator": f"Possible threat: {malicious}/{total_engines} vendor(s)",
                                "count": malicious,
                            }
                        )
                    elif suspicious >= 3:
                        threats.append(
                            {
                                "source": "VirusTotal",
                                "severity": "medium",
                                "indicator": f"Suspicious detection: {suspicious}/{total_engines} vendor(s)",
                                "count": suspicious,
                            }
                        )
                    elif total_engines > 0:
                        if malicious > 0 or suspicious > 0:
                            logger.info(f"Low threat indicators: {malicious} malicious, {suspicious} suspicious (below threshold)")
                        else:
                            logger.info(f"URL appears clean according to VirusTotal ({total_engines} engines)")

        except Exception as e:
            logger.warning(f"VirusTotal scan failed for {url}: {str(e)}")
            warnings.append(f"VirusTotal scan failed: {str(e)}")

        try:
            # Scan with URLScan.io
            logger.info(f"Scanning URL with URLScan.io: {url}")
            urlscan_result = await self.urlscan.scan_url(url)
            result["api_results"]["urlscan"] = urlscan_result
            
            # Check if API is configured
            if urlscan_result and urlscan_result.get("error"):
                if "not configured" in urlscan_result.get("error", ""):
                    warnings.append("URLScan API key not configured")
                    logger.warning("URLScan API key not configured")
                else:
                    apis_called.append("URLScan.io")
            else:
                apis_called.append("URLScan.io")

            if urlscan_result and not urlscan_result.get("error"):
                # URLScan returns a UUID immediately, results come later
                # For now, we just record that the scan was submitted
                if "uuid" in urlscan_result:
                    logger.info(f"URLScan.io scan submitted successfully: {urlscan_result.get('uuid')}")
                
                # Check if we have actual results (would need to poll the API)
                if isinstance(urlscan_result, dict) and "data" in urlscan_result:
                    result_data = urlscan_result.get("data", {})

                    # Check for phishing/malware
                    classifications = result_data.get("classifications", {})
                    if isinstance(classifications, dict):
                        if classifications.get("phishing"):
                            threats.append(
                                {
                                    "source": "URLScan.io",
                                    "severity": "critical",
                                    "indicator": "Phishing site detected",
                                }
                            )

                        if classifications.get("malware"):
                            threats.append(
                                {
                                    "source": "URLScan.io",
                                    "severity": "critical",
                                    "indicator": "Malware detected",
                                }
                            )

        except Exception as e:
            logger.warning(f"URLScan scan failed for {url}: {str(e)}")
            warnings.append(f"URLScan scan failed: {str(e)}")

        result["api_results"]["apis_called"] = apis_called
        result["threat_indicators"] = threats
        
        if warnings:
            result["warnings"] = warnings
            
        result = self._calculate_verdict(result)

        return result

    def _analyze_domain_heuristics(self, domain: str) -> List[Dict]:
        """
        Comprehensive domain heuristic analysis for suspicious patterns
        """
        threats = []
        
        try:
            import re
            from datetime import datetime
            
            domain = domain.lower().strip()
            
            # ============================================
            # 1. SUSPICIOUS TLD DETECTION
            # ============================================
            high_risk_tlds = [
                '.xyz', '.top', '.cc', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', 
                '.click', '.stream', '.download', '.work', '.date', '.racing',
                '.win', '.bid', '.faith', '.cricket', '.science', '.party', '.review'
            ]
            
            medium_risk_tlds = [
                '.info', '.biz', '.su', '.ru', '.cn', '.ws', '.vg', '.buzz',
                '.link', '.club', '.site', '.online', '.live', '.space'
            ]
            
            for tld in high_risk_tlds:
                if domain.endswith(tld):
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "medium",
                        "indicator": f"High-risk TLD ({tld}) frequently used in phishing/malware",
                        "type": "suspicious_tld",
                        "confidence": 0.6
                    })
                    break
            
            for tld in medium_risk_tlds:
                if domain.endswith(tld):
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "low",
                        "indicator": f"Medium-risk TLD ({tld}) - monitor for abuse",
                        "type": "suspicious_tld",
                        "confidence": 0.4
                    })
                    break
            
            # ============================================
            # 2. DOMAIN LENGTH & COMPLEXITY
            # ============================================
            # Extremely long domains (common in DGA)
            domain_name = domain.split('.')[0]  # Get domain without TLD
            if len(domain_name) > 30:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": f"Unusually long domain name ({len(domain_name)} chars - possible DGA)",
                    "type": "suspicious_length",
                    "confidence": 0.5
                })
            
            # Check for excessive hyphens or numbers (common in malicious domains)
            hyphen_count = domain_name.count('-')
            if hyphen_count > 3:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "low",
                    "indicator": f"Excessive hyphens in domain ({hyphen_count}) - suspicious pattern",
                    "type": "suspicious_pattern",
                    "confidence": 0.4
                })
            
            # Check for excessive numbers
            number_count = sum(c.isdigit() for c in domain_name)
            if number_count > len(domain_name) * 0.5:  # More than 50% numbers
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": f"High number density in domain ({number_count} digits) - possible DGA",
                    "type": "suspicious_pattern",
                    "confidence": 0.55
                })
            
            # ============================================
            # 3. BRAND IMPERSONATION & TYPOSQUATTING
            # ============================================
            brand_keywords = [
                'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook',
                'instagram', 'twitter', 'netflix', 'spotify', 'linkedin', 'ebay',
                'bank', 'banking', 'chase', 'wellsfargo', 'citibank', 'usbank',
                'outlook', 'office365', 'gmail', 'yahoo', 'icloud', 'dropbox'
            ]
            
            legitimate_domains = {
                'paypal': ['paypal.com', 'paypal.co.uk'],
                'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr'],
                'google': ['google.com', 'gmail.com', 'youtube.com', 'gstatic.com'],
                'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com'],
                'apple': ['apple.com', 'icloud.com', 'me.com'],
                'facebook': ['facebook.com', 'fb.com', 'fbcdn.net'],
                'netflix': ['netflix.com', 'nflxvideo.net'],
            }
            
            for brand in brand_keywords:
                if brand in domain:
                    # Check if it's a legitimate domain
                    is_legitimate = False
                    if brand in legitimate_domains:
                        for legit in legitimate_domains[brand]:
                            if domain.endswith(legit):
                                is_legitimate = True
                                break
                    
                    if not is_legitimate:
                        threats.append({
                            "source": "Heuristic Analysis",
                            "severity": "critical",
                            "indicator": f"Possible brand impersonation: '{brand}' in non-legitimate domain",
                            "type": "brand_impersonation",
                            "confidence": 0.75
                        })
                        break
            
            # ============================================
            # 4. PHISHING KEYWORDS
            # ============================================
            phishing_terms = [
                'verify', 'secure', 'account', 'update', 'confirm', 'login',
                'signin', 'webscr', 'banking', 'suspended', 'locked', 'alert',
                'urgent', 'expire', 'validate', 'restore', 'recover'
            ]
            
            phishing_count = sum(1 for term in phishing_terms if term in domain)
            if phishing_count >= 2:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "critical",
                    "indicator": f"Multiple phishing keywords detected ({phishing_count}) in domain",
                    "type": "phishing_domain",
                    "confidence": 0.8
                })
            elif phishing_count == 1:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": "Phishing-related keyword in domain",
                    "type": "phishing_domain",
                    "confidence": 0.5
                })
            
            # ============================================
            # 5. HOMOGRAPH/IDN ATTACKS
            # ============================================
            # Check for mixed character sets (Cyrillic, Greek lookalikes)
            suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'у', 'х']  # Cyrillic
            if any(char in domain for char in suspicious_chars):
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "critical",
                    "indicator": "Homograph attack detected (lookalike characters)",
                    "type": "homograph",
                    "confidence": 0.9
                })
            
            # Check for IDN domains (punycode)
            if domain.startswith('xn--'):
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": "IDN (internationalized) domain - potential homograph attack",
                    "type": "idn_domain",
                    "confidence": 0.6
                })
            
            # ============================================
            # 6. NEWLY REGISTERED PATTERNS
            # ============================================
            # Look for patterns common in newly registered malicious domains
            new_domain_patterns = [
                r'\d{4,}',  # Long numeric sequences
                r'[a-z]{20,}',  # Very long letter sequences (no spaces)
                r'([a-z]{2})\1{2,}',  # Repeated character pairs (aabbcc)
            ]
            
            for pattern in new_domain_patterns:
                if re.search(pattern, domain_name):
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "low",
                        "indicator": "Domain matches DGA (domain generation algorithm) pattern",
                        "type": "dga_pattern",
                        "confidence": 0.45
                    })
                    break
            
            # ============================================
            # 7. EXCESSIVE SUBDOMAINS
            # ============================================
            subdomain_count = domain.count('.')
            if subdomain_count > 4:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": f"Excessive subdomain levels ({subdomain_count}) - evasion technique",
                    "type": "excessive_subdomains",
                    "confidence": 0.55
                })
            
        except Exception as e:
            logger.warning(f"Domain heuristic analysis failed: {str(e)}")
        
        return threats

    async def _analyze_domain(self, domain: str, result: Dict) -> Dict:
        """Analyze domain using VirusTotal, urlscan.io, and heuristic analysis"""
        logger.info(f"Analyzing domain: {domain}")
        
        # Run heuristic analysis first
        heuristic_threats = self._analyze_domain_heuristics(domain)
        if heuristic_threats:
            if "threat_indicators" not in result:
                result["threat_indicators"] = []
            result["threat_indicators"].extend(heuristic_threats)
            logger.info(f"Domain heuristic analysis found {len(heuristic_threats)} indicator(s)")

        # Construct URL for domain analysis
        url = f"https://{domain}"

        return await self._analyze_url(url, result)

    def _analyze_filehash_heuristics(self, file_hash: str, hash_type: str) -> List[Dict]:
        """
        Heuristic analysis for file hashes
        """
        threats = []
        
        try:
            import re
            
            file_hash = file_hash.lower().strip()
            
            # ============================================
            # 1. KNOWN MALICIOUS HASH PATTERNS
            # ============================================
            # Check for null/empty file hash (0000...0000)
            if re.match(r'^0+$', file_hash):
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": "Null hash detected (empty or corrupted file)",
                    "type": "null_hash",
                    "confidence": 0.7
                })
            
            # Check for all same characters (suspicious pattern)
            if len(set(file_hash)) == 1:
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": "Suspicious hash pattern (all identical characters)",
                    "type": "suspicious_hash",
                    "confidence": 0.6
                })
            
            # ============================================
            # 2. HASH FORMAT VALIDATION
            # ============================================
            expected_lengths = {
                'md5': 32,
                'sha1': 40,
                'sha256': 64
            }
            
            if hash_type in expected_lengths:
                if len(file_hash) != expected_lengths[hash_type]:
                    threats.append({
                        "source": "Heuristic Analysis",
                        "severity": "medium",
                        "indicator": f"Invalid {hash_type.upper()} hash length (expected {expected_lengths[hash_type]}, got {len(file_hash)})",
                        "type": "invalid_hash",
                        "confidence": 0.8
                    })
            
            # Check for non-hexadecimal characters
            if not re.match(r'^[0-9a-f]+$', file_hash):
                threats.append({
                    "source": "Heuristic Analysis",
                    "severity": "medium",
                    "indicator": "Invalid hash format (contains non-hexadecimal characters)",
                    "type": "invalid_hash",
                    "confidence": 0.9
                })
            
        except Exception as e:
            logger.warning(f"File hash heuristic analysis failed: {str(e)}")
        
        return threats

    async def _analyze_file_hash(
        self, file_hash: str, hash_type: str, result: Dict
    ) -> Dict:
        """Analyze file hash using VirusTotal, Hybrid Analysis, and heuristic analysis"""
        logger.info(f"Analyzing file hash ({hash_type}): {file_hash}")

        threats = []
        apis_called = []
        
        # Run heuristic analysis first
        heuristic_threats = self._analyze_filehash_heuristics(file_hash, hash_type)
        if heuristic_threats:
            threats.extend(heuristic_threats)
            logger.info(f"File hash heuristic analysis found {len(heuristic_threats)} indicator(s)")

        try:
            # Scan with VirusTotal
            logger.info(f"Scanning hash with VirusTotal: {file_hash}")
            vt_result = await self.virustotal.scan_file(file_hash)
            result["api_results"]["virustotal"] = vt_result
            apis_called.append("VirusTotal")

            if vt_result:
                if "data" in vt_result:
                    analysis = (
                        vt_result.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {})
                    )
                    malicious = analysis.get("malicious", 0)
                    suspicious = analysis.get("suspicious", 0)

                    if malicious > 0:
                        threats.append(
                            {
                                "source": "VirusTotal",
                                "severity": "critical",
                                "indicator": f"Malware detected by {malicious} vendor(s)",
                                "count": malicious,
                            }
                        )
                    elif suspicious > 0:
                        threats.append(
                            {
                                "source": "VirusTotal",
                                "severity": "medium",
                                "indicator": f"Suspicious file by {suspicious} vendor(s)",
                                "count": suspicious,
                            }
                        )

        except Exception as e:
            logger.warning(f"VirusTotal file scan failed: {str(e)}")

        try:
            # Scan with Hybrid Analysis
            logger.info(f"Scanning hash with Hybrid Analysis: {file_hash}")
            ha_result = await self.hybrid_analysis.search_hash(file_hash)
            result["api_results"]["hybrid_analysis"] = ha_result
            apis_called.append("Hybrid Analysis")

            if ha_result:
                results = ha_result.get("results", [])

                if results:
                    for item in results:
                        verdict = item.get("verdict")
                        threat_score = item.get("threat_score", 0)

                        if verdict == "malicious" or threat_score > 75:
                            threats.append(
                                {
                                    "source": "Hybrid Analysis",
                                    "severity": "critical",
                                    "indicator": f"Malware verdict with score {threat_score}",
                                    "verdict": verdict,
                                }
                            )
                        elif verdict == "suspicious" or threat_score > 25:
                            threats.append(
                                {
                                    "source": "Hybrid Analysis",
                                    "severity": "medium",
                                    "indicator": f"Suspicious verdict with score {threat_score}",
                                    "verdict": verdict,
                                }
                            )

        except Exception as e:
            logger.warning(f"Hybrid Analysis search failed: {str(e)}")

        result["api_results"]["apis_called"] = apis_called
        result["threat_indicators"] = threats
        result = self._calculate_verdict(result)

        return result
    
    async def _apply_ai_analysis(self, result: Dict) -> Dict:
        """
        Apply AI and ML models to enhance threat analysis with predictions
        """
        try:
            if not self.anomaly_model and not self.threat_model and not self.ai_analyzer:
                # No AI/ML available, skip enhancement
                return result
            
            # Prepare features for ML models
            features = {
                'threat_indicators': result.get('threat_indicators', []),
                'verdict': result.get('verdict'),
                'confidence': result.get('confidence', 0),
                'scan_type': result.get('input_type', 'unknown'),
                'api_results': result.get('api_results', {}),
                'malicious_score': result.get('confidence', 0) if result.get('verdict') == ThreatLevel.MALICIOUS else 0
            }
            
            ai_analysis = {}
            
            # Anomaly Detection
            if self.anomaly_model:
                try:
                    anomaly_result = self.anomaly_model.predict(features)
                    ai_analysis['anomaly_detection'] = {
                        'is_anomaly': anomaly_result.get('is_anomaly', False),
                        'score': anomaly_result.get('score', 0),
                        'confidence': anomaly_result.get('confidence', 0),
                        'factors': anomaly_result.get('factors', [])
                    }
                    logger.info(f"Anomaly detection: {anomaly_result.get('is_anomaly')} (score: {anomaly_result.get('score')})")
                except Exception as e:
                    logger.warning(f"Anomaly detection failed: {e}")
            
            # Threat Prediction
            if self.threat_model:
                try:
                    threat_prediction = self.threat_model.predict(features)
                    ai_analysis['threat_prediction'] = {
                        'is_threat': threat_prediction.get('is_threat', False),
                        'probability': threat_prediction.get('probability', 0),
                        'threat_level': threat_prediction.get('threat_level', 'unknown'),
                        'confidence': threat_prediction.get('confidence', 0),
                        'factors': threat_prediction.get('factors', [])
                    }
                    logger.info(f"Threat prediction: {threat_prediction.get('threat_level')} (probability: {threat_prediction.get('probability')})")
                    
                    # Enhance verdict if AI predicts high threat
                    if threat_prediction.get('probability', 0) > 0.8 and result.get('verdict') != ThreatLevel.MALICIOUS:
                        logger.info("AI prediction suggests escalating to MALICIOUS")
                        result['ai_escalation'] = True
                        result['ai_escalation_reason'] = f"AI model predicted {threat_prediction.get('probability'):.0%} threat probability"
                        
                except Exception as e:
                    logger.warning(f"Threat prediction failed: {e}")
            
            # Advanced AI Analysis (Gemini if available)
            if self.ai_analyzer:
                try:
                    threat_data = {
                        'id': result.get('input', 'unknown'),
                        'type': result.get('input_type', 'unknown'),
                        'indicators': result.get('threat_indicators', []),
                        'api_results': result.get('api_results', {}),
                        'verdict': result.get('verdict'),
                        'confidence': result.get('confidence', 0)
                    }
                    
                    ai_result = await self.ai_analyzer.analyze_threat(threat_data)
                    ai_analysis['advanced_ai'] = {
                        'risk_level': ai_result.get('risk_level', 'unknown'),
                        'confidence': ai_result.get('confidence', 0),
                        'threat_types': ai_result.get('threat_types', []),
                        'recommendations': ai_result.get('recommendations', [])
                    }
                    logger.info(f"Advanced AI analysis: {ai_result.get('risk_level')}")
                    
                except Exception as e:
                    logger.warning(f"Advanced AI analysis failed: {e}")
            
            # Add behavioral analysis
            behavioral_analysis = self._generate_behavioral_analysis(result)
            ai_analysis['behavioral_analysis'] = behavioral_analysis
            
            # Calculate reputation score
            reputation_score = self._calculate_reputation_score(result, ai_analysis)
            ai_analysis['reputation_score'] = reputation_score
            
            # Store AI analysis results
            result['ai_analysis'] = ai_analysis
            
            # Refine verdict based on AI insights
            result = self._refine_verdict_with_ai(result, ai_analysis)
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}", exc_info=True)
        
        return result
    
    def _generate_behavioral_analysis(self, result: Dict) -> Dict:
        """
        Generate behavioral analysis based on patterns and characteristics
        """
        behavioral_score = 0
        behaviors = []
        
        try:
            input_type = result.get('input_type', '')
            threat_indicators = result.get('threat_indicators', [])
            
            # Analyze behavior patterns
            if input_type == 'url':
                # URL behavioral patterns
                indicator = result.get('input', '')
                
                if any(port in indicator for port in [':4444', ':5555', ':6666', ':1337']):
                    behavioral_score += 0.3
                    behaviors.append('Uses non-standard port associated with malware')
                
                if any(keyword in indicator.lower() for keyword in ['cmd', 'shell', 'exploit', 'payload']):
                    behavioral_score += 0.25
                    behaviors.append('Contains keywords associated with exploitation')
                
                if len([t for t in threat_indicators if t.get('severity') == 'critical']) >= 2:
                    behavioral_score += 0.2
                    behaviors.append('Multiple critical indicators suggest coordinated attack')
            
            elif input_type == 'ip':
                # IP behavioral patterns
                ip_ranges = result.get('metadata', {}).get('geo_info', {})
                
                if len(threat_indicators) > 3:
                    behavioral_score += 0.25
                    behaviors.append('Multiple threat indicators suggest active malicious activity')
            
            # Check for evasion techniques
            if any('obfuscation' in str(t).lower() for t in threat_indicators):
                behavioral_score += 0.2
                behaviors.append('Uses obfuscation/evasion techniques')
            
            # Check for multi-stage attack patterns
            if len(threat_indicators) >= 3 and len(set(t.get('type', '') for t in threat_indicators)) >= 2:
                behavioral_score += 0.15
                behaviors.append('Exhibits multi-stage attack pattern')
            
            behavioral_score = min(behavioral_score, 1.0)
            
        except Exception as e:
            logger.warning(f"Behavioral analysis failed: {e}")
        
        return {
            'score': round(behavioral_score, 2),
            'behaviors_detected': behaviors,
            'risk_level': 'high' if behavioral_score > 0.7 else 'medium' if behavioral_score > 0.4 else 'low'
        }
    
    def _calculate_reputation_score(self, result: Dict, ai_analysis: Dict) -> Dict:
        """
        Calculate reputation score based on multiple factors
        """
        reputation = 100  # Start with perfect score
        factors = []
        
        try:
            # Deduct points for threats
            threat_indicators = result.get('threat_indicators', [])
            critical_count = sum(1 for t in threat_indicators if t.get('severity') == 'critical')
            medium_count = sum(1 for t in threat_indicators if t.get('severity') == 'medium')
            low_count = sum(1 for t in threat_indicators if t.get('severity') == 'low')
            
            reputation -= critical_count * 25
            reputation -= medium_count * 10
            reputation -= low_count * 5
            
            if critical_count > 0:
                factors.append(f"{critical_count} critical threats (-{critical_count * 25} points)")
            if medium_count > 0:
                factors.append(f"{medium_count} medium threats (-{medium_count * 10} points)")
            
            # AI model influence
            if ai_analysis.get('threat_prediction', {}).get('probability', 0) > 0.8:
                reputation -= 20
                factors.append("AI model high threat probability (-20 points)")
            
            if ai_analysis.get('anomaly_detection', {}).get('is_anomaly', False):
                reputation -= 15
                factors.append("Anomaly detected (-15 points)")
            
            # Behavioral score influence
            behavioral_score = ai_analysis.get('behavioral_analysis', {}).get('score', 0)
            if behavioral_score > 0.7:
                reputation -= 20
                factors.append("High-risk behavior patterns (-20 points)")
            elif behavioral_score > 0.4:
                reputation -= 10
                factors.append("Medium-risk behavior patterns (-10 points)")
            
            # Ensure score stays in valid range
            reputation = max(0, min(100, reputation))
            
        except Exception as e:
            logger.warning(f"Reputation calculation failed: {e}")
        
        return {
            'score': reputation,
            'rating': 'trusted' if reputation >= 80 else 'neutral' if reputation >= 50 else 'suspicious' if reputation >= 30 else 'malicious',
            'factors': factors
        }
    
    def _refine_verdict_with_ai(self, result: Dict, ai_analysis: Dict) -> Dict:
        """
        Refine the threat verdict using AI insights
        """
        try:
            original_verdict = result.get('verdict')
            original_confidence = result.get('confidence', 0)
            
            # Get AI predictions
            threat_prediction = ai_analysis.get('threat_prediction', {})
            anomaly_detection = ai_analysis.get('anomaly_detection', {})
            behavioral_analysis = ai_analysis.get('behavioral_analysis', {})
            reputation = ai_analysis.get('reputation_score', {})
            
            # Escalation logic
            should_escalate = False
            escalation_reasons = []
            
            # Check if AI strongly suggests malicious
            if threat_prediction.get('probability', 0) > 0.85:
                should_escalate = True
                escalation_reasons.append(f"AI threat prediction: {threat_prediction.get('probability'):.0%}")
            
            if anomaly_detection.get('is_anomaly', False) and anomaly_detection.get('score', 0) > 0.8:
                should_escalate = True
                escalation_reasons.append(f"Strong anomaly detected (score: {anomaly_detection.get('score')})")
            
            if behavioral_analysis.get('score', 0) > 0.7:
                should_escalate = True
                escalation_reasons.append(f"High-risk behavior (score: {behavioral_analysis.get('score')})")
            
            if reputation.get('score', 100) < 30:
                should_escalate = True
                escalation_reasons.append(f"Poor reputation score: {reputation.get('score')}")
            
            # Apply escalation if needed
            if should_escalate and original_verdict != ThreatLevel.MALICIOUS:
                if original_verdict == ThreatLevel.CLEAN:
                    result['verdict'] = ThreatLevel.SUSPICIOUS
                    result['confidence'] = 0.65
                else:  # SUSPICIOUS -> MALICIOUS
                    result['verdict'] = ThreatLevel.MALICIOUS
                    result['confidence'] = min(0.90, original_confidence + 0.15)
                
                result['ai_verdict_adjustment'] = {
                    'original_verdict': original_verdict,
                    'adjusted_verdict': result['verdict'],
                    'reasons': escalation_reasons,
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                logger.info(f"Verdict escalated from {original_verdict} to {result['verdict']} based on AI analysis")
            
            # Boost confidence if AI corroborates
            elif original_verdict == ThreatLevel.MALICIOUS:
                if threat_prediction.get('probability', 0) > 0.7:
                    confidence_boost = 0.05
                    result['confidence'] = min(0.98, original_confidence + confidence_boost)
                    result['ai_confidence_boost'] = confidence_boost
        
        except Exception as e:
            logger.warning(f"Verdict refinement failed: {e}")
        
        return result

    def _calculate_verdict(self, result: Dict) -> Dict:
        """
        Calculate final threat verdict based on indicators with forensic corroboration

        Implements multi-source corroboration:
        - Malicious if ≥2 sources confirm threat
        - Tracks evidence sources with links/IDs
        - Confidence increases with more corroboration

        Returns ThreatLevel and confidence score
        """
        threats = result.get("threat_indicators", [])

        if not threats:
            # EVEN FOR CLEAN SCANS: Show which APIs were called and checked
            apis_called = result.get("api_results", {}).get("apis_called", [])
            api_results = result.get("api_results", {})
            
            # Build forensic record showing all APIs checked (even if no threats)
            checked_sources = []
            for api_name in apis_called:
                api_key = api_name.lower().replace(".", "_").replace(" ", "_")
                api_data = api_results.get(api_key, {})
                
                source_info = {
                    "source": api_name,
                    "severity": "info",
                    "indicator": "No threats detected",
                    "timestamp": datetime.utcnow().isoformat(),
                    "status": "checked",
                    "threats_found": 0
                }
                
                # Add specific scan details if available
                if "virustotal" in api_key and "data" in api_data:
                    attrs = api_data.get("data", {}).get("attributes", {})
                    stats = attrs.get("stats") or attrs.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) if stats else 0
                    source_info["details"] = f"Scanned by {total} engines, {malicious} detections"
                    source_info["threats_found"] = malicious
                elif "urlscan" in api_key and "data" in api_data:
                    source_info["details"] = "URL scanned successfully"
                elif "abuseipdb" in api_key and "data" in api_data:
                    score = api_data.get("data", {}).get("abuseConfidenceScore", 0)
                    source_info["details"] = f"Abuse score: {score}%"
                    source_info["threats_found"] = score
                elif "shodan" in api_key and not api_data.get("error"):
                    ports = len(api_data.get("ports", []))
                    source_info["details"] = f"{ports} ports scanned"
                elif "hybridanalysis" in api_key or "hybrid_analysis" in api_key:
                    source_info["details"] = "File hash lookup completed"
                
                checked_sources.append(source_info)
            
            result["verdict"] = ThreatLevel.CLEAN
            result["confidence"] = 1.0
            result["summary"] = f"No threats detected. Verified by {len(apis_called)} API(s)."
            result["forensic_metadata"] = {
                "evidence_sources": apis_called,  # List of API names that were called
                "corroboration_count": 0,  # No threats corroborated
                "corroboration_threshold_met": False,
                "source_details": checked_sources,  # Detailed info about what each API checked
                "apis_checked": len(apis_called),
                "total_apis_available": 5,
                "scan_coverage": f"{len(apis_called)}/5 APIs"
            }
            return result

        # Extract unique sources that detected threats
        unique_sources = set()
        evidence_sources = []
        source_details = []
        
        # Separate heuristic and API threats for proper handling
        heuristic_threats = [t for t in threats if t.get("source") == "Heuristic Analysis"]
        api_threats = [t for t in threats if t.get("source") != "Heuristic Analysis"]
        
        for threat in threats:
            source = threat.get("source")
            if source:
                unique_sources.add(source)
                
                # Build evidence record with source details
                evidence_record = {
                    "source": source,
                    "severity": threat.get("severity"),
                    "indicator": threat.get("indicator"),
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                # Add source-specific IDs/links for forensic traceability
                if "count" in threat:
                    evidence_record["detection_count"] = threat["count"]
                if "score" in threat:
                    evidence_record["score"] = threat["score"]
                if "details" in threat:
                    evidence_record["details"] = threat["details"]
                
                # Add API result reference for full traceability
                api_results = result.get("api_results", {})
                source_key = source.lower().replace(" ", "_").replace(".", "_")
                if source_key in api_results:
                    evidence_record["api_result_ref"] = source_key
                
                evidence_sources.append(source)
                source_details.append(evidence_record)

        # Count sources confirming threats
        corroboration_count = len(unique_sources)
        corroboration_threshold_met = corroboration_count >= 2
        
        # Analyze threat severity with corroboration
        critical_count = sum(1 for t in threats if t.get("severity") == "critical")
        medium_count = sum(1 for t in threats if t.get("severity") == "medium")
        low_count = sum(1 for t in threats if t.get("severity") == "low")
        
        # Count heuristic threats separately
        heuristic_critical = sum(1 for t in heuristic_threats if t.get("severity") == "critical")
        heuristic_medium = sum(1 for t in heuristic_threats if t.get("severity") == "medium")
        heuristic_low = sum(1 for t in heuristic_threats if t.get("severity") == "low")
        
        # Calculate average confidence from heuristic threats
        heuristic_confidences = [t.get("confidence", 0.5) for t in heuristic_threats if "confidence" in t]
        avg_heuristic_confidence = sum(heuristic_confidences) / len(heuristic_confidences) if heuristic_confidences else 0.5
        
        # Calculate highest confidence for critical heuristics
        critical_heuristic_confidences = [t.get("confidence", 0.5) for t in heuristic_threats if t.get("severity") == "critical" and "confidence" in t]
        max_critical_confidence = max(critical_heuristic_confidences) if critical_heuristic_confidences else 0.5

        # Enhanced Multi-source corroboration logic with heuristic confidence support
        # If heuristics found critical threats with high confidence, treat seriously
        if heuristic_critical >= 3:
            # 3+ critical heuristic indicators = very high confidence malicious
            result["verdict"] = ThreatLevel.MALICIOUS
            result["confidence"] = min(0.95, max_critical_confidence + 0.10)
            result["summary"] = (
                f"MALICIOUS - {heuristic_critical} critical threat indicators detected. "
                f"Multiple malicious patterns confirmed through heuristic analysis."
            )
        elif heuristic_critical >= 2:
            # 2 critical heuristic indicators = high confidence malicious
            result["verdict"] = ThreatLevel.MALICIOUS
            result["confidence"] = min(0.90, max_critical_confidence + 0.05)
            result["summary"] = (
                f"MALICIOUS - {heuristic_critical} critical threat indicators detected. "
                f"Pattern-based analysis identified malicious characteristics."
            )
        elif heuristic_critical >= 1 and len(api_threats) > 0:
            # Heuristic + any API threat = corroborated malicious
            result["verdict"] = ThreatLevel.MALICIOUS
            result["confidence"] = min(0.95, max_critical_confidence + (len(api_threats) * 0.05))
            result["summary"] = (
                f"MALICIOUS (CORROBORATED) - Critical threat patterns confirmed by external analysis."
            )
        elif heuristic_critical >= 1 and max_critical_confidence >= 0.85:
            # Single critical heuristic with very high confidence
            result["verdict"] = ThreatLevel.MALICIOUS
            result["confidence"] = max_critical_confidence
            result["summary"] = (
                f"MALICIOUS - High-confidence threat pattern: {heuristic_threats[0].get('indicator', 'Unknown')}"
            )
        elif heuristic_critical >= 1:
            # Single critical heuristic = suspicious with good confidence
            result["verdict"] = ThreatLevel.SUSPICIOUS
            result["confidence"] = min(0.80, max_critical_confidence + 0.05)
            result["summary"] = (
                f"SUSPICIOUS - Critical threat pattern detected: {heuristic_threats[0].get('indicator', 'Unknown')}"
            )
        elif heuristic_medium >= 3:
            # 3+ medium heuristics = likely malicious
            result["verdict"] = ThreatLevel.SUSPICIOUS
            result["confidence"] = min(0.75, avg_heuristic_confidence + 0.10)
            result["summary"] = (
                f"SUSPICIOUS - {heuristic_medium} suspicious patterns detected (strong evidence)."
            )
        elif heuristic_medium >= 2 and avg_heuristic_confidence >= 0.6:
            # 2 medium heuristics with good confidence
            result["verdict"] = ThreatLevel.SUSPICIOUS
            result["confidence"] = min(0.70, avg_heuristic_confidence + 0.05)
            result["summary"] = (
                f"SUSPICIOUS - {heuristic_medium} suspicious patterns detected in analysis."
            )
        elif corroboration_threshold_met:
            # At least 2 sources confirm - higher confidence
            if critical_count > 0:
                result["verdict"] = ThreatLevel.MALICIOUS
                result["confidence"] = min(1.0, 0.85 + (corroboration_count * 0.05))
                result["summary"] = (
                    f"MALICIOUS (CORROBORATED) - {critical_count} critical threat(s) "
                    f"confirmed by {corroboration_count} independent sources."
                )
            elif medium_count >= 2:
                result["verdict"] = ThreatLevel.MALICIOUS
                result["confidence"] = min(1.0, 0.75 + (corroboration_count * 0.05))
                result["summary"] = (
                    f"MALICIOUS (CORROBORATED) - Multiple medium threats "
                    f"confirmed by {corroboration_count} independent sources."
                )
            elif medium_count > 0:
                result["verdict"] = ThreatLevel.SUSPICIOUS
                result["confidence"] = min(1.0, 0.65 + (corroboration_count * 0.05))
                result["summary"] = (
                    f"SUSPICIOUS (CORROBORATED) - Threats detected by "
                    f"{corroboration_count} independent sources."
                )
            else:
                result["verdict"] = ThreatLevel.SUSPICIOUS
                result["confidence"] = 0.60
                result["summary"] = (
                    f"SUSPICIOUS - Low-level threats confirmed by "
                    f"{corroboration_count} sources."
                )
        else:
            # Single source only - lower confidence, more conservative verdict
            if critical_count > 0:
                result["verdict"] = ThreatLevel.MALICIOUS
                result["confidence"] = 0.70  # Lower confidence without corroboration
                result["summary"] = (
                    f"MALICIOUS - {critical_count} critical threat(s) detected "
                    f"(single source - corroboration recommended)."
                )
            elif medium_count >= 2:
                result["verdict"] = ThreatLevel.SUSPICIOUS
                result["confidence"] = 0.55
                result["summary"] = (
                    f"SUSPICIOUS - {medium_count} medium threat(s) detected "
                    f"(single source - manual review recommended)."
                )
            elif medium_count > 0:
                result["verdict"] = ThreatLevel.SUSPICIOUS
                result["confidence"] = 0.50
                result["summary"] = "SUSPICIOUS - Potential threats detected (single source)."
            elif low_count > 0:
                result["verdict"] = ThreatLevel.SUSPICIOUS
                result["confidence"] = 0.35
                result["summary"] = "SUSPICIOUS - Minor threat indicators (single source)."
            else:
                result["verdict"] = ThreatLevel.CLEAN
                result["confidence"] = 0.9
                result["summary"] = "No significant threats detected."

        # Add forensic metadata for reliability tracking
        apis_called = result.get("api_results", {}).get("apis_called", [])
        result["forensic_metadata"] = {
            "evidence_sources": evidence_sources,
            "corroboration_count": corroboration_count,
            "corroboration_threshold_met": corroboration_threshold_met,
            "source_details": source_details,
            "unique_sources": list(unique_sources),
            "total_indicators": len(threats),
            "critical_indicators": critical_count,
            "medium_indicators": medium_count,
            "low_indicators": low_count,
            "heuristic_indicators": {
                "critical": heuristic_critical,
                "medium": heuristic_medium,
                "low": heuristic_low,
                "avg_confidence": round(avg_heuristic_confidence, 2),
                "max_critical_confidence": round(max_critical_confidence, 2)
            },
            "apis_checked": len(apis_called),
            "apis_called_list": apis_called,
            "total_apis_available": 5,
            "scan_coverage": f"{len(apis_called)}/5 APIs"
        }

        return result


# Global instance
threat_analyzer = ThreatAnalyzer()
