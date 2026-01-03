"""
Unified Threat Analysis Orchestrator
Coordinates all threat detection APIs and returns verdict
"""

import logging
from datetime import datetime
from enum import Enum
from typing import Any, Dict

from ..services.abuseipdb import AbuseIPDBService
from ..services.hybrid_analysis import HybridAnalysisService
from ..services.shodan import ShodanService
from ..services.urlscan import URLScanService
from ..services.virus_total import VirusTotalService
from .input_detector import InputDetector, InputType

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

        except Exception as e:
            logger.error(f"Error analyzing {value}: {str(e)}")
            analysis_result["verdict"] = ThreatLevel.SUSPICIOUS
            analysis_result["summary"] = f"Error during analysis: {str(e)}"

        return analysis_result

    async def _analyze_ip(self, ip: str, result: Dict) -> Dict:
        """Analyze IP address using AbuseIPDB and Shodan"""
        logger.info(f"Analyzing IP: {ip}")

        threats = []
        apis_called = []

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

    async def _analyze_url(self, url: str, result: Dict) -> Dict:
        """Analyze URL using VirusTotal and urlscan.io"""
        logger.info(f"Analyzing URL: {url}")

        threats = []
        apis_called = []
        warnings = []

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

    async def _analyze_domain(self, domain: str, result: Dict) -> Dict:
        """Analyze domain using VirusTotal and urlscan.io"""
        logger.info(f"Analyzing domain: {domain}")

        # Construct URL for domain analysis
        url = f"https://{domain}"

        return await self._analyze_url(url, result)

    async def _analyze_file_hash(
        self, file_hash: str, hash_type: str, result: Dict
    ) -> Dict:
        """Analyze file hash using VirusTotal and Hybrid Analysis"""
        logger.info(f"Analyzing file hash ({hash_type}): {file_hash}")

        threats = []
        apis_called = []

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

    def _calculate_verdict(self, result: Dict) -> Dict:
        """
        Calculate final threat verdict based on indicators

        Returns ThreatLevel and confidence score
        """
        threats = result.get("threat_indicators", [])

        if not threats:
            result["verdict"] = ThreatLevel.CLEAN
            result["confidence"] = 1.0
            result["summary"] = "No threats detected by any API."
            return result

        # Analyze threat severity
        critical_count = sum(1 for t in threats if t.get("severity") == "critical")
        medium_count = sum(1 for t in threats if t.get("severity") == "medium")
        low_count = sum(1 for t in threats if t.get("severity") == "low")

        if critical_count > 0:
            result["verdict"] = ThreatLevel.MALICIOUS
            result["confidence"] = min(1.0, 0.7 + (critical_count * 0.1))
            result["summary"] = (
                f"MALICIOUS - {critical_count} critical threat(s) detected."
            )

        elif medium_count >= 2 or (medium_count > 0 and low_count > 0):
            result["verdict"] = ThreatLevel.SUSPICIOUS
            result["confidence"] = min(1.0, 0.5 + (medium_count * 0.15))
            result["summary"] = (
                f"SUSPICIOUS - {medium_count} medium threat(s) detected."
            )

        elif medium_count > 0:
            result["verdict"] = ThreatLevel.SUSPICIOUS
            result["confidence"] = 0.6
            result["summary"] = "SUSPICIOUS - Potential threats detected."

        elif low_count > 0:
            result["verdict"] = ThreatLevel.SUSPICIOUS
            result["confidence"] = 0.4
            result["summary"] = "SUSPICIOUS - Minor threat indicators present."

        else:
            result["verdict"] = ThreatLevel.CLEAN
            result["confidence"] = 0.9
            result["summary"] = "No significant threats detected."

        return result


# Global instance
threat_analyzer = ThreatAnalyzer()
