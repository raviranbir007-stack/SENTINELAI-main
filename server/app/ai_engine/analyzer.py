"""
AI-powered Threat Analyzer with Gemini AI Integration
Main threat analysis module for Sentinel AI System
"""

import json
import numpy as np
from typing import Dict, List, Any, Tuple, Optional
import logging
from datetime import datetime, timezone

# Import the Gemini integration
try:
    from ..gemini_integration import gemini_integration
    GEMINI_AVAILABLE = True
except ImportError:
    logging.warning("Gemini integration not available")
    GEMINI_AVAILABLE = False
    gemini_integration = None

from ..config import settings

logger = logging.getLogger(__name__)

class ThreatAnalyzer:
    """AI-powered threat analyzer with Gemini AI integration"""
    
    def __init__(self):
        """Initialize the threat analyzer"""
        self.gemini = gemini_integration if GEMINI_AVAILABLE else None
        self.rule_based_analyzer = RuleBasedAnalyzer()
        logger.info(f"Threat Analyzer initialized. Gemini AI: {'Available' if GEMINI_AVAILABLE else 'Not available'}")
    
    async def analyze_threat(self, threat_data: Dict) -> Dict:
        """
        Analyze threat using AI (async version)
        
        Args:
            threat_data: Dictionary containing threat data
            
        Returns:
            Dictionary with threat analysis results
        """
        try:
            logger.debug(f"Starting AI threat analysis for threat ID: {threat_data.get('id', 'unknown')}")
            
            # Enhanced analysis with Gemini if available
            if self.gemini and self.gemini.is_available():
                logger.debug("Using Gemini AI for threat analysis")
                
                # Determine scan type from threat data
                scan_type = self._determine_scan_type(threat_data)
                
                # Analyze with Gemini
                gemini_result = self.gemini.analyze_threat(threat_data, scan_type)
                
                if gemini_result:
                    # Generate comprehensive report
                    report = self.gemini.generate_threat_report(gemini_result)
                    
                    return {
                        "threat_id": threat_data.get("id"),
                        "confidence": gemini_result.get("risk_assessment", {}).get("confidence", 0.95),
                        "risk_level": gemini_result.get("risk_assessment", {}).get("risk_level", "high"),
                        "analysis": gemini_result.get("detailed_findings", {}).get("summary", "AI analysis complete"),
                        "detailed_results": {
                            "gemini_analysis": gemini_result,
                            "threat_report": report,
                            "analysis_method": "gemini_ai",
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        },
                        "threat_types": gemini_result.get("threat_analysis", {}).get("primary_threats", ["unknown"]),
                        "indicators": gemini_result.get("threat_analysis", {}).get("threat_indicators", []),
                        "recommendations": gemini_result.get("recommendations", {}).get("immediate_actions", [])
                    }
            
            # Fallback to rule-based analysis
            logger.debug("Using rule-based analysis")
            result = self.rule_based_analyzer.enhanced_analysis(threat_data)
            
            return {
                "threat_id": threat_data.get("id"),
                "confidence": result.get("confidence", 0.8),
                "risk_level": result.get("threat_level", "medium").lower(),
                "analysis": result.get("description", "Threat analysis complete"),
                "detailed_results": result.get("detailed_analysis", {}),
                "threat_types": result.get("threat_types", ["unknown"]),
                "indicators": result.get("indicators_found", []),
                "recommendations": result.get("recommendations", [])
            }
            
        except Exception as e:
            logger.error(f"Error in threat analysis: {e}", exc_info=True)
            return {
                "threat_id": threat_data.get("id"),
                "confidence": 0.5,
                "risk_level": "unknown",
                "analysis": f"Analysis error: {str(e)}",
                "detailed_results": {"error": str(e)},
                "threat_types": ["analysis_error"],
                "indicators": [],
                "recommendations": ["Review logs for error details"]
            }
    
    async def predict_threat_type(self, indicators: List[str]) -> str:
        """
        Predict threat type from indicators (async version)
        
        Args:
            indicators: List of threat indicators
            
        Returns:
            Predicted threat type
        """
        try:
            logger.debug(f"Predicting threat type from {len(indicators)} indicators")
            
            # Use Gemini for prediction if available
            if self.gemini and self.gemini.is_available():
                # Create prompt for threat type prediction
                prompt = self._create_threat_type_prompt(indicators)
                
                try:
                    generation = self.gemini.generate_text(
                        prompt,
                        max_output_tokens=50,
                        temperature=0.1,
                    )
                    response_text = (generation.get("text") or "").strip()

                    if generation.get("success") and response_text:
                        threat_type = response_text.lower()
                        
                        # Map to common threat types
                        threat_type = self._normalize_threat_type(threat_type)
                        logger.info(f"Gemini predicted threat type: {threat_type}")
                        return threat_type
                        
                except Exception as e:
                    logger.warning(f"Gemini threat type prediction failed: {e}")
            
            # Fallback to rule-based prediction
            return self._rule_based_threat_type_prediction(indicators)
            
        except Exception as e:
            logger.error(f"Error in threat type prediction: {e}")
            return "unknown"
    
    def _create_threat_type_prompt(self, indicators: List[str]) -> str:
        """Create prompt for threat type prediction"""
        indicators_text = "\n".join([f"- {indicator}" for indicator in indicators[:20]])  # Limit to 20 indicators
        
        prompt = f"""Based on these security indicators, what type of threat is most likely?

Indicators:
{indicators_text}

Respond with ONLY one of these threat types:
- malware
- phishing
- network_attack
- data_exfiltration
- ransomware
- command_control
- credential_theft
- denial_of_service
- insider_threat
- unknown

Provide only the threat type name, no explanations."""
        
        return prompt
    
    def _normalize_threat_type(self, threat_type: str) -> str:
        """Normalize threat type to standard categories"""
        threat_type = threat_type.lower().strip()
        
        # Mapping common variations to standard types
        type_mapping = {
            "virus": "malware",
            "trojan": "malware",
            "worm": "malware",
            "spyware": "malware",
            "adware": "malware",
            "botnet": "command_control",
            "c2": "command_control",
            "ddos": "denial_of_service",
            "dos": "denial_of_service",
            "sql injection": "network_attack",
            "xss": "network_attack",
            "brute force": "credential_theft",
            "password attack": "credential_theft",
            "data breach": "data_exfiltration",
            "data theft": "data_exfiltration"
        }
        
        # Check for exact match first
        if threat_type in ["malware", "phishing", "network_attack", "data_exfiltration",
                          "ransomware", "command_control", "credential_theft",
                          "denial_of_service", "insider_threat", "unknown"]:
            return threat_type
        
        # Check for mapped types
        for key, value in type_mapping.items():
            if key in threat_type:
                return value
        
        # Default to unknown
        return "unknown"
    
    def _rule_based_threat_type_prediction(self, indicators: List[str]) -> str:
        """Rule-based threat type prediction"""
        if not indicators:
            return "unknown"
        
        indicator_text = " ".join(indicators).lower()
        
        # Check for malware indicators
        malware_indicators = ["virus", "trojan", "worm", "malware", "executable", "dll", "exe"]
        if any(indicator in indicator_text for indicator in malware_indicators):
            return "malware"
        
        # Check for phishing indicators
        phishing_indicators = ["phish", "credential", "login", "password", "bank", "email"]
        if any(indicator in indicator_text for indicator in phishing_indicators):
            return "phishing"
        
        # Check for network attack indicators
        network_indicators = ["port", "scan", "ddos", "injection", "sql", "xss", "brute"]
        if any(indicator in indicator_text for indicator in network_indicators):
            return "network_attack"
        
        # Check for ransomware
        if "ransom" in indicator_text or "encrypt" in indicator_text:
            return "ransomware"
        
        return "unknown"
    
    def _determine_scan_type(self, data: Dict[str, Any]) -> str:
        """Determine the type of scan from data"""
        if "file_info" in data or "filename" in str(data):
            return "file"
        elif "url" in data or any("http" in str(k).lower() for k in data.keys()):
            return "url"
        elif "ip_address" in data or any(k in ["abuseipdb", "shodan"] for k in data.keys()):
            return "ip"
        elif "system_info" in data:
            return "system"
        else:
            return "general"
    
    # Compatibility methods for existing code
    def enhanced_analysis(self, combined_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enhanced threat analysis (sync version for compatibility)
        
        Args:
            combined_data: Dictionary containing scan results
            
        Returns:
            Comprehensive threat analysis
        """
        try:
            # This is a sync wrapper around async analyze_threat
            # For simplicity, we'll use the rule-based analyzer directly
            return self.rule_based_analyzer.enhanced_analysis(combined_data)
        except Exception as e:
            logger.error(f"Error in enhanced analysis: {e}")
            return self._create_error_analysis()
    
    def analyze_virus_total_result(self, vt_result: Dict[str, Any]) -> Tuple[float, str]:
        """Analyze VirusTotal results (compatibility method)"""
        return self.rule_based_analyzer.analyze_virus_total_result(vt_result)
    
    def analyze_abuseipdb_result(self, abuse_result: Dict[str, Any]) -> Tuple[float, str]:
        """Analyze AbuseIPDB results (compatibility method)"""
        return self.rule_based_analyzer.analyze_abuseipdb_result(abuse_result)
    
    def analyze_shodan_result(self, shodan_result: Dict[str, Any]) -> Tuple[float, str]:
        """Analyze Shodan results (compatibility method)"""
        return self.rule_based_analyzer.analyze_shodan_result(shodan_result)
    
    def aggregate_results(self, results: Dict[str, Tuple[float, str]]) -> Tuple[float, str, List[str]]:
        """Aggregate multiple analysis results (compatibility method)"""
        return self.rule_based_analyzer.aggregate_results(results)
    
    def _create_error_analysis(self) -> Dict[str, Any]:
        """Create error analysis response"""
        return {
            "risk_score": 0.5,
            "threat_level": "UNKNOWN",
            "threat_types": ["analysis_error"],
            "confidence": 0.1,
            "indicators_found": ["analysis_failed"],
            "description": "Threat analysis encountered an error",
            "recommendations": ["Check system logs", "Review input data"],
            "detailed_analysis": {
                "error": True,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }


class RuleBasedAnalyzer:
    """Rule-based analyzer for fallback when AI is not available"""
    
    def __init__(self):
        self.threat_indicators = self._load_threat_indicators()
    
    def _load_threat_indicators(self) -> Dict[str, Any]:
        """Load threat indicators for rule-based analysis"""
        return {
            "malware_categories": ["virus", "trojan", "worm", "ransomware", "spyware"],
            "phishing_indicators": ["login", "password", "credential", "verify", "bank"],
            "network_threats": ["port_scan", "brute_force", "ddos", "injection", "exploit"]
        }
    
    def enhanced_analysis(self, combined_data: Dict[str, Any]) -> Dict[str, Any]:
        """Rule-based enhanced analysis"""
        logger.debug("Performing rule-based analysis")
        
        risk_score = 0.0
        indicators = []
        threat_types = set()
        service_results = {}
        
        # Analyze each service
        for service, data in combined_data.items():
            if service == "virustotal" and data:
                score, details = self.analyze_virus_total_result(data)
                risk_score = max(risk_score, score)
                if score > 0:
                    indicators.append(f"VirusTotal: {details}")
                    threat_types.add("malware")
                service_results[service] = details or "No threats"
            
            elif service == "abuseipdb" and data:
                score, details = self.analyze_abuseipdb_result(data)
                risk_score = max(risk_score, score)
                if score > 0:
                    indicators.append(f"AbuseIPDB: {details}")
                    threat_types.add("network_attack")
                service_results[service] = details or "No abuse"
            
            elif service == "shodan" and data:
                score, details = self.analyze_shodan_result(data)
                risk_score = max(risk_score, score)
                if score > 0:
                    indicators.append(f"Shodan: {details}")
                    threat_types.add("network_exposure")
                service_results[service] = details or "No exposures"
            
            elif service == "urlscan" and data:
                score, details = self.analyze_urlscan_result(data)
                risk_score = max(risk_score, score)
                if score > 0:
                    indicators.append(f"URLScan: {details}")
                    threat_types.add("phishing" if "phishing" in str(details).lower() else "web_threat")
                service_results[service] = details or "No malicious indicators"
        
        # Deduplicate threat types
        if not threat_types:
            threat_types.add("unknown")
        
        threat_level = self._determine_threat_level(risk_score)
        
        return {
            "risk_score": round(risk_score, 3),
            "threat_level": threat_level,
            "threat_types": list(threat_types),
            "confidence": min(0.3 + (len(service_results) * 0.15), 0.8),
            "indicators_found": indicators,
            "description": f"Rule-based analysis: {threat_level} risk based on {len(indicators)} indicators",
            "recommendations": self._get_recommendations(threat_level, threat_types),
            "detailed_analysis": {
                "service_results": service_results,
                "analysis_method": "rule_based",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }
    
    def analyze_virus_total_result(self, vt_result: Dict[str, Any]) -> Tuple[float, str]:
        """Analyze VirusTotal results"""
        try:
            if "found" in vt_result and not vt_result["found"]:
                return 0.0, "Not in database"
            
            stats = vt_result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            total = sum(stats.values())
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            if total == 0:
                return 0.0, "No scan results"
            
            score = (malicious + (suspicious * 0.5)) / total
            
            if malicious > 0:
                details = f"{malicious}/{total} engines detected as malicious"
            elif suspicious > 0:
                details = f"{suspicious}/{total} engines flagged as suspicious"
            else:
                details = "Clean - no detections"
            
            return score, details
            
        except Exception as e:
            logger.error(f"Error analyzing VirusTotal: {e}")
            return 0.0, "Analysis error"
    
    def analyze_abuseipdb_result(self, abuse_result: Dict[str, Any]) -> Tuple[float, str]:
        """Analyze AbuseIPDB results"""
        try:
            ip_data = abuse_result.get("data", {})
            confidence = ip_data.get("abuseConfidenceScore", 0)
            reports = ip_data.get("totalReports", 0)
            
            score = confidence / 100
            
            if confidence >= 80:
                details = f"High abuse confidence ({confidence}%), {reports} reports"
            elif confidence >= 50:
                details = f"Moderate abuse confidence ({confidence}%), {reports} reports"
            elif confidence > 0:
                details = f"Low abuse confidence ({confidence}%), {reports} reports"
            else:
                details = "No abuse reports"
            
            return score, details
            
        except Exception as e:
            logger.error(f"Error analyzing AbuseIPDB: {e}")
            return 0.0, "Analysis error"
    
    def analyze_shodan_result(self, shodan_result: Dict[str, Any]) -> Tuple[float, str]:
        """Analyze Shodan results"""
        try:
            score = 0.0
            details_parts = []
            
            risky_ports = [21, 22, 23, 25, 139, 445, 3389, 5900]
            open_ports = shodan_result.get("ports", [])
            found_risky = [p for p in open_ports if p in risky_ports]
            
            if found_risky:
                score += len(found_risky) * 0.1
                details_parts.append(f"Risky ports: {found_risky}")
            
            vulns = shodan_result.get("vulns", {})
            if vulns:
                score += min(len(vulns) * 0.15, 0.5)
                details_parts.append(f"Vulnerabilities: {len(vulns)}")
            
            score = min(score, 1.0)
            
            if details_parts:
                details = "; ".join(details_parts)
            else:
                details = "No significant exposures"
            
            return score, details
            
        except Exception as e:
            logger.error(f"Error analyzing Shodan: {e}")
            return 0.0, "Analysis error"
    
    def analyze_urlscan_result(self, urlscan_result: Dict[str, Any]) -> Tuple[float, str]:
        """Analyze URLScan results"""
        try:
            verdicts = urlscan_result.get("verdicts", {})
            overall = verdicts.get("overall", {})
            malicious = overall.get("malicious", False)
            score_val = overall.get("score", 0)
            
            if malicious:
                return 0.8, f"Malicious (score: {score_val})"
            elif score_val > 5:
                return score_val / 10, f"Suspicious (score: {score_val})"
            else:
                return 0.0, "Clean"
                
        except Exception as e:
            logger.error(f"Error analyzing URLScan: {e}")
            return 0.0, "Analysis error"
    
    def _determine_threat_level(self, risk_score: float) -> str:
        """Determine threat level from risk score"""
        if risk_score >= 0.8:
            return "CRITICAL"
        elif risk_score >= 0.6:
            return "HIGH"
        elif risk_score >= 0.4:
            return "MEDIUM"
        elif risk_score >= 0.2:
            return "LOW"
        else:
            return "CLEAN"
    
    def _get_recommendations(self, threat_level: str, threat_types: set) -> List[str]:
        """Get recommendations based on threat level and types"""
        recommendations = []
        
        if threat_level in ["HIGH", "CRITICAL"]:
            recommendations.extend([
                "Immediate isolation of affected systems",
                "Notify security team",
                "Begin incident response"
            ])
        
        if "malware" in threat_types:
            recommendations.extend([
                "Run full system antivirus scan",
                "Check for persistence mechanisms"
            ])
        
        if "phishing" in threat_types:
            recommendations.extend([
                "Warn users about phishing attempt",
                "Block malicious URLs"
            ])
        
        if "network_attack" in threat_types:
            recommendations.extend([
                "Block malicious IP addresses",
                "Review firewall rules"
            ])
        
        if threat_level in ["MEDIUM", "HIGH", "CRITICAL"]:
            recommendations.extend([
                "Update security signatures",
                "Review security logs"
            ])
        
        if not recommendations:
            recommendations.append("No immediate action required")
        
        return recommendations
    
    def aggregate_results(self, results: Dict[str, Tuple[float, str]]) -> Tuple[float, str, List[str]]:
        """Aggregate multiple analysis results"""
        if not results:
            return 0.0, "No analysis results", []
        
        try:
            risk_scores = []
            details = []
            
            for service, (score, detail) in results.items():
                if score > 0:
                    risk_scores.append(score)
                    details.append(f"{service}: {detail}")
            
            if not risk_scores:
                return 0.0, "No threats detected", []
            
            avg_score = np.mean(risk_scores)
            max_score = max(risk_scores)
            max_index = risk_scores.index(max_score)
            primary_detail = details[max_index]
            
            return round(avg_score, 3), primary_detail, details
            
        except Exception as e:
            logger.error(f"Error aggregating results: {e}")
            return 0.0, "Error aggregating results", []


# Create a singleton instance for easy import
threat_analyzer = ThreatAnalyzer()
