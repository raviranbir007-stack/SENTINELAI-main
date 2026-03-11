"""
Multi-API Corroboration Engine
Implements intelligent threat verification across multiple threat intelligence sources
Addresses the 79.1% single-source detection gap
"""

import logging
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class CorroborationLevel(str, Enum):
    """Levels of corroboration confidence"""
    NONE = "none"  # 0 sources
    SINGLE = "single"  # 1 source
    LOW = "low"  # 2 sources
    MEDIUM = "medium"  # 3 sources
    HIGH = "high"  # 4+ sources
    UNANIMOUS = "unanimous"  # All sources agree


class ThreatVerdict(str, Enum):
    """Final threat verdict after corroboration"""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CRITICAL = "critical"


class CorroborationEngine:
    """
    Enhanced threat intelligence corroboration system
    
    Features:
    - Minimum corroboration thresholds before incident response
    - Source weighting based on reliability
    - Temporal analysis of threat indicators
    - False positive reduction through multi-source verification
    - Novel threat detection (zero-day indicators)
    """
    
    # API source reliability weights (0.0 - 1.0)
    SOURCE_WEIGHTS = {
        'VirusTotal': 0.95,  # High reliability, large vendor pool
        'AbuseIPDB': 0.90,  # Strong for IP reputation
        'Shodan': 0.85,  # Good for infrastructure analysis
        'URLScan': 0.80,  # Reliable for URL analysis
        'URLScan.io': 0.80,  # Alias used in some scan metadata
        'HybridAnalysis': 0.90,  # Strong malware analysis
        'Heuristic Analysis': 0.70,  # Pattern-based, needs corroboration
        'ML Model': 0.75,  # AI predictions, needs validation
        'AI Analysis': 0.80,  # Enhanced AI analysis
    }
    
    # Minimum sources required for different actions
    THRESHOLDS = {
        'alert': 1,  # Single source = create alert
        'quarantine': 2,  # 2 sources = isolate/quarantine
        'block': 3,  # 3 sources = block/deny
        'incident_response': 3,  # 3+ sources = trigger IR
    }

    API_NAME_MAP = {
        'virustotal': 'VirusTotal',
        'abuseipdb': 'AbuseIPDB',
        'shodan': 'Shodan',
        'urlscan': 'URLScan',
        'urlscan_result': 'URLScan',
        'hybrid_analysis': 'HybridAnalysis',
        'hybridanalysis': 'HybridAnalysis',
    }
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        
        # Allow custom thresholds
        if 'thresholds' in self.config:
            self.THRESHOLDS.update(self.config['thresholds'])
        
        # Statistics
        self.stats = {
            'total_analyses': 0,
            'single_source': 0,
            'multi_source': 0,
            'corroborated': 0,
            'false_positive_candidates': 0,
            'novel_threats': 0
        }
    
    def analyze_corroboration(self, api_results: Dict[str, Any], 
                             threat_indicators: List[Dict],
                             input_type: str = None) -> Dict[str, Any]:
        """
        Analyze threat intelligence from multiple sources and provide corroborated verdict
        
        Args:
            api_results: Dict of API responses {api_name: response}
            threat_indicators: List of threat indicators from various sources
            input_type: Type of input being analyzed (ip, url, domain, hash)
        
        Returns:
            Dict with corroboration analysis and verdict
        """
        self.stats['total_analyses'] += 1
        
        # Extract sources and their findings
        sources_data = self._extract_sources(api_results, threat_indicators)
        
        # Calculate corroboration metrics
        corroboration_metrics = self._calculate_corroboration(sources_data)
        
        # Determine final verdict with confidence
        verdict_data = self._determine_verdict(corroboration_metrics, sources_data)
        
        # Generate actionable recommendations
        recommendations = self._generate_recommendations(verdict_data, corroboration_metrics)
        
        # Update statistics
        self._update_statistics(corroboration_metrics)
        
        result = {
            'corroboration': {
                'level': corroboration_metrics['level'],
                'source_count': corroboration_metrics['source_count'],
                'sources': corroboration_metrics['sources'],
                'weighted_score': corroboration_metrics['weighted_score'],
                'agreement_rate': corroboration_metrics['agreement_rate'],
                'timestamp': datetime.utcnow().isoformat()
            },
            'verdict': {
                'classification': verdict_data['classification'],
                'confidence': verdict_data['confidence'],
                'severity': verdict_data['severity'],
                'explanation': verdict_data['explanation']
            },
            'recommendations': recommendations,
            'evidence': {
                'sources': sources_data,
                'threat_indicators': threat_indicators,
                'api_results_summary': self._summarize_api_results(api_results)
            },
            'flags': {
                'single_source_only': corroboration_metrics['source_count'] == 1,
                'requires_manual_review': verdict_data['requires_manual_review'],
                'novel_threat_indicator': corroboration_metrics['novel_threat'],
                'high_confidence': verdict_data['confidence'] >= 0.85,
                'meets_incident_threshold': corroboration_metrics['source_count'] >= self.THRESHOLDS['incident_response']
            }
        }
        
        return result
    
    def _extract_sources(self, api_results: Dict, threat_indicators: List[Dict]) -> List[Dict]:
        """Extract and normalize data from all sources"""
        sources = []
        source_names_seen: Set[str] = set()
        
        # Process API results
        for api_name, result in api_results.items():
            if api_name in {'apis_called', 'apis_attempted', 'apis_expected', 'api_status'}:
                continue
            if not isinstance(result, dict):
                continue

            normalized_api_name = self.API_NAME_MAP.get(api_name, api_name)

            if result and not result.get('error'):
                source_data = self._parse_api_result(normalized_api_name, result)
                if source_data:
                    sources.append(source_data)
                    source_names_seen.add(source_data['name'])
                else:
                    # Count clean/successful API checks as evidence sources too,
                    # so corroboration reflects multi-API verification instead of
                    # looking like a perpetual single-source result.
                    clean_source = {
                        'name': normalized_api_name,
                        'weight': self.SOURCE_WEIGHTS.get(normalized_api_name, 0.5),
                        'verdict': ThreatVerdict.CLEAN,
                        'confidence': 0.60,
                        'details': 'No threat indicators reported',
                        'timestamp': datetime.utcnow().isoformat(),
                        'raw_data': result
                    }
                    sources.append(clean_source)
                    source_names_seen.add(normalized_api_name)
        
        # Process threat indicators
        for indicator in threat_indicators:
            # Guard: skip anything that isn't a proper dict (e.g. stray strings/lists)
            if not isinstance(indicator, dict):
                logger.debug(f"Skipping non-dict indicator entry: {type(indicator).__name__}")
                continue

            source_name = indicator.get('source', 'Unknown')
            indicator_key = str(source_name).lower().replace(' ', '_').replace('.', '_')
            normalized_source_name = self.API_NAME_MAP.get(indicator_key, source_name)

            # Skip if already counted from API results
            if normalized_source_name in source_names_seen:
                continue

            source_data = {
                'name': normalized_source_name,
                'weight': self.SOURCE_WEIGHTS.get(normalized_source_name, 0.5),
                'verdict': self._severity_to_verdict(indicator.get('severity', 'low')),
                'confidence': indicator.get('confidence', 0.5),
                'details': indicator.get('indicator', ''),
                'timestamp': datetime.utcnow().isoformat(),
                'raw_data': indicator
            }
            sources.append(source_data)
            source_names_seen.add(normalized_source_name)

        return sources
    
    def _parse_api_result(self, api_name: str, result: Dict) -> Optional[Dict]:
        """Parse API-specific result format"""
        source_data = {
            'name': api_name,
            'weight': self.SOURCE_WEIGHTS.get(api_name, 0.5),
            'verdict': ThreatVerdict.CLEAN,
            'confidence': 0.0,
            'details': '',
            'timestamp': datetime.utcnow().isoformat(),
            'raw_data': result
        }
        
        try:
            if api_name == 'VirusTotal':
                if 'data' in result and 'attributes' in result['data']:
                    stats = result['data']['attributes'].get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    total = sum(stats.values())
                    
                    if malicious > 0:
                        source_data['verdict'] = ThreatVerdict.MALICIOUS
                        source_data['confidence'] = min(1.0, malicious / max(total, 1))
                        source_data['details'] = f"{malicious} vendors detected as malicious"
                        return source_data
                    elif suspicious > 0:
                        source_data['verdict'] = ThreatVerdict.SUSPICIOUS
                        source_data['confidence'] = min(1.0, suspicious / max(total, 1))
                        source_data['details'] = f"{suspicious} vendors detected as suspicious"
                        return source_data
            
            elif api_name == 'AbuseIPDB':
                if 'data' in result:
                    score = result['data'].get('abuseConfidenceScore', 0)
                    if score > 75:
                        source_data['verdict'] = ThreatVerdict.MALICIOUS
                        source_data['confidence'] = score / 100
                        source_data['details'] = f"Abuse score: {score}%"
                        return source_data
                    elif score > 25:
                        source_data['verdict'] = ThreatVerdict.SUSPICIOUS
                        source_data['confidence'] = score / 100
                        source_data['details'] = f"Abuse score: {score}%"
                        return source_data
            
            elif api_name == 'Shodan':
                # Shodan provides infrastructure data, not direct threat verdict
                # Mark as informational unless specific vulnerabilities found
                if 'vulns' in result and result['vulns']:
                    source_data['verdict'] = ThreatVerdict.SUSPICIOUS
                    source_data['confidence'] = 0.7
                    source_data['details'] = f"Vulnerabilities detected"
                    return source_data
            
            elif api_name == 'URLScan':
                if 'verdicts' in result:
                    verdicts = result['verdicts']
                    if verdicts.get('overall', {}).get('malicious', False):
                        source_data['verdict'] = ThreatVerdict.MALICIOUS
                        source_data['confidence'] = 0.85
                        source_data['details'] = "URLScan detected malicious content"
                        return source_data
            
            elif api_name == 'HybridAnalysis':
                if 'threat_score' in result:
                    score = result['threat_score']
                    if score >= 70:
                        source_data['verdict'] = ThreatVerdict.MALICIOUS
                        source_data['confidence'] = score / 100
                        source_data['details'] = f"Threat score: {score}"
                        return source_data
                    elif score >= 40:
                        source_data['verdict'] = ThreatVerdict.SUSPICIOUS
                        source_data['confidence'] = score / 100
                        source_data['details'] = f"Threat score: {score}"
                        return source_data
        
        except Exception as e:
            logger.error(f"Error parsing {api_name} result: {e}")
        
        return None
    
    def _severity_to_verdict(self, severity: str) -> ThreatVerdict:
        """Convert severity string to verdict"""
        severity = severity.lower()
        if severity in ['critical', 'high']:
            return ThreatVerdict.MALICIOUS
        elif severity == 'medium':
            return ThreatVerdict.SUSPICIOUS
        else:
            return ThreatVerdict.CLEAN
    
    def _calculate_corroboration(self, sources_data: List[Dict]) -> Dict:
        """Calculate corroboration metrics across sources"""
        source_count = len(sources_data)
        
        # Count verdicts
        verdict_counts = {
            ThreatVerdict.MALICIOUS: 0,
            ThreatVerdict.SUSPICIOUS: 0,
            ThreatVerdict.CLEAN: 0
        }
        
        weighted_score = 0.0
        total_weight = 0.0
        
        malicious_sources = []
        suspicious_sources = []
        
        for source in sources_data:
            verdict = source['verdict']
            weight = source['weight']
            confidence = source['confidence']
            
            verdict_counts[verdict] += 1
            
            # Calculate weighted threat score
            if verdict == ThreatVerdict.MALICIOUS:
                weighted_score += weight * confidence * 1.0
                malicious_sources.append(source['name'])
            elif verdict == ThreatVerdict.SUSPICIOUS:
                weighted_score += weight * confidence * 0.5
                suspicious_sources.append(source['name'])
            
            total_weight += weight
        
        # Normalize weighted score
        if total_weight > 0:
            weighted_score = weighted_score / total_weight
        
        # Determine corroboration level
        if source_count == 0:
            level = CorroborationLevel.NONE
        elif source_count == 1:
            level = CorroborationLevel.SINGLE
        elif source_count == 2:
            level = CorroborationLevel.LOW
        elif source_count == 3:
            level = CorroborationLevel.MEDIUM
        elif source_count >= 4:
            level = CorroborationLevel.HIGH
        
        # Check for unanimous agreement
        if source_count > 0:
            most_common_verdict = max(verdict_counts, key=verdict_counts.get)
            if verdict_counts[most_common_verdict] == source_count:
                level = CorroborationLevel.UNANIMOUS
        
        # Calculate agreement rate
        agreement_rate = 0.0
        if source_count > 0:
            max_count = max(verdict_counts.values())
            agreement_rate = max_count / source_count
        
        # Detect novel threats (heuristic-only or single-source with high confidence)
        novel_threat = False
        if source_count == 1:
            source = sources_data[0]
            if source['name'] in ['Heuristic Analysis', 'ML Model'] and source['confidence'] >= 0.8:
                novel_threat = True
        
        return {
            'level': level,
            'source_count': source_count,
            'sources': [s['name'] for s in sources_data],
            'malicious_sources': malicious_sources,
            'suspicious_sources': suspicious_sources,
            'verdict_distribution': {k.value: v for k, v in verdict_counts.items()},
            'weighted_score': weighted_score,
            'agreement_rate': agreement_rate,
            'novel_threat': novel_threat
        }
    
    def _determine_verdict(self, metrics: Dict, sources: List[Dict]) -> Dict:
        """Determine final verdict based on corroboration"""
        source_count = metrics['source_count']
        weighted_score = metrics['weighted_score']
        agreement_rate = metrics['agreement_rate']
        novel_threat = metrics['novel_threat']
        
        requires_manual_review = False
        
        # High corroboration (3+ sources)
        if source_count >= 3:
            if weighted_score >= 0.7:
                classification = ThreatVerdict.CRITICAL
                confidence = min(0.95, 0.7 + (source_count * 0.05) + (agreement_rate * 0.15))
                explanation = (
                    f"HIGH CONFIDENCE THREAT: {source_count} threat intelligence sources "
                    f"corroborate malicious activity (agreement: {agreement_rate:.0%})"
                )
                severity = "critical"
            elif weighted_score >= 0.4:
                classification = ThreatVerdict.MALICIOUS
                confidence = min(0.90, 0.6 + (source_count * 0.05) + (agreement_rate * 0.15))
                explanation = (
                    f"Malicious activity confirmed by {source_count} sources "
                    f"(agreement: {agreement_rate:.0%})"
                )
                severity = "high"
            elif weighted_score >= 0.2:
                classification = ThreatVerdict.SUSPICIOUS
                confidence = 0.6 + (agreement_rate * 0.2)
                explanation = (
                    f"Suspicious activity detected by multiple sources. "
                    f"Further investigation recommended."
                )
                severity = "medium"
                requires_manual_review = True
            else:
                classification = ThreatVerdict.CLEAN
                confidence = 0.7
                explanation = "Multiple sources indicate low threat level"
                severity = "low"
        
        # Medium corroboration (2 sources)
        elif source_count == 2:
            if weighted_score >= 0.6:
                classification = ThreatVerdict.MALICIOUS
                confidence = 0.75 + (agreement_rate * 0.15)
                explanation = (
                    f"Two independent sources confirm malicious activity "
                    f"(agreement: {agreement_rate:.0%})"
                )
                severity = "high"
            elif weighted_score >= 0.3:
                classification = ThreatVerdict.SUSPICIOUS
                confidence = 0.65
                explanation = "Two sources report suspicious indicators. Manual review recommended."
                severity = "medium"
                requires_manual_review = True
            else:
                classification = ThreatVerdict.SUSPICIOUS
                confidence = 0.55
                explanation = "Inconsistent signals from two sources. Further analysis needed."
                severity = "low"
                requires_manual_review = True
        
        # Single source (WARNING: High false positive risk)
        elif source_count == 1:
            source = sources[0]
            
            # Novel threat (zero-day candidate)
            if novel_threat:
                classification = ThreatVerdict.SUSPICIOUS
                confidence = min(0.70, source['confidence'])
                explanation = (
                    f"⚠️ SINGLE SOURCE DETECTION: Novel threat pattern detected by "
                    f"{source['name']}. Potential zero-day indicator requiring validation."
                )
                severity = "medium"
                requires_manual_review = True
                logger.warning(f"Novel threat candidate detected: {source['details']}")
            
            # High-reliability source
            elif source['weight'] >= 0.85 and source['confidence'] >= 0.8:
                classification = ThreatVerdict.SUSPICIOUS
                confidence = min(0.75, source['confidence'] * source['weight'])
                explanation = (
                    f"⚠️ SINGLE SOURCE DETECTION: {source['name']} reports {source['verdict'].value}. "
                    f"Awaiting corroboration from additional sources."
                )
                severity = "medium"
                requires_manual_review = True
            
            # Lower reliability or confidence
            else:
                classification = ThreatVerdict.SUSPICIOUS
                confidence = min(0.60, source['confidence'] * source['weight'])
                explanation = (
                    f"⚠️ UNVERIFIED: Single source ({source['name']}) detection. "
                    f"HIGH FALSE POSITIVE RISK. Multiple sources required for confirmation."
                )
                severity = "low"
                requires_manual_review = True
        
        # No sources
        else:
            classification = ThreatVerdict.CLEAN
            confidence = 0.5
            explanation = "No threat indicators detected"
            severity = "info"
        
        return {
            'classification': classification,
            'confidence': confidence,
            'severity': severity,
            'explanation': explanation,
            'requires_manual_review': requires_manual_review
        }
    
    def _generate_recommendations(self, verdict: Dict, metrics: Dict) -> List[str]:
        """Generate actionable recommendations based on verdict and corroboration"""
        recommendations = []
        
        classification = verdict['classification']
        confidence = verdict['confidence']
        source_count = metrics['source_count']
        
        # Incident response recommendations
        if source_count >= self.THRESHOLDS['incident_response']:
            recommendations.append("✅ TRIGGER INCIDENT RESPONSE: Multiple sources confirm threat")
            recommendations.append("Action: Isolate affected systems and begin forensic analysis")
        
        # Blocking recommendations
        if source_count >= self.THRESHOLDS['block'] and classification in [ThreatVerdict.MALICIOUS, ThreatVerdict.CRITICAL]:
            recommendations.append("✅ BLOCK IMMEDIATELY: High-confidence multi-source detection")
            recommendations.append("Action: Add to firewall blocklist and IDS signatures")
        
        # Quarantine recommendations
        elif source_count >= self.THRESHOLDS['quarantine']:
            recommendations.append("⚠️ QUARANTINE RECOMMENDED: Multiple sources indicate threat")
            recommendations.append("Action: Isolate for further analysis before blocking")
        
        # Single-source warnings
        elif source_count == 1:
            recommendations.append("⚠️ SINGLE SOURCE WARNING: High false positive risk")
            recommendations.append("Action: Queue for additional threat intelligence verification")
            recommendations.append("Action: Do NOT take automated blocking action")
            
            if metrics['novel_threat']:
                recommendations.append("🔬 NOVEL THREAT CANDIDATE: Potential zero-day indicator")
                recommendations.append("Action: Priority escalation for security analyst review")
                recommendations.append("Action: Consider sandboxed execution for behavioral analysis")
        
        # Monitoring recommendations
        if classification == ThreatVerdict.SUSPICIOUS:
            recommendations.append("📊 ENHANCED MONITORING: Enable detailed logging for this artifact")
            recommendations.append("Action: Track for repeated suspicious behavior patterns")
        
        # False positive mitigation
        if confidence < 0.70 and classification != ThreatVerdict.CLEAN:
            recommendations.append("🔍 MANUAL REVIEW REQUIRED: Confidence below threshold")
            recommendations.append("Action: Security analyst verification before action")
        
        # Clean verdict recommendations
        if classification == ThreatVerdict.CLEAN and source_count >= 2:
            recommendations.append("✅ VERIFIED CLEAN: Multiple sources confirm safety")
            recommendations.append("Action: Allow and whitelist if appropriate")
        
        return recommendations
    
    def _summarize_api_results(self, api_results: Dict) -> Dict:
        """Create summary of API results for reporting"""
        metadata_keys = {'apis_called', 'apis_attempted', 'apis_expected', 'api_status'}
        api_payload_items = [
            (api_name, result)
            for api_name, result in api_results.items()
            if api_name not in metadata_keys
        ]

        summary = {
            'total_apis_called': len(api_payload_items),
            'successful_responses': 0,
            'error_responses': 0,
            'apis_reporting_threats': []
        }
        
        for api_name, result in api_payload_items:
            if not isinstance(result, dict):
                continue

            if result.get('error'):
                summary['error_responses'] += 1
            else:
                summary['successful_responses'] += 1
                
                # Check if this API reported threats
                # (This is simplified; actual logic would be more detailed)
                if self._api_indicates_threat(api_name, result):
                    summary['apis_reporting_threats'].append(api_name)
        
        return summary
    
    def _api_indicates_threat(self, api_name: str, result: Dict) -> bool:
        """Check if API result indicates a threat"""
        try:
            if api_name == 'VirusTotal' and 'data' in result:
                stats = result['data'].get('attributes', {}).get('last_analysis_stats', {})
                return stats.get('malicious', 0) > 0 or stats.get('suspicious', 0) > 0
            
            elif api_name == 'AbuseIPDB' and 'data' in result:
                return result['data'].get('abuseConfidenceScore', 0) > 25
            
            # Add more API-specific checks as needed
            
        except:
            pass
        
        return False
    
    def _update_statistics(self, metrics: Dict):
        """Update engine statistics"""
        source_count = metrics['source_count']
        
        if source_count == 1:
            self.stats['single_source'] += 1
        elif source_count >= 2:
            self.stats['multi_source'] += 1
            if source_count >= self.THRESHOLDS['incident_response']:
                self.stats['corroborated'] += 1
        
        if metrics['novel_threat']:
            self.stats['novel_threats'] += 1
    
    def get_statistics(self) -> Dict:
        """Get engine statistics"""
        total = self.stats['total_analyses']
        if total > 0:
            single_source_pct = (self.stats['single_source'] / total) * 100
            multi_source_pct = (self.stats['multi_source'] / total) * 100
            corroboration_pct = (self.stats['corroborated'] / total) * 100
        else:
            single_source_pct = multi_source_pct = corroboration_pct = 0
        
        return {
            **self.stats,
            'single_source_percentage': round(single_source_pct, 1),
            'multi_source_percentage': round(multi_source_pct, 1),
            'corroboration_percentage': round(corroboration_pct, 1)
        }


# Global instance
corroboration_engine = CorroborationEngine()
