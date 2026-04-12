"""
Advanced AI Threat Prediction & Multi-API Integration Engine
Combines all 5 threat intelligence APIs with Gemini AI for predictive analysis
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
import aiohttp
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ....database import get_db
from ....models import ScanHistory, AttackEvent, ThreatSeverity
from ....gemini_integration import get_gemini_client

logger = logging.getLogger(__name__)
router = APIRouter()


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ThreatPredictionRequest(BaseModel):
    """Request for AI threat prediction"""
    target: str
    target_type: str  # ip, url, domain, file, hash
    context: Optional[Dict] = None


class AttackPatternAnalysisRequest(BaseModel):
    """Request for attack pattern analysis"""
    time_window: int = 24  # hours
    min_severity: str = "medium"


class PredictiveDefenseRequest(BaseModel):
    """Request for predictive defense recommendations"""
    client_id: str
    recent_threats: List[Dict]


class AIThreatEngine:
    """Advanced AI-powered threat analysis engine"""
    
    def __init__(self):
        self.api_configs = {
            "virustotal": {"weight": 0.30, "priority": 1},
            "abuseipdb": {"weight": 0.25, "priority": 2},
            "shodan": {"weight": 0.20, "priority": 3},
            "urlscan": {"weight": 0.15, "priority": 4},
            "hybrid_analysis": {"weight": 0.10, "priority": 5}
        }
        # Simplified api_weights for compatibility
        self.api_weights = {k: v["weight"] for k, v in self.api_configs.items()}

    @staticmethod
    def _deterministic_prediction(target_info: Dict, historical_data: List[Dict], note: Optional[str] = None) -> Dict:
        """Build a stable fallback prediction when AI output is unavailable or malformed."""
        history = list(historical_data or [])
        recent = history[-20:]
        if recent:
            confidences = [float(item.get("confidence") or 0.0) for item in recent]
            avg_conf = sum(confidences) / max(1, len(confidences))
            suspicious_events = sum(
                1
                for item in recent
                if str(item.get("threat_level") or "").strip().lower() in {"suspicious", "malicious", "high", "critical"}
            )
            attack_likelihood = int(min(95, max(5, round((avg_conf * 55) + (suspicious_events * 6)))))
        else:
            attack_likelihood = 35

        if attack_likelihood >= 75:
            timeline = "immediate"
        elif attack_likelihood >= 45:
            timeline = "short-term"
        else:
            timeline = "long-term"

        target_type = str(target_info.get("target_type") or "").lower()
        predicted_types = {
            "ip": ["DDoS", "Reconnaissance"],
            "domain": ["Phishing", "DNS Abuse"],
            "url": ["Phishing", "Malware Delivery"],
            "file": ["Malware", "Ransomware"],
            "hash": ["Malware"],
        }.get(target_type, ["Unknown"])

        reasoning = "Deterministic fallback based on recent local threat history"
        if note:
            reasoning = f"{reasoning}. AI unavailable: {note}"

        return {
            "attack_likelihood": attack_likelihood,
            "predicted_attack_types": predicted_types,
            "recommended_actions": [
                "Maintain enhanced monitoring for this target",
                "Correlate with IDS/HIDS alerts for the next 24 hours",
                "Escalate to manual review if confidence or severity increases",
            ],
            "risk_timeline": timeline,
            "confidence": 0.55,
            "reasoning": reasoning,
            "fallback": True,
        }

    @staticmethod
    def _parse_ai_json_response(ai_response) -> Dict:
        """Parse Gemini response that may be dict, JSON string, or markdown-wrapped JSON."""
        if isinstance(ai_response, dict):
            return ai_response

        if not isinstance(ai_response, str):
            raise ValueError("Unsupported AI response type")

        text = ai_response.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
            text = re.sub(r"\s*```$", "", text).strip()

        return json.loads(text)
    
    async def multi_api_threat_analysis(self, scan_results: Dict) -> Dict:
        """Analyze threat using weighted multi-API approach"""
        try:
            threat_scores = {}
            api_results = {}
            
            # Extract results from each API
            for api_name in self.api_configs.keys():
                if api_name in scan_results:
                    api_data = scan_results[api_name]
                    score = self._calculate_api_threat_score(api_name, api_data)
                    threat_scores[api_name] = score
                    api_results[api_name] = api_data
            
            # Calculate weighted average threat score
            total_score = 0
            total_weight = 0
            
            for api_name, score in threat_scores.items():
                weight = self.api_configs[api_name]["weight"]
                total_score += score * weight
                total_weight += weight
            
            if total_weight > 0:
                final_score = total_score / total_weight
            else:
                final_score = 0
            
            # Determine threat level
            if final_score >= 0.8:
                threat_level = "malicious"
                severity = ThreatSeverity.CRITICAL
            elif final_score >= 0.6:
                threat_level = "malicious"
                severity = ThreatSeverity.HIGH
            elif final_score >= 0.4:
                threat_level = "suspicious"
                severity = ThreatSeverity.MEDIUM
            elif final_score >= 0.2:
                threat_level = "suspicious"
                severity = ThreatSeverity.LOW
            else:
                threat_level = "safe"
                severity = ThreatSeverity.LOW
            
            return {
                "final_score": final_score,
                "threat_level": threat_level,
                "severity": severity.value,
                "api_scores": threat_scores,
                "api_results": api_results,
                "confidence": self._calculate_confidence(threat_scores)
            }
            
        except Exception as e:
            logger.error(f"Multi-API analysis error: {e}")
            return {
                "final_score": 0,
                "threat_level": "unknown",
                "severity": "low",
                "error": str(e)
            }
    
    def _calculate_api_threat_score(self, api_name: str, api_data: Dict) -> float:
        """Calculate threat score from individual API response"""
        try:
            if api_name == "virustotal":
                # VirusTotal analysis
                if "positives" in api_data and "total" in api_data:
                    total = api_data["total"]
                    positives = api_data["positives"]
                    return min(positives / max(total, 1), 1.0) if total > 0 else 0
            
            elif api_name == "abuseipdb":
                # AbuseIPDB analysis
                if "abuseConfidenceScore" in api_data:
                    return api_data["abuseConfidenceScore"] / 100
            
            elif api_name == "shodan":
                # Shodan analysis - based on vulnerabilities
                if "vulns" in api_data:
                    vuln_count = len(api_data.get("vulns", []))
                    return min(vuln_count / 10, 1.0)  # 10+ vulns = max score
            
            elif api_name == "urlscan":
                # URLScan analysis
                if "verdicts" in api_data:
                    malicious = api_data["verdicts"].get("malicious", 0)
                    suspicious = api_data["verdicts"].get("suspicious", 0)
                    return min((malicious * 1.0 + suspicious * 0.5) / 5, 1.0)
            
            elif api_name == "hybrid_analysis":
                # Hybrid Analysis
                if "threat_score" in api_data:
                    return api_data["threat_score"] / 100
            
            return 0
            
        except Exception as e:
            logger.error(f"Error calculating score for {api_name}: {e}")
            return 0
    
    def _calculate_confidence(self, threat_scores: Dict) -> float:
        """Calculate confidence based on API agreement"""
        if not threat_scores:
            return 0
        
        # Check how many APIs agree
        scores = list(threat_scores.values())
        avg_score = sum(scores) / len(scores)
        
        # Calculate standard deviation
        variance = sum((x - avg_score) ** 2 for x in scores) / len(scores)
        std_dev = variance ** 0.5
        
        # Lower deviation = higher confidence
        confidence = max(0, 1 - (std_dev * 2))
        return confidence
    
    async def predict_attack_likelihood(self, target_info: Dict, historical_data: List[Dict]) -> Dict:
        """Predict likelihood of attack using AI and historical patterns"""
        try:
            # Prepare context for Gemini AI
            context = {
                "target": target_info,
                "historical_threats": historical_data[-50:],  # Last 50 threats
                "current_time": utcnow().isoformat()
            }
            
            prompt = f"""
You are an advanced cybersecurity AI analyzing threat intelligence data.

Target Information:
- Target: {target_info.get('target')}
- Type: {target_info.get('target_type')}
- Previous Threat Level: {target_info.get('threat_level', 'unknown')}

Historical Attack Data:
{json.dumps(historical_data[-10:], indent=2)}

Analyze and predict:
1. Likelihood of this target being involved in an attack (0-100%)
2. Predicted attack types (DDoS, malware, phishing, etc.)
3. Recommended defense actions
4. Risk timeline (immediate, short-term, long-term)
5. Confidence level in predictions

Provide analysis in JSON format with these exact keys:
{{
    "attack_likelihood": <0-100>,
    "predicted_attack_types": [<list of attack types>],
    "recommended_actions": [<list of actions>],
    "risk_timeline": "<immediate|short-term|long-term>",
    "confidence": <0-1>,
    "reasoning": "<brief explanation>"
}}
            """
            
            # Get AI prediction
            gemini = get_gemini_client()
            ai_response = await gemini.analyze_with_gemini(prompt, context)
            
            # Parse AI response
            try:
                prediction = self._parse_ai_json_response(ai_response)
            except:
                # Fallback parsing
                prediction = {
                    "attack_likelihood": 50,
                    "predicted_attack_types": ["unknown"],
                    "recommended_actions": ["Monitor closely"],
                    "risk_timeline": "short-term",
                    "confidence": 0.5,
                    "reasoning": str(ai_response)[:500]
                }

            if not isinstance(prediction, dict):
                return self._deterministic_prediction(target_info, historical_data, note="non-dict AI response")

            required_keys = {
                "attack_likelihood",
                "predicted_attack_types",
                "recommended_actions",
                "risk_timeline",
                "confidence",
                "reasoning",
            }
            if not required_keys.issubset(set(prediction.keys())):
                note = prediction.get("error") if isinstance(prediction, dict) else "missing required keys"
                return self._deterministic_prediction(target_info, historical_data, note=str(note or "missing required keys"))
            
            return prediction
            
        except Exception as e:
            logger.error(f"Attack prediction error: {e}")
            return self._deterministic_prediction(target_info, historical_data, note=str(e))
    
    async def generate_defense_strategy(self, threat_analysis: Dict, client_context: Dict) -> Dict:
        """Generate intelligent defense strategy using AI"""
        try:
            prompt = f"""
You are an expert cybersecurity defense strategist.

Current Threat Analysis:
{json.dumps(threat_analysis, indent=2)}

Client Context:
{json.dumps(client_context, indent=2)}

Generate a comprehensive defense strategy including:
1. Immediate actions (block, quarantine, alert)
2. Preventive measures
3. Monitoring recommendations
4. Estimated effectiveness of each action
5. Priority order

Response in JSON format:
{{
    "immediate_actions": [
        {{"action": "<action_type>", "target": "<target>", "priority": <1-5>, "effectiveness": <0-100>}}
    ],
    "preventive_measures": [<list of measures>],
    "monitoring_recommendations": [<list of recommendations>],
    "estimated_risk_reduction": <0-100>,
    "implementation_notes": "<notes>"
}}
            """
            
            gemini = get_gemini_client()
            ai_response = await gemini.analyze_with_gemini(prompt, threat_analysis)
            
            try:
                strategy = self._parse_ai_json_response(ai_response)
            except:
                # Fallback strategy
                strategy = {
                    "immediate_actions": [
                        {
                            "action": "block_ip" if threat_analysis.get("target_type") == "ip" else "monitor",
                            "target": threat_analysis.get("target"),
                            "priority": 3,
                            "effectiveness": 70
                        }
                    ],
                    "preventive_measures": ["Enable firewall", "Update security rules"],
                    "monitoring_recommendations": ["Monitor for 24 hours"],
                    "estimated_risk_reduction": 60,
                    "implementation_notes": str(ai_response)[:500]
                }
            
            return strategy
            
        except Exception as e:
            logger.error(f"Defense strategy generation error: {e}")
            return {
                "immediate_actions": [],
                "preventive_measures": [],
                "monitoring_recommendations": ["Manual review required"],
                "estimated_risk_reduction": 0,
                "implementation_notes": f"Error: {str(e)}"
            }


# Global AI engine instance
ai_engine = AIThreatEngine()


@router.post("/ai/predict-threat")
async def predict_threat(request: ThreatPredictionRequest, db: AsyncSession = Depends(get_db)):
    """
    AI-powered threat prediction combining all 5 APIs + Gemini AI
    """
    try:
        logger.info(f"AI threat prediction for: {request.target}")
        
        # Get historical data for this target type
        query = select(ScanHistory).where(
            ScanHistory.target_type == request.target_type
        ).order_by(ScanHistory.scan_timestamp.desc()).limit(50)
        
        result = await db.execute(query)
        historical_scans = result.scalars().all()
        
        historical_data = [
            {
                "target": scan.target,
                "threat_level": scan.threat_level,
                "confidence": scan.confidence,
                "threats_detected": scan.threats_detected,
                "timestamp": scan.scan_timestamp.isoformat() if scan.scan_timestamp else None
            }
            for scan in historical_scans
        ]
        
        # Perform AI prediction
        target_info = {
            "target": request.target,
            "target_type": request.target_type,
            "context": request.context or {}
        }
        
        prediction = await ai_engine.predict_attack_likelihood(target_info, historical_data)
        
        # Generate defense strategy if high risk
        strategy = None
        if prediction.get("attack_likelihood", 0) > 50:
            strategy = await ai_engine.generate_defense_strategy(
                prediction,
                {"target": request.target, "type": request.target_type}
            )
        
        return {
            "target": request.target,
            "prediction": prediction,
            "defense_strategy": strategy,
            "analysis_timestamp": utcnow().isoformat(),
            "historical_samples": len(historical_data)
        }
        
    except Exception as e:
        logger.error(f"Threat prediction failed: {e}")
        raise HTTPException(status_code=500, detail="Threat prediction failed")


@router.post("/ai/analyze-attack-patterns")
async def analyze_attack_patterns(request: AttackPatternAnalysisRequest, db: AsyncSession = Depends(get_db)):
    """
    Analyze attack patterns across the network using AI
    """
    try:
        since_time = utcnow() - timedelta(hours=request.time_window)
        
        # Get recent attacks
        query = select(AttackEvent).where(
            AttackEvent.detected_at >= since_time
        ).order_by(AttackEvent.detected_at.desc())
        
        result = await db.execute(query)
        attacks = result.scalars().all()
        
        if not attacks:
            return {
                "patterns_found": [],
                "message": "No attacks detected in the specified time window"
            }
        
        # Prepare data for AI analysis
        attack_data = [
            {
                "attack_type": attack.attack_type,
                "source_ip": attack.source_ip,
                "severity": attack.severity.value if attack.severity else "unknown",
                "timestamp": attack.detected_at.isoformat() if attack.detected_at else None
            }
            for attack in attacks
        ]
        
        prompt = f"""
Analyze these cybersecurity attacks and identify patterns:

Attacks Data:
{json.dumps(attack_data, indent=2)}

Identify:
1. Common attack patterns
2. Potential coordinated attacks
3. High-risk IP addresses or sources
4. Attack trends over time
5. Recommended defensive posture

Response in JSON format:
{{
    "patterns": [
        {{"pattern_type": "<type>", "frequency": <count>, "severity": "<level>"}}
    ],
    "coordinated_attacks": [<list if any>],
    "high_risk_sources": [<list of IPs/sources>],
    "trends": "<description>",
    "defensive_recommendations": [<list>]
}}
        """
        
        gemini = get_gemini_client()
        ai_analysis = await gemini.analyze_with_gemini(prompt, {"attacks": attack_data})
        
        try:
            analysis = json.loads(ai_analysis)
        except:
            analysis = {"raw_analysis": ai_analysis}
        
        return {
            "time_window_hours": request.time_window,
            "attacks_analyzed": len(attacks),
            "analysis": analysis,
            "timestamp": utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Attack pattern analysis failed: {e}")
        raise HTTPException(status_code=500, detail="Attack pattern analysis failed")


@router.post("/ai/defensive-recommendations")
async def get_defensive_recommendations(request: PredictiveDefenseRequest):
    """
    Get AI-powered defensive recommendations for a client
    """
    try:
        prompt = f"""
As a cybersecurity expert, analyze these recent threats and provide comprehensive defensive recommendations:

Client ID: {request.client_id}

Recent Threats:
{json.dumps(request.recent_threats, indent=2)}

Provide:
1. Immediate defensive actions needed
2. Long-term security improvements
3. Vulnerabilities to address
4. Monitoring priorities
5. Incident response plan updates

Response in JSON format with actionable recommendations.
        """
        
        gemini = get_gemini_client()
        ai_response = await gemini.analyze_with_gemini(prompt, {"client_id": request.client_id})
        
        return {
            "client_id": request.client_id,
            "recommendations": ai_response,
            "generated_at": utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Defensive recommendations failed: {e}")
        raise HTTPException(status_code=500, detail="Defensive recommendations failed")
