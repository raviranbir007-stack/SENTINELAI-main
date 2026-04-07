"""
Activity Analysis API Endpoints
Provides AI-powered analysis of websites, IPs, and files using Gemini AI
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Dict, List, Optional
import logging

from .auth import get_current_user

try:
    from server.app.gemini_integration import get_gemini_client
except ImportError:
    from app.gemini_integration import get_gemini_client

logger = logging.getLogger(__name__)

router = APIRouter()


class URLAnalysisRequest(BaseModel):
    url: str
    domain: str
    api_results: Dict


class IPAnalysisRequest(BaseModel):
    ip_address: str
    api_results: Dict


class FileAnalysisRequest(BaseModel):
    file_path: str
    file_hash: str
    api_results: Dict


@router.post("/url-safety")
async def analyze_url_safety(
    request: URLAnalysisRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Analyze URL safety using Gemini AI
    """
    try:
        logger.info(f"Received URL safety analysis request: {request.url} / {request.domain}")
        gemini = get_gemini_client()

        # Check if Gemini is available
        avail = gemini.check_availability()
        if not avail.get('available'):
            logger.info("Gemini not available, using fallback URL analysis")
            return _fallback_url_analysis(request)
        
        # Create analysis prompt
        prompt = f"""
Analyze the following website for security threats:

URL: {request.url}
Domain: {request.domain}

Threat Intelligence Results:
{_format_api_results(request.api_results)}

Provide a comprehensive security analysis including:
1. Risk level (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
2. Identified threats
3. Specific security recommendations
4. Whether to block access

Format your response as JSON with keys: risk_level, threats, recommendations
"""
        # use the async wrapper which also handles quota/availability
        gemini_result = await gemini.analyze_with_gemini(prompt)
        if not gemini_result.get('success') or not gemini_result.get('response'):
            logger.warning("Gemini returned no usable response for URL, falling back")
            return _fallback_url_analysis(request)

        response_text = gemini_result['response']
        # extract json
        import json, re
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            analysis = json.loads(json_match.group())
            return {
                'risk_level': analysis.get('risk_level', 'UNKNOWN'),
                'threats': analysis.get('threats', []),
                'recommendations': analysis.get('recommendations', []),
                'should_block': analysis.get('risk_level', 'UNKNOWN') in ['HIGH', 'CRITICAL'],
                'analysis_source': 'gemini_ai'
            }
        else:
            logger.warning("Unable to parse JSON from Gemini URL analysis, using fallback")
            return _fallback_url_analysis(request)


        
    except Exception as e:
        logger.error(f"URL analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="URL safety analysis failed"
        )


@router.post("/ip-reputation")
async def analyze_ip_reputation(
    request: IPAnalysisRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Analyze IP reputation using Gemini AI
    """
    try:
        logger.info(f"Received IP reputation analysis request for {request.ip_address}")
        gemini = get_gemini_client()
        if not gemini.check_availability().get('available'):
            logger.info("Gemini not available, using fallback IP analysis")
            return _fallback_ip_analysis(request)
        
        prompt = f"""
Analyze the following IP address for security threats:

IP Address: {request.ip_address}

Threat Intelligence Results:
{_format_api_results(request.api_results)}

Provide a comprehensive security analysis including:
1. Risk level (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
2. Identified threats
3. Specific security recommendations
4. Whether to block this IP

Format your response as JSON with keys: risk_level, threats, recommendations
"""

        # perform GEMINI analysis and parse results
        gemini_result = await gemini.analyze_with_gemini(prompt)
        if not gemini_result.get('success') or not gemini_result.get('response'):
            logger.warning("Gemini returned no usable response for IP, falling back")
            return _fallback_ip_analysis(request)

        response_text = gemini_result['response']
        import json, re
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            analysis = json.loads(json_match.group())
            return {
                'risk_level': analysis.get('risk_level', 'UNKNOWN'),
                'threats': analysis.get('threats', []),
                'recommendations': analysis.get('recommendations', []),
                'should_block': analysis.get('risk_level', 'UNKNOWN') in ['HIGH', 'CRITICAL'],
                'analysis_source': 'gemini_ai'
            }
        else:
            logger.warning("Unable to parse JSON from Gemini IP analysis, using fallback")
            return _fallback_ip_analysis(request)

    # catch any unexpected errors during IP analysis
    except Exception as e:
        logger.error(f"IP analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="IP reputation analysis failed"
        )


@router.post("/file-safety")
async def analyze_file_safety(
    request: FileAnalysisRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Analyze file safety using Gemini AI
    """
    try:
        logger.info(f"Received file safety analysis request for {request.file_path} hash {request.file_hash}")
        gemini = get_gemini_client()
        if not gemini.check_availability().get('available'):
            logger.info("Gemini not available, using fallback file analysis")
            return _fallback_file_analysis(request)
        
        prompt = f"""
Analyze the following file for malware and security threats:

File Path: {request.file_path}
File Hash (SHA256): {request.file_hash}

Threat Intelligence Results:
{_format_api_results(request.api_results)}

Provide a comprehensive security analysis including:
1. Risk level (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
2. Identified threats and malware families
3. Specific security recommendations
4. Whether to quarantine this file

Format your response as JSON with keys: risk_level, threats, recommendations, malware_family
"""
        
        gemini_result = await gemini.analyze_with_gemini(prompt)
        if not gemini_result.get('success') or not gemini_result.get('response'):
            logger.warning("Gemini returned no usable response for file, falling back")
            return _fallback_file_analysis(request)

        response_text = gemini_result['response']
        import json, re
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            analysis = json.loads(json_match.group())
            return {
                'risk_level': analysis.get('risk_level', 'UNKNOWN'),
                'threats': analysis.get('threats', []),
                'recommendations': analysis.get('recommendations', []),
                'malware_family': analysis.get('malware_family', 'None'),
                'should_quarantine': analysis.get('risk_level', 'UNKNOWN') in ['HIGH', 'CRITICAL'],
                'analysis_source': 'gemini_ai'
            }
        else:
            logger.warning("Unable to parse JSON from Gemini file analysis, using fallback")
            return _fallback_file_analysis(request)
        
    except Exception as e:
        logger.error(f"File analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="File safety analysis failed"
        )


def _format_api_results(api_results: Dict) -> str:
    """Format API results for Gemini prompt"""
    formatted = []
    
    for api_name, results in api_results.items():
        if isinstance(results, dict) and 'error' not in results:
            formatted.append(f"\n{api_name.upper()}:")
            for key, value in results.items():
                formatted.append(f"  - {key}: {value}")
    
    return '\n'.join(formatted) if formatted else "No API results available"


def _fallback_url_analysis(request: URLAnalysisRequest) -> Dict:
    """Fallback rule-based URL analysis"""
    risk_score = 0
    threats = []
    
    # Analyze API results
    if 'virustotal' in request.api_results:
        vt = request.api_results['virustotal']
        if isinstance(vt, dict) and 'malicious' in vt:
            malicious_count = vt['malicious']
            if malicious_count > 0:
                risk_score += 50
                threats.append(f"VirusTotal: {malicious_count} engines detected malicious content")
    
    if 'abuseipdb' in request.api_results:
        abuse = request.api_results['abuseipdb']
        if isinstance(abuse, dict) and 'abuse_confidence_score' in abuse:
            score = abuse['abuse_confidence_score']
            if score > 50:
                risk_score += 40
                threats.append(f"AbuseIPDB: High abuse score ({score})")
    
    # Determine risk level
    if risk_score >= 80:
        risk_level = 'CRITICAL'
    elif risk_score >= 60:
        risk_level = 'HIGH'
    elif risk_score >= 40:
        risk_level = 'MEDIUM'
    elif risk_score >= 20:
        risk_level = 'LOW'
    else:
        risk_level = 'SAFE'
    
    recommendations = _generate_recommendations(risk_level)
    
    return {
        'risk_level': risk_level,
        'threats': threats,
        'recommendations': recommendations,
        'should_block': risk_level in ['HIGH', 'CRITICAL'],
        'analysis_source': 'rule_based'
    }


def _fallback_ip_analysis(request: IPAnalysisRequest) -> Dict:
    """Fallback rule-based IP analysis"""
    risk_score = 0
    threats = []
    
    if 'abuseipdb' in request.api_results:
        abuse = request.api_results['abuseipdb']
        if isinstance(abuse, dict) and 'abuse_confidence_score' in abuse:
            score = abuse['abuse_confidence_score']
            if score > 50:
                risk_score += 60
                threats.append(f"AbuseIPDB: High abuse score ({score})")
    
    if 'virustotal' in request.api_results:
        vt = request.api_results['virustotal']
        if isinstance(vt, dict) and 'malicious' in vt:
            if vt['malicious'] > 0:
                risk_score += 40
                threats.append("VirusTotal: Malicious activity detected")
    
    # Determine risk level
    if risk_score >= 80:
        risk_level = 'CRITICAL'
    elif risk_score >= 60:
        risk_level = 'HIGH'
    elif risk_score >= 40:
        risk_level = 'MEDIUM'
    elif risk_score >= 20:
        risk_level = 'LOW'
    else:
        risk_level = 'SAFE'
    
    recommendations = _generate_recommendations(risk_level)
    
    return {
        'risk_level': risk_level,
        'threats': threats,
        'recommendations': recommendations,
        'should_block': risk_level in ['HIGH', 'CRITICAL'],
        'analysis_source': 'rule_based'
    }


def _fallback_file_analysis(request: FileAnalysisRequest) -> Dict:
    """Fallback rule-based file analysis"""
    risk_score = 0
    threats = []
    
    if 'virustotal' in request.api_results:
        vt = request.api_results['virustotal']
        if isinstance(vt, dict) and 'malicious' in vt:
            malicious_count = vt['malicious']
            if malicious_count > 0:
                risk_score += 80
                threats.append(f"VirusTotal: {malicious_count} engines detected malware")
    
    if 'hybrid_analysis' in request.api_results:
        ha = request.api_results['hybrid_analysis']
        if isinstance(ha, dict) and 'threat_score' in ha:
            threat_score = ha['threat_score']
            if threat_score > 50:
                risk_score += 60
                threats.append(f"Hybrid Analysis: High threat score ({threat_score})")
    
    # Determine risk level
    if risk_score >= 80:
        risk_level = 'CRITICAL'
    elif risk_score >= 60:
        risk_level = 'HIGH'
    elif risk_score >= 40:
        risk_level = 'MEDIUM'
    elif risk_score >= 20:
        risk_level = 'LOW'
    else:
        risk_level = 'SAFE'
    
    recommendations = _generate_recommendations(risk_level)
    
    return {
        'risk_level': risk_level,
        'threats': threats,
        'recommendations': recommendations,
        'should_quarantine': risk_level in ['HIGH', 'CRITICAL'],
        'analysis_source': 'rule_based'
    }


def _generate_recommendations(risk_level: str) -> List[str]:
    """Generate security recommendations"""
    recommendations = []
    
    if risk_level in ['CRITICAL', 'HIGH']:
        recommendations.append("🚫 BLOCK this resource immediately")
        recommendations.append("🔍 Run full system scan for potential compromise")
        recommendations.append("🔒 Change passwords if credentials were entered")
    elif risk_level == 'MEDIUM':
        recommendations.append("⚠️  Exercise extreme caution")
        recommendations.append("🛡️  Do not enter sensitive information")
        recommendations.append("📊 Monitor system for unusual activity")
    elif risk_level == 'LOW':
        recommendations.append("⚡ Proceed with caution")
        recommendations.append("🔍 Verify authenticity before proceeding")
    else:
        recommendations.append("✅ No immediate threats detected")
        recommendations.append("🛡️  Continue following security best practices")
    
    return recommendations
