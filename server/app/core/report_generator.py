"""
PDF Report Generator using Gemini API
Generates AI-analyzed threat reports in PDF format
"""

import asyncio
import logging
import os
from datetime import datetime
from typing import Any, Dict, Optional
import time

try:
    import google.genai as genai
    from google.genai.types import GenerateContentConfig

    GEMINI_AVAILABLE = True
except ImportError:
    try:
        import google.generativeai as genai

        GEMINI_AVAILABLE = True
    except ImportError:
        GEMINI_AVAILABLE = False

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


logger = logging.getLogger(__name__)

if GEMINI_AVAILABLE is False:
    logger.warning(
        "google.genai or google-generativeai not installed. Install with: pip install google-genai or pip install google-generativeai"
    )
if REPORTLAB_AVAILABLE is False:
    logger.warning("reportlab not installed. Install with: pip install reportlab")


class ReportGenerator:
    """Generate AI-analyzed threat reports in PDF format"""

    def __init__(self):
        self.gemini_key = os.getenv("GEMINI_API_KEY", "")
        self.initialized = False
        # Circuit-breaker & retry configuration (env-configurable)
        # Reduced to 1 attempt to save quota - each retry wastes requests
        try:
            self.gemini_max_attempts = int(os.getenv("GEMINI_MAX_ATTEMPTS", "1"))
        except Exception:
            self.gemini_max_attempts = 1
        try:
            self.circuit_threshold = int(os.getenv("GEMINI_CIRCUIT_THRESHOLD", "5"))
        except Exception:
            self.circuit_threshold = 5
        try:
            self.circuit_open_seconds = int(os.getenv("GEMINI_CIRCUIT_OPEN_SECONDS", "60"))
        except Exception:
            self.circuit_open_seconds = 60

        self._failure_count = 0
        self._circuit_open_until = 0
        
        # Rate limiter: track last request time (min 4 seconds between requests for 15 RPM)
        self._last_request_time = 0
        self._min_request_interval = 4.0  # seconds between requests

        if GEMINI_AVAILABLE and self.gemini_key:
            try:
                # Prefer older `configure` call when available (legacy package)
                if hasattr(genai, "configure"):
                    genai.configure(api_key=self.gemini_key)
                    self.initialized = True
                    logger.info("Gemini API initialized successfully (legacy client)")
                # Newer `google.genai` provides a `client.Client` class
                elif hasattr(genai, "client") and hasattr(genai.client, "Client"):
                    # We don't need to call configure; client will accept api_key at call time
                    self.initialized = True
                    logger.info("Gemini API available via google.genai client")
                else:
                    logger.warning("Gemini client present but no supported initializer found")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini: {str(e)}")

    async def generate_analysis_report(
        self, threat_analysis: Dict[str, Any], output_filename: Optional[str] = None
    ) -> Optional[bytes]:
        """
        Generate comprehensive AI-analyzed threat report

        Args:
            threat_analysis: Output from ThreatAnalyzer
            output_filename: Optional filename for the PDF

        Returns:
            PDF file bytes or None if generation fails
        """

        if not REPORTLAB_AVAILABLE:
            logger.warning("reportlab not installed. Returning text fallback instead of PDF.")
            # Generate AI analysis and return as UTF-8 bytes so callers receive a report
            ai_analysis = await self._generate_ai_analysis(threat_analysis)
            return ai_analysis.encode("utf-8")

        try:
            # Generate AI analysis using Gemini
            ai_analysis = await self._generate_ai_analysis(threat_analysis)

            # Create PDF
            pdf_bytes = self._create_pdf_report(threat_analysis, ai_analysis)

            return pdf_bytes

        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            return None

    async def _generate_ai_analysis(self, threat_data: Dict[str, Any]) -> str:
        """Generate AI analysis using Gemini API"""
        # Check daily limit (50 reports per day - conservative limit for free tier)
        if not hasattr(self, '_daily_reports'):
            self._daily_reports = []
            self._last_reset = datetime.now().date()
        
        # Reset counter if new day
        if datetime.now().date() > self._last_reset:
            self._daily_reports = []
            self._last_reset = datetime.now().date()
        
        # Check if we hit daily limit
        if len(self._daily_reports) >= 50:
            logger.warning("Daily Gemini report limit (50) reached. Using local fallback.")
            return self._get_fallback_analysis(threat_data)
        
        if not self.initialized or not GEMINI_AVAILABLE:
            return self._get_fallback_analysis(threat_data)
        
        # Prepare simplified prompt for Gemini (reduce tokens)
        prompt = self._prepare_analysis_prompt(threat_data)

        # Unified call with retry/backoff for modern and legacy clients
        async def _call_genai_with_retry(p: str, max_attempts: int = self.gemini_max_attempts) -> Optional[str]:
            # Rate limiter: ensure minimum interval between requests
            time_since_last = time.time() - self._last_request_time
            if time_since_last < self._min_request_interval:
                wait_time = self._min_request_interval - time_since_last
                logger.info(f"Rate limiting: waiting {wait_time:.1f}s before next Gemini request")
                await asyncio.sleep(wait_time)
            
            self._last_request_time = time.time()
            
            # Circuit open check
            if time.time() < self._circuit_open_until:
                logger.warning("Gemini circuit open until %s, skipping remote call", self._circuit_open_until)
                return None

            for attempt in range(1, max_attempts + 1):
                # Try modern google.genai client first
                if hasattr(genai, "client") and hasattr(genai.client, "Client"):
                    try:
                        client = genai.client.Client(api_key=self.gemini_key)

                        # Use gemini-2.5-flash which is available and has good quotas
                        model_name = "gemini-2.5-flash"
                        
                        # Try to get first available model from API
                        try:
                            models_list = client.models.list()
                            if getattr(models_list, "models", None) and len(models_list.models) > 0:
                                m = models_list.models[0]
                                # Get model name and strip "models/" prefix if present
                                name = getattr(m, "name", None) or getattr(m, "id", None)
                                if name:
                                    # Remove "models/" prefix if present for v1beta API
                                    if name.startswith("models/"):
                                        model_name = name  # Use full name for newer API
                                    else:
                                        model_name = name
                        except Exception as e:
                            logger.debug(f"Could not list models, using default: {e}")

                        response = client.models.generate_content(
                            model=model_name, 
                            contents=p, 
                            config=GenerateContentConfig(
                                temperature=0.7,
                                top_p=0.9,
                                max_output_tokens=2048
                            )
                        )
                        text = self._extract_text_from_genai_response(response)
                        if text:
                            # success -> reset failures and track daily usage
                            self._failure_count = 0
                            self._daily_reports.append(datetime.now())
                            return text
                        # fallback to stringified response
                        self._failure_count = 0
                        return str(response)

                    except Exception as e:
                        msg = str(e)
                        logger.debug("google.genai attempt %d failed: %s", attempt, msg)
                        # detect transient quota errors and retry with backoff
                        # increment failure counter
                        self._failure_count += 1
                        if self._failure_count >= self.circuit_threshold:
                            self._circuit_open_until = time.time() + self.circuit_open_seconds
                            logger.error("Gemini circuit opened until %s after %d failures", self._circuit_open_until, self._failure_count)
                            return None

                        if ("429" in msg) or ("quota" in msg.lower()) or ("exceed" in msg.lower()):
                            if attempt < max_attempts:
                                backoff = min(2 ** attempt, 30)
                                logger.debug("Transient Gemini error, retrying in %s seconds (attempt %d/%d)", backoff, attempt, max_attempts)
                                await asyncio.sleep(backoff)
                                continue
                            else:
                                logger.debug("Quota exceeded, using local analysis")
                        # non-transient or exhausted retries -> continue to legacy fallback

                # Fallback to legacy google.generativeai if available (sync API)
                if hasattr(genai, "GenerativeModel"):
                    try:
                        loop = asyncio.get_event_loop()
                        model = genai.GenerativeModel("gemini-2.5-flash")
                        response = await loop.run_in_executor(None, lambda: model.generate_content(p))
                        text = self._extract_text_from_genai_response(response)
                        if text:
                            self._failure_count = 0
                            return text
                        self._failure_count = 0
                        return getattr(response, "text", None)
                    except Exception as e:
                        msg = str(e)
                        logger.warning("legacy generativeai attempt %d failed: %s", attempt, msg)
                        # increment failure counter
                        self._failure_count += 1
                        if self._failure_count >= self.circuit_threshold:
                            self._circuit_open_until = time.time() + self.circuit_open_seconds
                            logger.error("Gemini circuit opened until %s after %d failures", self._circuit_open_until, self._failure_count)
                            return None

                        if ("429" in msg) or ("quota" in msg.lower()) or ("exceed" in msg.lower()):
                            if attempt < max_attempts:
                                backoff = min(2 ** attempt, 30)
                                logger.info("Transient legacy Gemini error, retrying in %s seconds (attempt %d/%d)", backoff, attempt, max_attempts)
                                await asyncio.sleep(backoff)
                                continue
                            else:
                                logger.error("Exceeded retries for legacy generativeai client")
                        # else continue to next attempt or final fallback

                # If neither client yields or we should not retry further, break
                break

            return None

        # Attempt to call Gemini with retries
        genai_result = await _call_genai_with_retry(prompt)
        if genai_result:
            return genai_result

        # Final fallback to deterministic local analysis
        logger.debug("Using local analysis (Gemini quota exhausted or unavailable)")
        return self._get_fallback_analysis(threat_data)

    def _extract_text_from_genai_response(self, response: Any) -> str:
        """Best-effort extraction of textual content from various GenAI response shapes.

        The modern `google.genai` and legacy `google.generativeai` clients return different
        shapes. This helper inspects common attributes and dict structures to return
        readable text when available, otherwise falls back to `str(response)`.
        """
        try:
            # Common modern shape: response.output -> list of outputs -> each has content (list)
            if getattr(response, "output", None):
                parts = []
                for out in response.output:
                    content = getattr(out, "content", None)
                    if content:
                        for item in content:
                            # item may be an object with .text or a dict
                            txt = None
                            if hasattr(item, "text"):
                                txt = getattr(item, "text")
                            elif isinstance(item, dict):
                                txt = item.get("text") or item.get("content")
                            if txt:
                                parts.append(str(txt))
                    else:
                        # fallback: maybe out has text
                        if hasattr(out, "text"):
                            parts.append(str(getattr(out, "text")))
                if parts:
                    return "\n\n".join(parts)

            # Another common pattern: response.candidates -> list
            if getattr(response, "candidates", None):
                texts = []
                for cand in response.candidates:
                    content = getattr(cand, "content", None) or (cand.get("content") if isinstance(cand, dict) else None)
                    if isinstance(content, list):
                        for item in content:
                            if hasattr(item, "text"):
                                texts.append(getattr(item, "text"))
                            elif isinstance(item, dict) and item.get("text"):
                                texts.append(item.get("text"))
                    elif isinstance(content, str):
                        texts.append(content)
                if texts:
                    return "\n\n".join(map(str, texts))

            # Direct text attribute
            if getattr(response, "text", None):
                return str(getattr(response, "text"))

            # If it's dict-like, try to find first text-like value
            if isinstance(response, dict):
                def _find_text(obj):
                    if isinstance(obj, str):
                        return obj
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            if k.lower() in ("text", "content", "output") and v:
                                res = _find_text(v)
                                if res:
                                    return res
                        for v in obj.values():
                            res = _find_text(v)
                            if res:
                                return res
                    if isinstance(obj, list):
                        for item in obj:
                            res = _find_text(item)
                            if res:
                                return res
                    return None

                t = _find_text(response)
                if t:
                    return str(t)

        except Exception:
            # Be conservative; fall through to default
            pass

        # Fallback: stringify response
        try:
            return str(response)
        except Exception:
            return ""

    def _prepare_analysis_prompt(self, threat_data: Dict[str, Any]) -> str:
        """Prepare detailed prompt for Gemini analysis with all API results"""

        input_val = threat_data.get("input", "Unknown")
        input_type = threat_data.get("input_type", "Unknown")
        verdict = threat_data.get("verdict", "unknown")
        confidence = threat_data.get("confidence", 0.0)
        threats = threat_data.get("threat_indicators", [])
        api_results = threat_data.get("api_results", {})

        # Format threat indicators with details
        if threats:
            threat_details = []
            for t in threats:
                severity = t.get("severity", "unknown").upper()
                source = t.get("source", "Unknown")
                indicator = t.get("indicator", "No details")
                # Include additional fields if present
                extra = []
                if "score" in t:
                    extra.append(f"Score: {t['score']}")
                if "count" in t:
                    extra.append(f"Count: {t['count']}")
                extra_str = f" ({', '.join(extra)})" if extra else ""
                threat_details.append(f"  - [{severity}] {source}: {indicator}{extra_str}")
            threats_str = "\n".join(threat_details)
        else:
            threats_str = "  No threats detected"

        # Format detailed API results
        api_details = []
        apis_called = api_results.get("apis_called", [])
        
        # AbuseIPDB Details
        if "abuseipdb" in api_results and api_results["abuseipdb"]:
            abuse_data = api_results["abuseipdb"].get("data", {})
            if abuse_data:
                api_details.append(f"""
AbuseIPDB Analysis:
  - Abuse Confidence: {abuse_data.get('abuseConfidenceScore', 0)}%
  - Total Reports: {abuse_data.get('totalReports', 0)}
  - Country: {abuse_data.get('countryCode', 'Unknown')}
  - ISP: {abuse_data.get('isp', 'Unknown')}
  - Domain: {abuse_data.get('domain', 'None')}
  - Usage: {abuse_data.get('usageType', 'Unknown')}
  - Last Report: {abuse_data.get('lastReportedAt', 'Never')}""")

        # Shodan Details
        if "shodan" in api_results and api_results["shodan"]:
            shodan_data = api_results["shodan"]
            if not shodan_data.get("error"):
                ports = shodan_data.get("ports", [])
                vulns = shodan_data.get("vulns", [])
                api_details.append(f"""
Shodan Analysis:
  - Organization: {shodan_data.get('org', 'Unknown')}
  - Country: {shodan_data.get('country_name', 'Unknown')}
  - OS: {shodan_data.get('os', 'Unknown')}
  - Open Ports: {', '.join(map(str, ports[:10])) if ports else 'None'}
  - Vulnerabilities: {len(vulns)} found
  - Hostnames: {', '.join(shodan_data.get('hostnames', [])[:3]) or 'None'}""")

        # VirusTotal Details
        if "virustotal" in api_results and api_results["virustotal"]:
            vt_data = api_results["virustotal"]
            if "data" in vt_data:
                attrs = vt_data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                api_details.append(f"""
VirusTotal Analysis:
  - Malicious: {stats.get('malicious', 0)} engines
  - Suspicious: {stats.get('suspicious', 0)} engines
  - Undetected: {stats.get('undetected', 0)} engines
  - Harmless: {stats.get('harmless', 0)} engines
  - Total Engines: {sum(stats.values())}
  - Reputation: {attrs.get('reputation', 0)}""")

        # URLScan Details
        if "urlscan" in api_results and api_results["urlscan"]:
            url_data = api_results["urlscan"]
            if "verdicts" in url_data:
                overall = url_data.get("verdicts", {}).get("overall", {})
                api_details.append(f"""
URLScan Analysis:
  - Risk Score: {overall.get('score', 0)}
  - Malicious: {overall.get('malicious', False)}
  - Categories: {', '.join(overall.get('categories', [])) or 'None'}
  - Brands: {', '.join(url_data.get('brands', [])[:5]) or 'None'}
  - Tags: {', '.join(url_data.get('tags', [])[:5]) or 'None'}""")

        # Hybrid Analysis Details
        if "hybrid_analysis" in api_results and api_results["hybrid_analysis"]:
            ha_data = api_results["hybrid_analysis"]
            if "results" in ha_data and ha_data["results"]:
                item = ha_data["results"][0]
                api_details.append(f"""
Hybrid Analysis:
  - Verdict: {item.get('verdict', 'Unknown')}
  - Threat Score: {item.get('threat_score', 0)}/100
  - Malware Family: {item.get('vx_family', 'Unknown')}
  - Environment: {item.get('environment_description', 'Unknown')}""")

        api_results_str = "\n".join(api_details) if api_details else "No detailed API data available"

        prompt = f"""
You are a senior cybersecurity threat analyst. Analyze this security scan and provide a professional report.

TARGET INFORMATION:
- Target: {input_val}
- Type: {input_type}
- Scan Time: {threat_data.get('timestamp', 'Unknown')}

INITIAL VERDICT:
- Assessment: {verdict.upper()}
- Confidence: {confidence * 100:.1f}%

THREAT INDICATORS:
{threats_str}

DETAILED API RESULTS:
{api_results_str}

APIs Used: {', '.join(apis_called) if apis_called else 'None'}

Provide a professional security analysis with these sections:

1. EXECUTIVE SUMMARY (2-3 sentences)
   Overall risk and key findings

2. DETAILED ANALYSIS (4-5 paragraphs)
   - Analyze each API's findings
   - Explain threat implications
   - Correlate findings across APIs
   - Real-world risk assessment

3. TECHNICAL FINDINGS (bulleted)
   Key technical details from each API

4. RISK ASSESSMENT
   Risk level, impact, likelihood

5. RECOMMENDATIONS (prioritized)
   Immediate actions, remediation, prevention

6. CONCLUSION
   Final assessment and next steps

Keep professional, cite specific data, 800-1200 words total.
"""

        return prompt

    def _get_fallback_analysis(self, threat_data: Dict[str, Any]) -> str:
        """Generate detailed fallback analysis when Gemini is unavailable"""

        verdict = threat_data.get("verdict", "unknown").upper()
        confidence = threat_data.get("confidence", 0.0) * 100
        threats = threat_data.get("threat_indicators", [])
        api_results = threat_data.get("api_results", {})
        input_val = threat_data.get("input", "Unknown")
        input_type = threat_data.get("input_type", "Unknown")

        analysis = f"""## EXECUTIVE SUMMARY

Target: {input_val} (Type: {input_type})
Assessment: {verdict}
Confidence: {confidence:.1f}%
Scan Date: {threat_data.get('timestamp', 'Unknown')}

The target has been assessed as {verdict} with {confidence:.1f}% confidence based on analysis from multiple security APIs including VirusTotal, Shodan, URLScan, AbuseIPDB, and Hybrid Analysis.

## DETAILED ANALYSIS

"""

        # Add API-specific findings
        apis_called = api_results.get("apis_called", [])
        if apis_called:
            analysis += f"This analysis utilized {len(apis_called)} security intelligence APIs: {', '.join(apis_called)}.\n\n"

        # Analyze threat indicators
        if threats:
            analysis += f"### Threat Indicators Detected ({len(threats)})\n\n"
            analysis += "The following security threats were identified during the scan:\n\n"
            
            # Group by severity
            critical_threats = [t for t in threats if t.get('severity') == 'critical']
            medium_threats = [t for t in threats if t.get('severity') == 'medium']
            low_threats = [t for t in threats if t.get('severity') == 'low']
            
            if critical_threats:
                analysis += "**CRITICAL THREATS:**\n"
                for threat in critical_threats:
                    source = threat.get('source', 'Unknown')
                    indicator = threat.get('indicator', 'No details')
                    analysis += f"- **{source}**: {indicator}\n"
                    if 'score' in threat:
                        analysis += f"  Risk Score: {threat['score']}\n"
                analysis += "\n"
            
            if medium_threats:
                analysis += "**MEDIUM THREATS:**\n"
                for threat in medium_threats:
                    source = threat.get('source', 'Unknown')
                    indicator = threat.get('indicator', 'No details')
                    analysis += f"- **{source}**: {indicator}\n"
                analysis += "\n"
            
            if low_threats:
                analysis += "**LOW-LEVEL THREATS:**\n"
                for threat in low_threats:
                    source = threat.get('source', 'Unknown')
                    indicator = threat.get('indicator', 'No details')
                    analysis += f"- **{source}**: {indicator}\n"
                analysis += "\n"
        else:
            analysis += "### No Threats Detected\n\n"
            analysis += "No significant security threats were detected during the comprehensive scan across all security intelligence APIs.\n\n"

        # Add API-specific details
        analysis += "## TECHNICAL FINDINGS\n\n"
        
        if "abuseipdb" in api_results and api_results["abuseipdb"]:
            abuse_data = api_results["abuseipdb"].get("data", {})
            if abuse_data:
                score = abuse_data.get("abuseConfidenceScore", 0)
                analysis += f"**AbuseIPDB:**\n"
                analysis += f"- Abuse Confidence: {score}%\n"
                analysis += f"- Total Reports: {abuse_data.get('totalReports', 0)}\n"
                analysis += f"- ISP: {abuse_data.get('isp', 'Unknown')}\n"
                analysis += f"- Country: {abuse_data.get('countryCode', 'Unknown')}\n\n"

        if "shodan" in api_results and api_results["shodan"]:
            shodan_data = api_results["shodan"]
            if not shodan_data.get("error"):
                analysis += f"**Shodan:**\n"
                analysis += f"- Organization: {shodan_data.get('org', 'Unknown')}\n"
                analysis += f"- Open Ports: {len(shodan_data.get('ports', []))}\n"
                analysis += f"- Vulnerabilities: {len(shodan_data.get('vulns', []))}\n\n"

        if "virustotal" in api_results and api_results["virustotal"]:
            vt_data = api_results["virustotal"]
            if "data" in vt_data:
                stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                analysis += f"**VirusTotal:**\n"
                analysis += f"- Malicious Detections: {malicious}/{sum(stats.values())}\n"
                analysis += f"- Suspicious: {stats.get('suspicious', 0)}\n"
                analysis += f"- Clean: {stats.get('harmless', 0)}\n\n"

        analysis += "## RISK ASSESSMENT\n\n"
        
        if verdict == "MALICIOUS":
            risk_level = "CRITICAL"
            analysis += f"**Risk Level: {risk_level}**\n\n"
            analysis += "This target poses a critical security risk and should be treated with maximum caution. "
            analysis += "Immediate action is required to block or quarantine this threat.\n\n"
        elif verdict == "SUSPICIOUS":
            risk_level = "MEDIUM-HIGH"
            analysis += f"**Risk Level: {risk_level}**\n\n"
            analysis += "This target exhibits suspicious characteristics that warrant further investigation and caution. "
            analysis += "Consider implementing additional monitoring or blocking measures.\n\n"
        else:
            risk_level = "LOW"
            analysis += f"**Risk Level: {risk_level}**\n\n"
            analysis += "This target appears to be safe based on the current security assessments. "
            analysis += "However, continued monitoring is recommended as threats can emerge over time.\n\n"

        analysis += "## RECOMMENDATIONS\n\n"
        
        if verdict == "MALICIOUS":
            analysis += "**Immediate Actions:**\n"
            analysis += "1. Block all traffic to/from this target immediately\n"
            analysis += "2. Investigate any systems that have communicated with this target\n"
            analysis += "3. Initiate incident response procedures\n"
            analysis += "4. Preserve logs and forensic data\n\n"
            analysis += "**Remediation:**\n"
            analysis += "1. Scan all affected systems for malware\n"
            analysis += "2. Reset credentials for potentially compromised accounts\n"
            analysis += "3. Review firewall and security policies\n"
            analysis += "4. Document the incident for future reference\n\n"
        elif verdict == "SUSPICIOUS":
            analysis += "**Recommended Actions:**\n"
            analysis += "1. Enable enhanced monitoring for this target\n"
            analysis += "2. Restrict access based on business requirements\n"
            analysis += "3. Conduct additional investigation if interaction is necessary\n"
            analysis += "4. Update threat intelligence feeds\n\n"
        else:
            analysis += "**General Recommendations:**\n"
            analysis += "1. Continue routine security monitoring\n"
            analysis += "2. Keep security policies up to date\n"
            analysis += "3. Maintain regular scan schedules\n"
            analysis += "4. Train staff on security awareness\n\n"

        analysis += "## CONCLUSION\n\n"
        
        if threats:
            threat_summary = f"detected {len(threats)} threat indicator(s)"
        else:
            threat_summary = "found no significant threats"
        
        analysis += f"This comprehensive security analysis {threat_summary} "
        analysis += f"across multiple intelligence sources. "
        
        if verdict == "MALICIOUS":
            analysis += "The target represents a confirmed security threat requiring immediate action."
        elif verdict == "SUSPICIOUS":
            analysis += "The target exhibits characteristics that warrant caution and further investigation."
        else:
            analysis += "The target appears safe based on current intelligence, though ongoing monitoring is advised."

        analysis += f"\n\nConfidence Level: {confidence:.1f}%\n"
        analysis += f"APIs Consulted: {', '.join(apis_called) if apis_called else 'None'}\n"
        analysis += "\n---\n"
        analysis += "*Note: This is a local fallback analysis. For enhanced AI-powered insights, configure Gemini API.*"

        return analysis

    def _create_pdf_report(
        self, threat_analysis: Dict[str, Any], ai_analysis: str
    ) -> bytes:
        """Create PDF report using ReportLab"""

        from io import BytesIO

        # Create PDF in memory
        pdf_buffer = BytesIO()
        doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)

        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            textColor=colors.HexColor("#1a1a1a"),
            spaceAfter=6,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        )

        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading2"],
            fontSize=14,
            textColor=colors.HexColor("#0066cc"),
            spaceAfter=12,
            spaceBefore=12,
            fontName="Helvetica-Bold",
        )

        normal_style = ParagraphStyle(
            "CustomNormal",
            parent=styles["Normal"],
            fontSize=10,
            spaceAfter=8,
            leading=14,
        )

        # Build document elements
        elements = []

        # Header
        elements.append(Paragraph("SENTINEL-AI THREAT ANALYSIS REPORT", title_style))
        elements.append(Spacer(1, 0.2 * inch))

        # Report Info
        timestamp = threat_analysis.get("timestamp", datetime.utcnow().isoformat())
        input_val = threat_analysis.get("input", "Unknown")
        input_type = threat_analysis.get("input_type", "Unknown")
        verdict = threat_analysis.get("verdict", "unknown")
        confidence = threat_analysis.get("confidence", 0.0)
        
        # Forensic metadata
        forensic_metadata = threat_analysis.get("forensic_metadata", {})
        corroboration_count = forensic_metadata.get("corroboration_count", 0)
        corroboration_met = forensic_metadata.get("corroboration_threshold_met", False)

        info_data = [
            ["Report Generated:", timestamp],
            ["Target:", input_val],
            ["Target Type:", input_type.upper()],
            ["Verdict:", verdict.upper()],
            ["Confidence:", f"{confidence * 100:.1f}%"],
            ["Sources Corroborating:", str(corroboration_count)],
            ["Forensic Threshold Met:", "YES" if corroboration_met else "NO (single source)"],
        ]

        info_table = Table(info_data, colWidths=[2 * inch, 4 * inch])
        info_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e6e6e6")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ]
            )
        )

        elements.append(info_table)
        elements.append(Spacer(1, 0.3 * inch))

        # Forensic Evidence Section
        if forensic_metadata and forensic_metadata.get("source_details"):
            elements.append(Paragraph("FORENSIC EVIDENCE TRACKING", heading_style))
            
            source_details = forensic_metadata.get("source_details", [])
            if source_details:
                evidence_data = [["Source", "Severity", "Detection Details", "Timestamp"]]
                
                for detail in source_details:
                    evidence_data.append([
                        detail.get("source", "Unknown"),
                        detail.get("severity", "unknown").upper(),
                        detail.get("indicator", "")[:50],  # Truncate
                        detail.get("timestamp", "")[:19],  # Show only date/time
                    ])
                
                evidence_table = Table(
                    evidence_data, colWidths=[1.2 * inch, 0.9 * inch, 2.5 * inch, 1.4 * inch]
                )
                evidence_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#006633")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f8f0")]),
                    ])
                )
                elements.append(evidence_table)
                
                # Add corroboration note
                if corroboration_met:
                    corroboration_note = (
                        f"<b>FORENSIC NOTE:</b> This threat has been corroborated by "
                        f"{corroboration_count} independent sources, meeting the forensic "
                        f"reliability threshold (≥2 sources). This significantly increases "
                        f"confidence in the verdict."
                    )
                else:
                    corroboration_note = (
                        f"<b>FORENSIC CAUTION:</b> This threat has been detected by only "
                        f"{corroboration_count} source. Multi-source corroboration (≥2 sources) "
                        f"is recommended for higher forensic reliability. Consider manual review."
                    )
                
                elements.append(Spacer(1, 0.1 * inch))
                elements.append(Paragraph(corroboration_note, normal_style))
                elements.append(Spacer(1, 0.2 * inch))

        # Threat Summary
        elements.append(Paragraph("THREAT SUMMARY", heading_style))
        threats = threat_analysis.get("threat_indicators", [])

        if threats:
            threat_data = [["Source", "Severity", "Indicator"]]
            for threat in threats:
                threat_data.append(
                    [
                        threat.get("source", "Unknown"),
                        threat.get("severity", "unknown").upper(),
                        threat.get("indicator", "")[:80],  # Truncate long indicators
                    ]
                )

            threat_table = Table(
                threat_data, colWidths=[1.5 * inch, 1.2 * inch, 3.3 * inch]
            )
            threat_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0066cc")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#f9f9f9")],
                        ),
                    ]
                )
            )

            elements.append(threat_table)
        else:
            elements.append(Paragraph("No threats detected.", normal_style))

        elements.append(Spacer(1, 0.3 * inch))

        # AI Analysis
        elements.append(PageBreak())
        elements.append(Paragraph("AI ANALYSIS & RECOMMENDATIONS", heading_style))

        # Parse AI analysis into paragraphs
        for paragraph_text in ai_analysis.split("\n"):
            if paragraph_text.strip().startswith("##"):
                elements.append(
                    Paragraph(paragraph_text.replace("##", "").strip(), heading_style)
                )
            elif paragraph_text.strip().startswith("#"):
                elements.append(
                    Paragraph(paragraph_text.replace("#", "").strip(), heading_style)
                )
            elif paragraph_text.strip():
                elements.append(Paragraph(paragraph_text.strip(), normal_style))

        # Footer
        elements.append(Spacer(1, 0.5 * inch))
        footer_text = "SENTINEL-AI | Automated Threat Detection & Analysis | Powered by Google Gemini"
        elements.append(
            Paragraph(
                footer_text,
                ParagraphStyle(
                    "Footer",
                    parent=styles["Normal"],
                    fontSize=8,
                    textColor=colors.grey,
                    alignment=TA_CENTER,
                ),
            )
        )

        # Build PDF
        doc.build(elements)

        # Get PDF bytes
        pdf_buffer.seek(0)
        return pdf_buffer.read()


# Global instance
report_generator = ReportGenerator()
