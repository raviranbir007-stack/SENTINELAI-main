"""
PDF Report Generator using Gemini API
Generates AI-analyzed threat reports in PDF format
"""

import asyncio
import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
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
                            logger.debug("Gemini circuit opened until %s after %d failures", self._circuit_open_until, self._failure_count)
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
                            logger.debug("Gemini circuit opened until %s after %d failures", self._circuit_open_until, self._failure_count)
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

        # Format forensic metadata
        forensic_metadata = threat_data.get("forensic_metadata", {})
        forensic_str = ""
        if forensic_metadata and forensic_metadata.get("corroboration_count") is not None:
            corroboration_count = forensic_metadata.get("corroboration_count", 0)
            corroboration_met = forensic_metadata.get("corroboration_threshold_met", False)
            unique_sources = forensic_metadata.get("unique_sources", [])
            total_indicators = forensic_metadata.get("total_indicators", 0)
            critical_indicators = forensic_metadata.get("critical_indicators", 0)
            medium_indicators = forensic_metadata.get("medium_indicators", 0)
            low_indicators = forensic_metadata.get("low_indicators", 0)
            
            forensic_str = f"""
FORENSIC RELIABILITY ANALYSIS:
- Evidence Sources: {', '.join(unique_sources) if unique_sources else 'None'}
- Corroboration Count: {corroboration_count} sources
- Forensic Threshold Met: {'YES (≥2 sources)' if corroboration_met else 'NO (single source - manual review recommended)'}
- Total Threat Indicators: {total_indicators}
  * Critical: {critical_indicators}
  * Medium: {medium_indicators}
  * Low: {low_indicators}
- Reliability Rating: {'HIGH - Multi-source corroboration' if corroboration_met else 'MODERATE - Single source detection'}
"""

        prompt = f"""
You are a senior cybersecurity threat analyst. Analyze this security scan and provide a professional report.

TARGET INFORMATION:
- Target: {input_val}
- Type: {input_type}
- Scan Time: {threat_data.get('timestamp', 'Unknown')}

INITIAL VERDICT:
- Assessment: {verdict.upper()}
- Confidence: {confidence * 100:.1f}%
{forensic_str}
THREAT INDICATORS:
{threats_str}

DETAILED API RESULTS:
{api_results_str}

APIs Used: {', '.join(apis_called) if apis_called else 'None'}

Provide a professional security analysis with these sections:

1. EXECUTIVE SUMMARY (2-3 sentences)
   Overall risk and key findings, including forensic reliability status

2. FORENSIC RELIABILITY ASSESSMENT (1-2 paragraphs)
   - Discuss the corroboration status and what it means for confidence
   - Explain the significance of multi-source vs single-source detection
   - Address any concerns about reliability based on source count

3. DETAILED ANALYSIS (4-5 paragraphs)
   - Analyze each API's findings
   - Explain threat implications
   - Correlate findings across APIs
   - Real-world risk assessment

4. TECHNICAL FINDINGS (bulleted)
   Key technical details from each API

5. RISK ASSESSMENT
   Risk level, impact, likelihood, and reliability confidence

6. RECOMMENDATIONS (prioritized)
   Immediate actions, remediation, prevention

7. CONCLUSION
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
        forensic_metadata = threat_data.get("forensic_metadata", {})
        apis_called = api_results.get("apis_called", [])

        if apis_called:
            coverage_line = (
                f"The target has been assessed as {verdict} with {confidence:.1f}% confidence based on "
                f"{len(apis_called)} security intelligence source(s): {', '.join(apis_called)}."
            )
        else:
            coverage_line = (
                f"The target has been assessed as {verdict} with {confidence:.1f}% confidence based on "
                "available local and heuristic analysis (external API corroboration unavailable)."
            )

        analysis = f"""## EXECUTIVE SUMMARY

Target: {input_val} (Type: {input_type})
Assessment: {verdict}
Confidence: {confidence:.1f}%
Scan Date: {threat_data.get('timestamp', 'Unknown')}

{coverage_line}

## FORENSIC RELIABILITY ASSESSMENT

"""

        # Add forensic metadata
        if forensic_metadata and forensic_metadata.get("corroboration_count") is not None:
            corroboration_count = forensic_metadata.get("corroboration_count", 0)
            corroboration_met = forensic_metadata.get("corroboration_threshold_met", False)
            unique_sources = forensic_metadata.get("unique_sources", [])
            total_indicators = forensic_metadata.get("total_indicators", len(threats))
            apis_checked_count = int(forensic_metadata.get("apis_checked", len(apis_called)) or 0)
            total_apis_available = int(forensic_metadata.get("total_apis_available", len(apis_called)) or 0)
            unavailable_reasons = forensic_metadata.get("external_corroboration_unavailable_reasons", [])
            
            if total_indicators == 0:
                analysis += f"**FORENSIC STATUS: BASELINE CLEAR**\n\n"
                analysis += "No threat indicators were identified in this scan. Corroboration thresholds are not applicable for clean results. "
                analysis += "Reliability is primarily reflected through scan coverage (number of completed checks and intelligence sources queried).\n\n"
            elif corroboration_met:
                analysis += f"**FORENSIC STATUS: HIGH RELIABILITY**\n\n"
                analysis += f"This threat assessment has been corroborated by {corroboration_count} independent security intelligence sources: {', '.join(unique_sources)}.\n\n"
                analysis += "Multi-source corroboration (≥2 sources) significantly increases the reliability and confidence of this assessment. "
                analysis += "The independent confirmation from multiple threat intelligence providers provides strong forensic evidence "
                analysis += "for the detected threats, making this assessment suitable for security incident documentation and compliance reporting.\n\n"
            elif corroboration_count == 1:
                analysis += f"**FORENSIC STATUS: LIMITED CORROBORATION**\n\n"
                analysis += f"This threat assessment is currently supported by one source: {', '.join(unique_sources) if unique_sources else 'N/A'}.\n\n"
                analysis += "⚠️ FORENSIC CAUTION: Single-source detection has moderate reliability. Obtain at least one independent confirmation "
                analysis += "before initiating irreversible remediation or legal/compliance actions.\n\n"
            else:
                if total_apis_available > 0 and apis_checked_count == 0:
                    analysis += f"**FORENSIC STATUS: EVIDENCE-LIMITED (EXTERNAL CORROBORATION UNAVAILABLE)**\n\n"
                    analysis += (
                        "Threat signals were detected, but relevant external corroboration sources were not reachable/configured for this scan window. "
                        "This is an evidence-availability limitation, not proof that the signal is false.\n\n"
                    )
                    if unavailable_reasons:
                        analysis += f"External corroboration blockers: {', '.join(unavailable_reasons)}.\n\n"
                    analysis += (
                        "⚠️ INVESTIGATION GUIDANCE: Preserve endpoint/network artifacts, re-run scan when API coverage is restored, and seek at least "
                        "one independent external confirmation before legal/compliance escalation.\n\n"
                    )
                elif apis_checked_count > 0:
                    analysis += f"**FORENSIC STATUS: API-CHECKED, NO POSITIVE CORROBORATION**\n\n"
                    analysis += (
                        "Threat signals were detected, but completed external checks did not independently confirm the same threat pattern. "
                        "Treat as investigational and continue evidence collection.\n\n"
                    )
                    analysis += "⚠️ FORENSIC CAUTION: Re-scan and validate with additional sources to reduce false positives and improve evidence quality.\n\n"
                else:
                    analysis += f"**FORENSIC STATUS: UNCORROBORATED**\n\n"
                    analysis += "Threat signals were detected, but no independent source corroboration is currently available.\n\n"
                    analysis += "⚠️ FORENSIC CAUTION: Re-scan and validate with additional sources to reduce false positives and improve evidence quality.\n\n"
            
            # Add indicator breakdown
            if total_indicators > 0:
                analysis += f"**Evidence Breakdown:**\n"
                analysis += f"- Total Threat Indicators: {total_indicators}\n"
                analysis += f"- Critical Severity: {forensic_metadata.get('critical_indicators', 0)}\n"
                analysis += f"- Medium Severity: {forensic_metadata.get('medium_indicators', 0)}\n"
                analysis += f"- Low Severity: {forensic_metadata.get('low_indicators', 0)}\n\n"
        else:
            analysis += "Forensic metadata not available for this scan.\n\n"

        analysis += "## DETAILED ANALYSIS\n\n"

        # Add API-specific findings
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

    def _get_report_action_plan(self, threat_analysis: Dict[str, Any]) -> list[str]:
        """Return a concise prioritized action plan for professional reports."""
        recommendations = threat_analysis.get("recommendations") or []
        if recommendations:
            return [str(item).strip() for item in recommendations if str(item).strip()][:5]

        verdict = str(threat_analysis.get("verdict", "unknown")).lower()
        if verdict in {"malicious", "critical"}:
            return [
                "Isolate or block the target immediately.",
                "Review affected hosts, sessions, and recent communications.",
                "Preserve logs and forensic evidence for follow-up analysis.",
                "Open an incident ticket and track containment actions.",
            ]
        if verdict == "suspicious":
            return [
                "Place the target under enhanced monitoring.",
                "Validate business need before allowing further interaction.",
                "Collect corroborating telemetry from endpoint, proxy, and DNS logs.",
                "Escalate to analyst review if activity persists.",
            ]
        return [
            "No immediate containment is required.",
            "Keep the target in routine monitoring baselines.",
            "Retain this assessment for audit and trend reporting.",
        ]

    def _get_api_coverage_rows(self, threat_analysis: Dict[str, Any]) -> list[list[str]]:
        """Build report rows summarizing which intelligence sources participated."""
        api_status = threat_analysis.get("api_results", {}).get("api_status", {}) or {}
        rows = [["Source", "Status", "Configured", "Applicable"]]

        if not api_status:
            rows.append(["N/A", "No telemetry", "No", "No"])
            return rows

        for api_key in ["virustotal", "abuseipdb", "shodan", "urlscan", "hybrid_analysis"]:
            api_meta = api_status.get(api_key)
            if not api_meta:
                continue
            rows.append(
                [
                    str(api_meta.get("name", api_key)),
                    str(api_meta.get("status", "unknown")).replace("_", " ").title(),
                    "Yes" if api_meta.get("configured") else "No",
                    "Yes" if api_meta.get("applicable") else "No",
                ]
            )

        return rows

    def _get_endpoint_vuln_summary(self, hours: int = 24) -> Optional[Dict[str, int]]:
        """Summarize endpoint vulnerability findings from local activity_logs DB.

        Returns per-severity counts for the requested time window, or None when
        no vulnerability table/data is available.
        """
        try:
            project_root = Path(__file__).resolve().parents[3]
            candidates = [
                project_root / "activity_logs.db",
                project_root / "server" / "activity_logs.db",
                project_root / "client" / "activity_logs.db",
            ]

            cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

            for db_path in candidates:
                if not db_path.exists():
                    continue

                conn = sqlite3.connect(str(db_path))
                try:
                    cur = conn.cursor()
                    cur.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='vulnerabilities'"
                    )
                    if not cur.fetchone():
                        continue

                    cur.execute(
                        """
                        SELECT UPPER(COALESCE(severity, 'INFO')) as sev, COUNT(*)
                        FROM vulnerabilities
                        WHERE timestamp >= ?
                        GROUP BY UPPER(COALESCE(severity, 'INFO'))
                        """,
                        (cutoff,),
                    )
                    rows = cur.fetchall()
                    if not rows:
                        continue

                    counts = {sev: int(cnt) for sev, cnt in rows}
                    summary = {
                        "critical": counts.get("CRITICAL", 0),
                        "high": counts.get("HIGH", 0),
                        "medium": counts.get("MEDIUM", 0),
                        "low": counts.get("LOW", 0),
                        "info": counts.get("INFO", 0),
                    }
                    summary["total"] = sum(summary.values())
                    return summary
                finally:
                    conn.close()

            return None
        except Exception as e:
            logger.debug(f"Could not read endpoint vulnerability summary: {e}")
            return None

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

        emphasis_style = ParagraphStyle(
            "Emphasis",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#2f3b52"),
            backColor=colors.HexColor("#f4f7fb"),
            borderPadding=8,
        )

        # Build document elements
        elements = []

        # Header
        elements.append(Paragraph("SENTINEL-AI THREAT ANALYSIS REPORT", title_style))
        elements.append(Spacer(1, 0.2 * inch))

        # Report Info
        timestamp = threat_analysis.get("timestamp", datetime.now(timezone.utc).isoformat())
        input_val = threat_analysis.get("input", "Unknown")
        input_type = threat_analysis.get("input_type", "Unknown")
        verdict = threat_analysis.get("verdict", "unknown")
        confidence = threat_analysis.get("confidence", 0.0)
        verdict_key = str(verdict).lower()
        
        # Forensic metadata
        forensic_metadata = threat_analysis.get("forensic_metadata", {})
        corroboration_count = forensic_metadata.get("corroboration_count", 0)
        corroboration_met = forensic_metadata.get("corroboration_threshold_met", False)
        threat_indicators_count = len(threat_analysis.get("threat_indicators", []))
        apis_checked_count = int(forensic_metadata.get("apis_checked", 0) or 0)
        total_apis_available = int(forensic_metadata.get("total_apis_available", 0) or 0)

        verdict_palette = {
            "safe": {"bg": colors.HexColor("#e8f5e9"), "fg": colors.HexColor("#1b5e20")},
            "clean": {"bg": colors.HexColor("#e8f5e9"), "fg": colors.HexColor("#1b5e20")},
            "malicious": {"bg": colors.HexColor("#fff3e0"), "fg": colors.HexColor("#e65100")},
            "suspicious": {"bg": colors.HexColor("#ffebee"), "fg": colors.HexColor("#b71c1c")},
        }
        verdict_style = verdict_palette.get(verdict_key, {"bg": colors.HexColor("#eceff1"), "fg": colors.HexColor("#263238")})

        if threat_indicators_count == 0:
            forensic_threshold_text = "N/A (no threat indicators)"
            forensic_cell_bg = colors.HexColor("#e8f5e9")
            forensic_cell_fg = colors.HexColor("#1b5e20")
        elif corroboration_met:
            forensic_threshold_text = "YES (multi-source corroborated)"
            forensic_cell_bg = colors.HexColor("#e8f5e9")
            forensic_cell_fg = colors.HexColor("#1b5e20")
        elif corroboration_count == 1:
            forensic_threshold_text = "NO (single source - limited reliability)"
            forensic_cell_bg = colors.HexColor("#fff3e0")
            forensic_cell_fg = colors.HexColor("#e65100")
        else:
            if total_apis_available > 0 and apis_checked_count == 0:
                forensic_threshold_text = "NO (external corroboration unavailable)"
                forensic_cell_bg = colors.HexColor("#fff8e1")
                forensic_cell_fg = colors.HexColor("#8d6e63")
            elif apis_checked_count > 0:
                forensic_threshold_text = "NO (API-checked, no positive corroboration)"
                forensic_cell_bg = colors.HexColor("#ffebee")
                forensic_cell_fg = colors.HexColor("#b71c1c")
            else:
                forensic_threshold_text = "NO (uncorroborated)"
                forensic_cell_bg = colors.HexColor("#ffebee")
                forensic_cell_fg = colors.HexColor("#b71c1c")

        info_data = [
            ["Report Generated:", timestamp],
            ["Target:", input_val],
            ["Target Type:", input_type.upper()],
            ["Verdict:", verdict.upper()],
            ["Confidence:", f"{confidence * 100:.1f}%"],
            ["Sources Corroborating:", str(corroboration_count)],
            ["Forensic Threshold Met:", forensic_threshold_text],
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
                    ("BACKGROUND", (1, 3), (1, 3), verdict_style["bg"]),
                    ("TEXTCOLOR", (1, 3), (1, 3), verdict_style["fg"]),
                    ("FONTNAME", (1, 3), (1, 3), "Helvetica-Bold"),
                    ("BACKGROUND", (1, 6), (1, 6), forensic_cell_bg),
                    ("TEXTCOLOR", (1, 6), (1, 6), forensic_cell_fg),
                    ("FONTNAME", (1, 6), (1, 6), "Helvetica-Bold"),
                ]
            )
        )

        elements.append(info_table)
        elements.append(Spacer(1, 0.3 * inch))

        threats = threat_analysis.get("threat_indicators", [])
        action_plan = self._get_report_action_plan(threat_analysis)
        executive_snapshot = (
            f"<b>Executive Snapshot:</b> Verdict <b>{verdict.upper()}</b> with "
            f"confidence <b>{confidence * 100:.1f}%</b>. The assessment recorded "
            f"<b>{len(threats)}</b> threat indicator(s), <b>{forensic_metadata.get('apis_checked', 0)}</b> "
            f"relevant API check(s), and a corroboration count of "
            f"<b>{forensic_metadata.get('corroboration_count', 0)}</b>. "
            f"Primary operator action: <b>{action_plan[0]}</b>"
        )
        elements.append(Paragraph(executive_snapshot, emphasis_style))
        elements.append(Spacer(1, 0.15 * inch))
        
        # Activity Monitoring Section (if available)
        try:
            from .activity_database import activity_db
            activity_summary = activity_db.get_activity_summary(hours=24)
            
            if activity_summary and activity_summary.get('threat_scans', 0) > 0:
                elements.append(Paragraph("ACTIVITY MONITORING SUMMARY (Last 24h)", heading_style))
                
                activity_data = [
                    ["Metric", "Count"],
                    ["Threat Scans Performed", str(activity_summary.get('threat_scans', 0))],
                    ["Threats Detected", str(activity_summary.get('threats_detected', 0))],
                    ["Websites Monitored", str(activity_summary.get('websites_visited', 0))],
                    ["Applications Monitored", str(activity_summary.get('applications_launched', 0))],
                    ["Network Connections", str(activity_summary.get('network_connections', 0))],
                ]
                
                activity_table = Table(activity_data, colWidths=[3 * inch, 2 * inch])
                activity_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0066cc")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 11),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f0f0")]),
                    ])
                )
                
                elements.append(activity_table)
                elements.append(Spacer(1, 0.2 * inch))

                # Endpoint vulnerability scan summary (short/simple table)
                vuln_summary = self._get_endpoint_vuln_summary(hours=24)
                if vuln_summary and vuln_summary.get("total", 0) > 0:
                    elements.append(Paragraph("ENDPOINT VULNERABILITY SUMMARY (Last 24h)", heading_style))

                    vuln_data = [
                        ["Severity", "Findings"],
                        ["Critical", str(vuln_summary.get("critical", 0))],
                        ["High", str(vuln_summary.get("high", 0))],
                        ["Medium", str(vuln_summary.get("medium", 0))],
                        ["Low", str(vuln_summary.get("low", 0))],
                        ["Info", str(vuln_summary.get("info", 0))],
                        ["Total", str(vuln_summary.get("total", 0))],
                    ]

                    vuln_table = Table(vuln_data, colWidths=[3 * inch, 2 * inch])
                    vuln_table.setStyle(
                        TableStyle([
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474f")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 10),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                            ("TOPPADDING", (0, 0), (-1, -1), 7),
                            ("GRID", (0, 0), (-1, -1), 1, colors.black),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
                            ("BACKGROUND", (0, 6), (-1, 6), colors.HexColor("#eceff1")),
                            ("FONTNAME", (0, 6), (-1, 6), "Helvetica-Bold"),
                        ])
                    )
                    elements.append(vuln_table)
                    elements.append(Spacer(1, 0.2 * inch))
                
                # Recent threats from activity monitoring
                recent_threats = activity_db.get_recent_threats(limit=5)
                if recent_threats:
                    elements.append(Paragraph("Recent Threats Detected", heading_style))
                    
                    for threat in recent_threats:
                        threat_text = f"• [{threat['time']}] {threat['type'].upper()}: {threat['value']} - {threat['verdict'].upper()} (Confidence: {threat['confidence']:.1%}, Sources: {threat['sources']})"
                        elements.append(Paragraph(threat_text, normal_style))
                    
                    elements.append(Spacer(1, 0.2 * inch))
        except Exception as e:
            logger.debug(f"Could not include activity monitoring in report: {e}")

        # Intelligence source coverage
        elements.append(Paragraph("INTELLIGENCE SOURCE COVERAGE", heading_style))
        coverage_table = Table(
            self._get_api_coverage_rows(threat_analysis),
            colWidths=[1.8 * inch, 1.5 * inch, 1.2 * inch, 1.2 * inch],
        )
        coverage_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        elements.append(coverage_table)
        elements.append(Spacer(1, 0.2 * inch))

        # Prioritized action plan
        elements.append(Paragraph("PRIORITIZED ACTION PLAN", heading_style))
        for index, action in enumerate(action_plan, start=1):
            elements.append(Paragraph(f"{index}. {action}", normal_style))
        elements.append(Spacer(1, 0.2 * inch))

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
                elif len(threats) == 0:
                    corroboration_note = (
                        "<b>FORENSIC NOTE:</b> No threat indicators were detected in this scan. "
                        "Single-source corroboration checks are not required for clean results."
                    )
                else:
                    corroboration_note = (
                        f"<b>FORENSIC CAUTION:</b> This threat has limited corroboration "
                        f"({corroboration_count} source). Multi-source corroboration (≥2 sources) "
                        f"is recommended for higher forensic reliability before critical response actions."
                    )
                
                elements.append(Spacer(1, 0.1 * inch))
                elements.append(Paragraph(corroboration_note, normal_style))
                elements.append(Spacer(1, 0.2 * inch))

        # Advanced forensic intelligence (if available)
        advanced_forensic = (
            threat_analysis.get("forensic_analysis")
            or forensic_metadata.get("advanced_analysis")
            or {}
        )
        if advanced_forensic:
            elements.append(Paragraph("ADVANCED FORENSIC INTELLIGENCE", heading_style))

            orchestration = advanced_forensic.get("orchestration", {})
            methods = advanced_forensic.get("detection_methods", {})
            cor_summary = advanced_forensic.get("corroboration_summary", {})

            advanced_rows = [
                ["Orchestration Coverage", f"{orchestration.get('coverage_percent', 0)}%"],
                ["APIs Expected/Called", f"{orchestration.get('apis_expected', 0)}/{orchestration.get('apis_called', 0)}"],
                ["Detection Method Mix", f"H={methods.get('heuristic_indicators', 0)} | S={methods.get('signature_based_indicators', 0)} | TI={methods.get('threat_intel_indicators', 0)}"],
                ["Corroboration Reliability", str(cor_summary.get("reliability", "unknown")).upper()],
            ]

            advanced_table = Table(advanced_rows, colWidths=[2.2 * inch, 3.8 * inch])
            advanced_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8eef8")),
                    ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#90a4ae")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ])
            )
            elements.append(advanced_table)
            elements.append(Spacer(1, 0.1 * inch))

            elements.append(Spacer(1, 0.2 * inch))

        # Threat Summary
        elements.append(Paragraph("THREAT SUMMARY", heading_style))

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
