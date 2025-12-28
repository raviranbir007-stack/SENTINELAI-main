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
        try:
            self.gemini_max_attempts = int(os.getenv("GEMINI_MAX_ATTEMPTS", "4"))
        except Exception:
            self.gemini_max_attempts = 4
        try:
            self.circuit_threshold = int(os.getenv("GEMINI_CIRCUIT_THRESHOLD", "6"))
        except Exception:
            self.circuit_threshold = 6
        try:
            self.circuit_open_seconds = int(os.getenv("GEMINI_CIRCUIT_OPEN_SECONDS", "300"))
        except Exception:
            self.circuit_open_seconds = 300

        self._failure_count = 0
        self._circuit_open_until = 0

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
        if not self.initialized or not GEMINI_AVAILABLE:
            return self._get_fallback_analysis(threat_data)
        # Prepare prompt for Gemini
        prompt = self._prepare_analysis_prompt(threat_data)

        # Unified call with retry/backoff for modern and legacy clients
        async def _call_genai_with_retry(p: str, max_attempts: int = self.gemini_max_attempts) -> Optional[str]:
            # Circuit open check
            if time.time() < self._circuit_open_until:
                logger.warning("Gemini circuit open until %s, skipping remote call", self._circuit_open_until)
                return None

            for attempt in range(1, max_attempts + 1):
                # Try modern google.genai client first
                if hasattr(genai, "client") and hasattr(genai.client, "Client"):
                    try:
                        client = genai.client.Client(api_key=self.gemini_key)

                        # Try to pick a reasonable model if available
                        model_name = None
                        try:
                            models_list = client.models.list()
                            if getattr(models_list, "models", None):
                                m = models_list.models[0]
                                model_name = getattr(m, "name", None) or getattr(m, "id", None)
                        except Exception:
                            model_name = None

                        if not model_name:
                            model_name = "gemini-1.0"

                        response = client.models.generate_content(model=model_name, contents=p)
                        text = self._extract_text_from_genai_response(response)
                        if text:
                            # success -> reset failures
                            self._failure_count = 0
                            return text
                        # fallback to stringified response
                        self._failure_count = 0
                        return str(response)

                    except Exception as e:
                        msg = str(e)
                        logger.warning("google.genai attempt %d failed: %s", attempt, msg)
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
                                logger.info("Transient Gemini error, retrying in %s seconds (attempt %d/%d)", backoff, attempt, max_attempts)
                                await asyncio.sleep(backoff)
                                continue
                            else:
                                logger.error("Exceeded retries for google.genai client")
                        # non-transient or exhausted retries -> continue to legacy fallback

                # Fallback to legacy google.generativeai if available (sync API)
                if hasattr(genai, "GenerativeModel"):
                    try:
                        loop = asyncio.get_event_loop()
                        model = genai.GenerativeModel("gemini-2.0-flash-exp")
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
        logger.info("Falling back to local analysis (Gemini unavailable or failed)")
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
        """Prepare prompt for Gemini analysis"""

        input_val = threat_data.get("input", "Unknown")
        input_type = threat_data.get("input_type", "Unknown")
        verdict = threat_data.get("verdict", "unknown")
        confidence = threat_data.get("confidence", 0.0)
        threats = threat_data.get("threat_indicators", [])
        api_results = threat_data.get("api_results", {})

        if threats:
            parts = []
            for t in threats:
                parts.append(
                    "- {}: {} (Severity: {})".format(
                        t.get("source", "Unknown"),
                        t.get("indicator", "No details"),
                        t.get("severity", "unknown"),
                    )
                )
            threats_str = "\n".join(parts)
        else:
            threats_str = ""

        prompt = f"""
Analyze the following security threat assessment and provide a comprehensive professional report:

SCAN TARGET:
- Input: {input_val}
- Type: {input_type}

VERDICT: {verdict.upper()}
Confidence Score: {confidence * 100:.1f}%

DETECTED THREATS:
{threats_str if threats else 'No threats detected'}

APIS CALLED: {', '.join(api_results.get('apis_called', []))}

Please provide:
1. Executive Summary: Brief assessment of the threat level
2. Risk Analysis: Detailed analysis of each detected threat
3. API Findings: Summary of what each security API found
4. Recommendations: Actions to take based on findings
5. Conclusion: Final professional recommendation

Format the response in clear sections with markdown headers.
Keep it professional and concise (500-800 words).
"""

        return prompt

    def _get_fallback_analysis(self, threat_data: Dict[str, Any]) -> str:
        """Generate fallback analysis when Gemini is unavailable"""

        verdict = threat_data.get("verdict", "unknown").upper()
        confidence = threat_data.get("confidence", 0.0) * 100
        threats = threat_data.get("threat_indicators", [])

        analysis = f"""## Executive Summary
The target has been assessed as {verdict} with {confidence:.1f}% confidence.

## Risk Analysis
"""

        if threats:
            analysis += "The following security threats were detected:\n\n"
            for threat in threats:
                analysis += f"- **{threat.get('source', 'Unknown')}**: {threat.get('indicator', 'No details')}\n"
                analysis += (
                    f"  Severity: {threat.get('severity', 'Unknown').upper()}\n\n"
                )
        else:
            analysis += (
                "No significant security threats were detected during the scan.\n\n"
            )

        analysis += """## Recommendations
- Review the detailed API results in the technical section
- Take appropriate action based on the threat level
- Monitor the target for any future suspicious activity
- Update security policies if needed

## Conclusion
"""

        if verdict == "MALICIOUS":
            analysis += (
                "This target poses a critical security risk and should be treated "
                "with maximum caution. Immediate action is recommended."
            )
        elif verdict == "SUSPICIOUS":
            analysis += (
                "This target exhibits suspicious characteristics and warrants "
                "further investigation. Exercise caution when interacting with this resource."
            )
        else:
            analysis += "This target appears to be safe based on the security assessments performed."

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

        info_data = [
            ["Report Generated:", timestamp],
            ["Target:", input_val],
            ["Target Type:", input_type.upper()],
            ["Verdict:", verdict.upper()],
            ["Confidence:", f"{confidence * 100:.1f}%"],
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
