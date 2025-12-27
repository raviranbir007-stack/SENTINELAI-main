import io
import logging

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# ---------- ReportLab Import Handling ----------
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

# ---------- Gemini AI Optional Support ----------
try:
    import os

    import google.generativeai as genai

    GEMINI_KEY = os.getenv("GEMINI_API_KEY")
    if GEMINI_KEY:
        genai.configure(api_key=GEMINI_KEY)
        GEMINI_READY = True
    else:
        GEMINI_READY = False
except Exception:
    GEMINI_READY = False

router = APIRouter()
logger = logging.getLogger(__name__)


# ---------- Request Schema ----------
class ReportRequest(BaseModel):
    target: str
    risk_score: float | None = None
    threats: list[str] | None = None
    scan_summary: str | None = None


# ---------- AI Text Generation ----------
def generate_ai_report(data: ReportRequest) -> str:
    base_text = f"""
Security Report for Target: {data.target}

Risk Score: {data.risk_score if data.risk_score is not None else "Not Available"}

Threat Summary:
{", ".join(data.threats) if data.threats else "No threats found or data missing."}

Scan Summary:
{data.scan_summary if data.scan_summary else "Scan summary not available."}
"""

    if not GEMINI_READY:
        return (
            base_text
            + "\n\nNote: AI enhancement unavailable. Install Gemini / set API key."
        )

    try:
        model = genai.GenerativeModel("gemini-pro")
        response = model.generate_content(
            f"Create a professional cybersecurity vulnerability report:\n{base_text}"
        )
        return response.text
    except Exception as e:
        logger.error(f"Gemini AI failed: {e}")
        return base_text + "\n\nNote: AI enhancement failed."


# ---------- PDF Generator ----------
def create_pdf(text: str, data: ReportRequest) -> io.BytesIO:
    if not REPORTLAB_AVAILABLE:
        raise HTTPException(
            status_code=500,
            detail="ReportLab not installed. Run: pip install reportlab",
        )

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setTitle(f"{data.target} Security Report")

    y = 750
    for line in text.split("\n"):
        if y < 40:
            pdf.showPage()
            y = 750
        pdf.drawString(50, y, line)
        y -= 18

    pdf.save()
    buffer.seek(0)
    return buffer


# ---------- API Endpoint ----------
@router.post("/generate")
async def generate_report(data: ReportRequest):
    try:
        logger.info(f"Generating report for target: {data.target}")

        report_text = generate_ai_report(data)
        pdf_file = create_pdf(report_text, data)

        filename = f"{data.target}_security_report.pdf"

        return StreamingResponse(
            pdf_file,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail="Report generation failed")
