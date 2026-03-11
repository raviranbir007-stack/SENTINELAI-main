69
"""
Advanced Reporting Endpoints
Generates structured reports for multiple time intervals (24h, 7d, 30d)
"""

import io
import logging
from datetime import datetime, timedelta
from typing import List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import and_, func
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ....database import get_db, init_db
from ....models import (
    AttackEvent,
    ClientInstallation,
    DefenseAction,
    ScanHistory,
    ThreatSeverity,
)
from ...compat import REPORTS_PDF_CACHE, REPORTS_STORE
from .report_generators import generate_executive_summary_pdf, generate_technical_analysis_pdf

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
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
router = APIRouter()


class ReportInterval(BaseModel):
    """Report time interval configuration"""

    hours: int
    label: str


REPORT_INTERVALS = {
    "24h": ReportInterval(hours=24, label="24 Hours"),
    "7d": ReportInterval(hours=168, label="7 Days"),
    "30d": ReportInterval(hours=720, label="30 Days"),
}


class AdvancedReportRequest(BaseModel):
    """Request model for advanced report generation"""

    intervals: List[str] = ["24h", "7d", "30d"]  # Time intervals to include
    include_files: bool = True
    include_urls: bool = True
    include_ips: bool = True
    include_domains: bool = True
    include_hashes: bool = True
    include_attacks: bool = True
    include_defense_actions: bool = True
    client_id: Optional[str] = None  # Filter by specific client
    format: str = "pdf"  # pdf or json
    report_type: str = "executive_summary"  # 'executive_summary' or 'technical_analysis'


@router.post("/generate-comprehensive")
async def generate_comprehensive_report(
    request: AdvancedReportRequest, db: AsyncSession = Depends(get_db)
):
    """
    Generate comprehensive security report across multiple time intervals
    Includes all scans (files, URLs, IPs, domains, hashes), attacks, and defense actions
    """
    try:
        # Ensure DB schema exists (handles fresh installs or new DB files)
        try:
            await init_db()
        except Exception as e:
            logger.warning(f"Database init check failed: {e}")

        logger.info(f"Generating comprehensive report for intervals: {request.intervals}")

        # Collect data for each interval
        report_data = {}

        for interval_key in request.intervals:
            if interval_key not in REPORT_INTERVALS:
                continue

            interval = REPORT_INTERVALS[interval_key]
            since_time = datetime.utcnow() - timedelta(hours=interval.hours)

            # Query scan history
            scan_query = select(ScanHistory).where(ScanHistory.scan_timestamp >= since_time)

            if request.client_id:
                # Join with ClientInstallation to filter by client_id
                scan_query = scan_query.join(ClientInstallation).where(
                    ClientInstallation.client_id == request.client_id
                )

            try:
                result = await db.execute(scan_query)
                all_scans = result.scalars().all()
            except OperationalError as e:
                # Attempt one-time schema creation and retry
                logger.warning(f"Scan history query failed, retrying after init: {e}")
                await init_db()
                result = await db.execute(scan_query)
                all_scans = result.scalars().all()

            # Filter scans by type
            scans_by_type = {
                "files": [],
                "urls": [],
                "ips": [],
                "domains": [],
                "hashes": [],
            }

            for scan in all_scans:
                scan_type = scan.target_type.lower()
                if scan_type == "file" and request.include_files:
                    scans_by_type["files"].append(scan)
                elif scan_type == "url" and request.include_urls:
                    scans_by_type["urls"].append(scan)
                elif scan_type == "ip" and request.include_ips:
                    scans_by_type["ips"].append(scan)
                elif scan_type == "domain" and request.include_domains:
                    scans_by_type["domains"].append(scan)
                elif scan_type == "hash" and request.include_hashes:
                    scans_by_type["hashes"].append(scan)

            # Query attack events
            attacks = []
            if request.include_attacks:
                attack_query = select(AttackEvent).where(AttackEvent.detected_at >= since_time)
                if request.client_id:
                    attack_query = attack_query.join(ClientInstallation).where(
                        ClientInstallation.client_id == request.client_id
                    )
                result = await db.execute(attack_query)
                attacks = result.scalars().all()

            # Query defense actions
            defense_actions = []
            if request.include_defense_actions:
                action_query = select(DefenseAction).where(DefenseAction.created_at >= since_time)
                if request.client_id:
                    action_query = action_query.join(ClientInstallation).where(
                        ClientInstallation.client_id == request.client_id
                    )
                result = await db.execute(action_query)
                defense_actions = result.scalars().all()

            # Calculate statistics
            # Forensic reliability metrics
            scans_with_forensic = sum(1 for s in all_scans if s.analysis_data and s.analysis_data.get("forensic_metadata", {}).get("apis_checked", 0) > 0)
            avg_apis_checked = (
                sum(
                    s.analysis_data.get("forensic_metadata", {}).get("apis_checked", 0)
                    for s in all_scans
                    if s.analysis_data
                )
                / len(all_scans)
                if all_scans
                else 0
            )
            corroborated_threats = sum(1 for s in all_scans if s.analysis_data and s.analysis_data.get("forensic_metadata", {}).get("corroboration_threshold_met", False))
            high_confidence_threats = sum(
                1
                for s in all_scans
                if s.threat_level in ["suspicious", "malicious"] and s.confidence >= 0.7
            )
            
            stats = {
                "total_scans": len(all_scans),
                "files_scanned": len(scans_by_type["files"]),
                "urls_scanned": len(scans_by_type["urls"]),
                "ips_scanned": len(scans_by_type["ips"]),
                "domains_scanned": len(scans_by_type["domains"]),
                "hashes_scanned": len(scans_by_type["hashes"]),
                "threats_detected": sum(1 for s in all_scans if s.threat_level in ["suspicious", "malicious"]),
                "attacks_detected": len(attacks),
                "defense_actions_taken": len(defense_actions),
                "safe_scans": sum(1 for s in all_scans if s.threat_level == "safe"),
                "suspicious_scans": sum(1 for s in all_scans if s.threat_level == "suspicious"),
                "malicious_scans": sum(1 for s in all_scans if s.threat_level == "malicious"),
                # Forensic reliability metrics
                "scans_with_forensic_data": scans_with_forensic,
                "forensic_coverage_pct": (scans_with_forensic / len(all_scans) * 100) if all_scans else 0,
                "avg_apis_per_scan": round(avg_apis_checked, 2),
                "corroborated_threats": corroborated_threats,
                "high_confidence_threats": high_confidence_threats,
                "avg_confidence": (sum(s.confidence for s in all_scans) / len(all_scans)) if all_scans else 0,
            }

            report_data[interval_key] = {
                "interval": interval.label,
                "since": since_time.isoformat(),
                "until": datetime.utcnow().isoformat(),
                "statistics": stats,
                "scans_by_type": {
                    "files": [_scan_to_dict(s) for s in scans_by_type["files"]],
                    "urls": [_scan_to_dict(s) for s in scans_by_type["urls"]],
                    "ips": [_scan_to_dict(s) for s in scans_by_type["ips"]],
                    "domains": [_scan_to_dict(s) for s in scans_by_type["domains"]],
                    "hashes": [_scan_to_dict(s) for s in scans_by_type["hashes"]],
                },
                "attacks": [_attack_to_dict(a) for a in attacks],
                "defense_actions": [_action_to_dict(a) for a in defense_actions],
            }

        # Generate report based on format
        if request.format == "json":
            return {
                "report_type": "comprehensive",
                "generated_at": datetime.utcnow().isoformat(),
                "intervals": report_data,
                "client_id": request.client_id,
            }
        elif request.format == "pdf":
            if not REPORTLAB_AVAILABLE:
                raise HTTPException(
                    status_code=500,
                    detail="ReportLab not installed. Install with: pip install reportlab",
                )

            # Generate PDF based on report type
            generated_at = datetime.utcnow()
            report_id = f"RPT_ADV_{generated_at.strftime('%Y%m%d%H%M%S')}_{uuid4().hex[:8]}"
            if request.report_type == "technical_analysis":
                pdf_bytes = await generate_technical_analysis_pdf(report_data, request)
                filename = f"security_report_technical_{generated_at.strftime('%Y%m%d_%H%M%S')}.pdf"
            else:  # executive_summary (default)
                pdf_bytes = await generate_executive_summary_pdf(report_data, request)
                filename = f"security_report_executive_{generated_at.strftime('%Y%m%d_%H%M%S')}.pdf"

            # Persist metadata so dashboard /api/reports can show recent advanced reports
            total_threats_detected = sum(
                interval_data.get("statistics", {}).get("threats_detected", 0)
                for interval_data in report_data.values()
            )
            report_meta = {
                "report_id": report_id,
                "title": f"{request.report_type.replace('_', ' ').title()} Report",
                "target": request.client_id or "all_targets",
                "type": request.report_type,
                "time_range": ", ".join(request.intervals),
                "threats_detected": total_threats_detected,
                "verdict": "safe" if total_threats_detected == 0 else "suspicious",
                "confidence": 0.9 if total_threats_detected == 0 else 0.7,
                "created": generated_at.isoformat(),
                "source": "advanced_reports",
            }
            REPORTS_STORE.append(report_meta)
            REPORTS_PDF_CACHE[report_id] = pdf_bytes

            # Keep caches bounded
            if len(REPORTS_PDF_CACHE) > 100:
                oldest_ids = sorted(REPORTS_PDF_CACHE.keys())[:-100]
                for old_id in oldest_ids:
                    REPORTS_PDF_CACHE.pop(old_id, None)

            if len(REPORTS_STORE) > 500:
                del REPORTS_STORE[:-500]

            return StreamingResponse(
                io.BytesIO(pdf_bytes),
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename={filename}"},
            )
        else:
            raise HTTPException(status_code=400, detail="Unsupported format")

    except Exception as e:
        logger.error(f"Comprehensive report generation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@router.get("/interval/{interval}")
async def get_interval_report(
    interval: str,
    target_type: Optional[str] = Query(None, description="Filter by type: file, url, ip, domain, hash"),
    format: str = Query("json", description="Response format: json or pdf"),
    client_id: Optional[str] = Query(None, description="Filter by client ID"),
    db: AsyncSession = Depends(get_db),
):
    """
    Get report for a specific time interval (24h, 7d, or 30d)
    """
    try:
        if interval not in REPORT_INTERVALS:
            raise HTTPException(
                status_code=400, detail=f"Invalid interval. Use: {', '.join(REPORT_INTERVALS.keys())}"
            )

        interval_config = REPORT_INTERVALS[interval]
        since_time = datetime.utcnow() - timedelta(hours=interval_config.hours)

        # Build query
        query = select(ScanHistory).where(ScanHistory.scan_timestamp >= since_time)

        if target_type:
            query = query.where(ScanHistory.target_type == target_type)

        if client_id:
            query = query.join(ClientInstallation).where(ClientInstallation.client_id == client_id)

        result = await db.execute(query)
        scans = result.scalars().all()

        # Calculate statistics
        stats = {
            "total_scans": len(scans),
            "safe": sum(1 for s in scans if s.threat_level == "safe"),
            "suspicious": sum(1 for s in scans if s.threat_level == "suspicious"),
            "malicious": sum(1 for s in scans if s.threat_level == "malicious"),
            "unknown": sum(1 for s in scans if s.threat_level == "unknown"),
        }

        report = {
            "interval": interval_config.label,
            "since": since_time.isoformat(),
            "until": datetime.utcnow().isoformat(),
            "filter": {"type": target_type, "client_id": client_id},
            "statistics": stats,
            "scans": [_scan_to_dict(s) for s in scans],
        }

        if format == "json":
            return report
        elif format == "pdf":
            if not REPORTLAB_AVAILABLE:
                raise HTTPException(status_code=500, detail="ReportLab not installed")

            pdf_bytes = _generate_simple_pdf(report, interval)
            filename = f"report_{interval}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"

            return StreamingResponse(
                io.BytesIO(pdf_bytes),
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename={filename}"},
            )
        else:
            raise HTTPException(status_code=400, detail="Unsupported format")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Interval report generation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# Helper functions
def _scan_to_dict(scan: ScanHistory) -> dict:
    """Convert ScanHistory object to dictionary with full details including forensic metadata"""
    analysis_data = scan.analysis_data or {}
    
    # Extract forensic metadata from multiple sources
    forensic_metadata = {}
    
    # First, try to get from analysis_data (where it's stored)
    if "forensic_metadata" in analysis_data:
        forensic_metadata = analysis_data.get("forensic_metadata", {})
    # Fallback to scan attributes
    elif hasattr(scan, 'evidence_sources') and scan.evidence_sources:
        forensic_metadata = {
            "evidence_sources": scan.evidence_sources if isinstance(scan.evidence_sources, list) else [],
            "corroboration_count": scan.corroboration_count if hasattr(scan, 'corroboration_count') else 0,
            "corroboration_threshold_met": (scan.corroboration_count >= 2) if hasattr(scan, 'corroboration_count') else False,
        }
    
    # If still empty but we have evidence_sources attribute, use it
    if not forensic_metadata and hasattr(scan, 'evidence_sources'):
        forensic_metadata = {
            "evidence_sources": scan.evidence_sources if scan.evidence_sources else [],
            "corroboration_count": scan.corroboration_count if hasattr(scan, 'corroboration_count') else 0,
            "corroboration_threshold_met": (scan.corroboration_count >= 2) if hasattr(scan, 'corroboration_count') else False,
        }
    
    # Normalize threat level and target type for report display
    threat_level = (scan.threat_level or analysis_data.get("verdict") or "unknown").lower()
    if threat_level == "clean":
        threat_level = "safe"

    target_type = (scan.target_type or analysis_data.get("input_type") or "unknown").lower()
    if target_type == "file_hash":
        target_type = "hash"

    if target_type == "unknown" and scan.target:
        try:
            from app.core.input_detector import InputDetector
            detected, _meta = InputDetector.detect(scan.target)
            target_type = detected.value
            if target_type == "file_hash":
                target_type = "hash"
        except Exception:
            pass

    return {
        "scan_id": scan.scan_id,
        "target": scan.target,
        "target_type": target_type,
        "target_name": scan.target_name,
        "threat_level": threat_level,
        "confidence": scan.confidence,
        "threats_detected": scan.threats_detected,
        "timestamp": scan.scan_timestamp.isoformat() if scan.scan_timestamp else None,
        "analysis": analysis_data,  # Full analysis data
        "forensic_metadata": forensic_metadata,  # Forensic reliability data
    }


def _attack_to_dict(attack: AttackEvent) -> dict:
    """Convert AttackEvent object to dictionary"""
    return {
        "event_id": attack.event_id,
        "attack_type": attack.attack_type,
        "source_ip": attack.source_ip,
        "severity": attack.severity.value if attack.severity else "unknown",
        "status": attack.status,
        "blocked": attack.blocked,
        "detected_at": attack.detected_at.isoformat() if attack.detected_at else None,
    }


def _action_to_dict(action: DefenseAction) -> dict:
    """Convert DefenseAction object to dictionary"""
    return {
        "action_id": action.action_id,
        "action_type": action.action_type,
        "target": action.target,
        "status": action.status,
        "successful": action.successful,
        "created_at": action.created_at.isoformat() if action.created_at else None,
    }


async def _generate_comprehensive_pdf(report_data: dict, request: AdvancedReportRequest) -> bytes:
    """Generate comprehensive PDF report with enhanced design and forensic analysis"""
    buffer = io.BytesIO()
    
    # Custom page template with footer
    def add_page_number(canvas, doc):
        """Add page number and footer to each page"""
        page_num = canvas.getPageNumber()
        text = f"Page {page_num} | SENTINELAI Comprehensive Security Report | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
        canvas.saveState()
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.HexColor("#757575"))
        canvas.drawCentredString(letter[0] / 2, 0.4 * inch, text)
        canvas.restoreState()
    
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=letter, 
        topMargin=0.75 * inch, 
        bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title",
        parent=styles["Heading1"],
        fontSize=28,
        textColor=colors.HexColor("#1a237e"),
        spaceAfter=12,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
    )
    
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=14,
        textColor=colors.HexColor("#424242"),
        spaceAfter=20,
        alignment=TA_CENTER,
        fontName="Helvetica",
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.HexColor("#0066cc"),
        spaceAfter=10,
        spaceBefore=10,
        fontName="Helvetica-Bold",
    )

    elements = []

    # Enhanced Title Page
    elements.append(Spacer(1, 1.5 * inch))
    elements.append(Paragraph("🛡️ SENTINELAI", title_style))
    elements.append(Paragraph("COMPREHENSIVE SECURITY ANALYSIS REPORT", subtitle_style))
    elements.append(Spacer(1, 0.3 * inch))
    
    # Report metadata box
    report_info = [
        ["Report Type:", "Multi-Interval Security Analysis"],
        ["Generated:", datetime.utcnow().strftime('%B %d, %Y at %H:%M:%S UTC')],
        ["Intervals Analyzed:", ", ".join(data["interval"] for data in report_data.values())],
        ["Report ID:", f"COMP-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"],
    ]
    if request.client_id:
        report_info.append(["Client ID:", request.client_id])
    
    info_table = Table(report_info, colWidths=[2 * inch, 3.5 * inch])
    info_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e3f2fd")),
        ("BACKGROUND", (1, 0), (1, -1), colors.white),
        ("ALIGN", (0, 0), (0, -1), "RIGHT"),
        ("ALIGN", (1, 0), (1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#90caf9")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 0.5 * inch))
    
    # Security notice
    notice_style = ParagraphStyle(
        "Notice",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#666666"),
        alignment=TA_CENTER,
    )
    elements.append(Paragraph(
        "<i>This report contains sensitive security information. Handle according to your organization's data classification policy.</i>",
        notice_style
    ))

    # Process each interval
    for interval_key, data in report_data.items():
        elements.append(PageBreak())
        elements.append(Paragraph(f"REPORT FOR: {data['interval'].upper()}", heading_style))
        elements.append(Spacer(1, 0.1 * inch))

        stats = data["statistics"]

        # Statistics table - Overview
        stats_data = [
            ["Metric", "Count"],
            ["Total Scans", str(stats["total_scans"])],
            ["Files Scanned", str(stats["files_scanned"])],
            ["URLs Scanned", str(stats["urls_scanned"])],
            ["IPs Scanned", str(stats["ips_scanned"])],
            ["Domains Scanned", str(stats["domains_scanned"])],
            ["Hashes Scanned", str(stats["hashes_scanned"])],
            ["", ""],  # Separator
            ["Threats Detected", str(stats["threats_detected"])],
            ["High Confidence Threats", str(stats["high_confidence_threats"])],
            ["Corroborated Threats", str(stats["corroborated_threats"])],
            ["Attacks Detected", str(stats["attacks_detected"])],
            ["Defense Actions", str(stats["defense_actions_taken"])],
        ]

        stats_table = Table(stats_data, colWidths=[3 * inch, 2 * inch])
        stats_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0066cc")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9f9f9")]),
                ]
            )
        )

        elements.append(stats_table)
        elements.append(Spacer(1, 0.2 * inch))
        
        # Forensic Reliability Metrics
        elements.append(Paragraph("Forensic Reliability & Verification:", heading_style))
        forensic_data = [
            ["Forensic Metric", "Value"],
            ["Scans with API Verification", f"{stats['scans_with_forensic_data']} ({stats['forensic_coverage_pct']:.1f}%)"],
            ["Average APIs per Scan", f"{stats['avg_apis_per_scan']:.1f}/5 APIs"],
            ["Multi-Source Corroborated", str(stats['corroborated_threats'])],
            ["Average Confidence Score", f"{stats['avg_confidence']*100:.1f}%"],
        ]
        
        forensic_table = Table(forensic_data, colWidths=[3 * inch, 2 * inch])
        forensic_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2e7d32")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#388e3c")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#e8f5e9")]),
                ]
            )
        )
        elements.append(forensic_table)
        elements.append(Spacer(1, 0.2 * inch))

        # Threat breakdown
        if stats["threats_detected"] > 0:
            elements.append(Paragraph("Threat Breakdown:", heading_style))
            threat_data = [
                ["Category", "Count"],
                ["Safe", str(stats["safe_scans"])],
                ["Suspicious", str(stats["suspicious_scans"])],
                ["Malicious", str(stats["malicious_scans"])],
            ]

            threat_table = Table(threat_data, colWidths=[3 * inch, 2 * inch])
            threat_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#cc6600")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                    ]
                )
            )
            elements.append(threat_table)
            elements.append(Spacer(1, 0.2 * inch))

        # Top threats by type
        scans_by_type = data["scans_by_type"]
        for scan_type, scans in scans_by_type.items():
            if scans and len(scans) > 0:
                elements.append(Paragraph(f"📌 {scan_type.upper()} Scan Results ({len(scans)} total):", heading_style))

                # Show top 15 malicious/suspicious with forensic data
                threat_scans = [s for s in scans if s["threat_level"] in ["suspicious", "malicious"]]
                threat_scans = sorted(threat_scans, key=lambda x: x["confidence"], reverse=True)[:15]

                if threat_scans:
                    elements.append(Paragraph(f"<b>⚠️ Threats Detected ({len(threat_scans)}):</b>", 
                        ParagraphStyle("OrangeBold", parent=styles["Normal"], textColor=colors.HexColor("#ff6f00"), fontName="Helvetica-Bold")))
                    elements.append(Spacer(1, 0.05 * inch))
                    
                    scan_data = [["Target", "Level", "Confidence", "Forensic"]]
                    for scan in threat_scans:
                        target = scan["target"][:35] + "..." if len(scan["target"]) > 35 else scan["target"]
                        
                        # Get forensic info
                        forensic = scan.get("forensic_metadata", {})
                        apis_checked = forensic.get("apis_checked", 0)
                        corr_count = forensic.get("corroboration_count", 0)
                        
                        if corr_count >= 2:
                            forensic_status = f"✓ {corr_count} APIs"
                        elif apis_checked > 0:
                            forensic_status = f"{apis_checked} API(s)"
                        else:
                            forensic_status = "No data"
                        
                        scan_data.append([
                            target, 
                            scan["threat_level"].upper()[:4], 
                            f"{scan['confidence']*100:.0f}%",
                            forensic_status
                        ])

                    scan_table = Table(scan_data, colWidths=[2.5 * inch, 0.8 * inch, 0.9 * inch, 1.3 * inch])
                    scan_table.setStyle(
                        TableStyle(
                            [
                                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d32f2f")),
                                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                                ("ALIGN", (2, 0), (2, -1), "CENTER"),
                                ("ALIGN", (3, 0), (3, -1), "CENTER"),
                                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                                ("FONTSIZE", (0, 0), (-1, -1), 8),
                                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e57373")),
                                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#ffebee")]),
                            ]
                        )
                    )
                    elements.append(scan_table)
                else:
                    elements.append(Paragraph(f"✅ No threats detected in {scan_type} scans", 
                        ParagraphStyle("GreenNormal", parent=styles["Normal"], textColor=colors.HexColor("#2e7d32"))))

                elements.append(Spacer(1, 0.15 * inch))
        
        # Add recommendations section at end of each interval
        elements.append(PageBreak())
        elements.append(Paragraph(f"🎯 SECURITY RECOMMENDATIONS - {data['interval'].upper()}", heading_style))
        elements.append(Spacer(1, 0.1 * inch))
        
        recommendations = []
        
        # Check forensic coverage
        if stats["forensic_coverage_pct"] < 50:
            recommendations.append("⚠️ <b>Low Forensic Coverage</b>: Only {:.1f}% of scans have API verification. Configure API keys (VirusTotal, URLScan, AbuseIPDB, Shodan, Hybrid Analysis) for better threat detection.".format(stats["forensic_coverage_pct"]))
        
        # Check for threats
        if stats["malicious_scans"] > 0:
            recommendations.append(f"🚨 <b>Critical</b>: {stats['malicious_scans']} malicious threats detected. Immediate investigation and remediation required.")
        
        if stats["suspicious_scans"] > 0:
            recommendations.append(f"⚠️ <b>Warning</b>: {stats['suspicious_scans']} suspicious activities detected. Review and monitor these targets closely.")
        
        # Check corroboration
        if stats["corroborated_threats"] > 0:
            recommendations.append(f"✓ <b>High Confidence</b>: {stats['corroborated_threats']} threats corroborated by multiple sources. These detections are highly reliable.")
        
        # Check average confidence
        if stats["avg_confidence"] < 0.5:
            recommendations.append("📊 <b>Low Confidence</b>: Average confidence score is {:.1f}%. Consider enabling more API sources for better accuracy.".format(stats["avg_confidence"]*100))
        
        # Good security posture
        if stats["total_scans"] > 0 and stats["safe_scans"] > stats["total_scans"] * 0.8:
            clean_pct = (stats["safe_scans"] / stats["total_scans"] * 100) if stats["total_scans"] else 0
            recommendations.append(
                f"✅ <b>Good Security Posture</b>: {clean_pct:.1f}% of scans are clean. Continue monitoring."
            )
        
        if not recommendations:
            recommendations.append("✅ <b>All Clear</b>: No critical security issues detected. Continue regular monitoring and maintain current security practices.")
        
        for rec in recommendations:
            elements.append(Paragraph(f"• {rec}", styles["Normal"]))
            elements.append(Spacer(1, 0.08 * inch))

    # Build PDF with page numbers
    doc.build(elements, onFirstPage=add_page_number, onLaterPages=add_page_number)
    buffer.seek(0)
    return buffer.read()


def _generate_simple_pdf(report: dict, interval: str) -> bytes:
    """Generate comprehensive PDF for single interval with detailed cybersecurity analysis"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=letter,
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch
    )

    styles = getSampleStyleSheet()
    elements = []
    
    # Custom styles
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Heading1"],
        fontSize=24,
        textColor=colors.HexColor("#1a237e"),
        spaceAfter=6,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
    )
    
    subtitle_style = ParagraphStyle(
        "CustomSubtitle",
        parent=styles["Normal"],
        fontSize=11,
        textColor=colors.HexColor("#424242"),
        spaceAfter=12,
        alignment=TA_CENTER,
    )
    
    heading_style = ParagraphStyle(
        "CustomHeading",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.HexColor("#1565c0"),
        spaceAfter=8,
        spaceBefore=12,
        fontName="Helvetica-Bold",
    )
    
    # Header
    elements.append(Paragraph("🛡️ SENTINELAI SECURITY REPORT", title_style))
    elements.append(Paragraph(f"Threat Analysis Report - {report['interval']}", subtitle_style))
    
    # Report metadata
    since_dt = datetime.fromisoformat(report['since'].replace('Z', '+00:00'))
    until_dt = datetime.fromisoformat(report['until'].replace('Z', '+00:00'))
    
    metadata_data = [
        ["Report Generated:", until_dt.strftime("%B %d, %Y at %H:%M:%S UTC")],
        ["Analysis Period:", f"{since_dt.strftime('%B %d, %Y %H:%M')} - {until_dt.strftime('%B %d, %Y %H:%M')}"],
        ["Time Range:", report['interval']],
        ["Report ID:", f"RPT-{interval.upper()}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"],
    ]
    
    metadata_table = Table(metadata_data, colWidths=[2*inch, 4.5*inch])
    metadata_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e3f2fd")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#212121")),
        ("ALIGN", (0, 0), (0, -1), "RIGHT"),
        ("ALIGN", (1, 0), (1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#90caf9")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(metadata_table)
    elements.append(Spacer(1, 0.3 * inch))
    
    # Executive Summary
    stats = report["statistics"]
    elements.append(Paragraph("📊 EXECUTIVE SUMMARY", heading_style))
    
    total_scans = stats["total_scans"]
    threat_percentage = (stats["malicious"] + stats["suspicious"]) / total_scans * 100 if total_scans > 0 else 0
    
    summary_text = f"""
    <para>
    This report provides a comprehensive analysis of {total_scans} security scans performed during the specified period.
    The analysis identified <b>{stats["malicious"]} malicious threats</b> and <b>{stats["suspicious"]} suspicious activities</b>,
    representing a <b>{threat_percentage:.1f}% threat detection rate</b>. 
    All threats have been categorized, analyzed, and documented below for your review and action.
    </para>
    """
    elements.append(Paragraph(summary_text, styles["Normal"]))
    elements.append(Spacer(1, 0.2 * inch))
    
    # Statistics Overview
    elements.append(Paragraph("📈 SCAN STATISTICS", heading_style))
    
    stats_data = [
        ["METRIC", "COUNT", "PERCENTAGE"],
        ["Total Scans Performed", str(total_scans), "100%"],
        ["✅ Safe (No Threats)", str(stats["safe"]), f"{stats['safe']/total_scans*100:.1f}%" if total_scans > 0 else "0%"],
        ["⚠️  Suspicious Activity", str(stats["suspicious"]), f"{stats['suspicious']/total_scans*100:.1f}%" if total_scans > 0 else "0%"],
        ["🚨 Malicious Threats", str(stats["malicious"]), f"{stats['malicious']/total_scans*100:.1f}%" if total_scans > 0 else "0%"],
        ["❓ Unknown/Unclassified", str(stats["unknown"]), f"{stats['unknown']/total_scans*100:.1f}%" if total_scans > 0 else "0%"],
    ]
    
    stats_table = Table(stats_data, colWidths=[3*inch, 1.5*inch, 2*inch])
    stats_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1565c0")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 11),
        ("FONTSIZE", (0, 1), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#1976d2")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 0.3 * inch))
    
    # Threat Classification by Scan Type
    scans = report["scans"]
    if scans:
        elements.append(Paragraph("🔍 DETAILED SCAN ANALYSIS", heading_style))
        
        # Group scans by type
        scans_by_type = {}
        for scan in scans:
            scan_type = scan.get("target_type", "unknown").upper()
            if scan_type not in scans_by_type:
                scans_by_type[scan_type] = []
            scans_by_type[scan_type].append(scan)
        
        # Scan type summary
        type_summary_data = [["SCAN TYPE", "COUNT", "THREATS", "SAFE"]]
        for scan_type, type_scans in scans_by_type.items():
            threats = sum(1 for s in type_scans if s.get("threat_level") in ["suspicious", "malicious"])
            safe = sum(1 for s in type_scans if s.get("threat_level") == "safe")
            type_summary_data.append([
                scan_type,
                str(len(type_scans)),
                str(threats),
                str(safe)
            ])
        
        type_summary_table = Table(type_summary_data, colWidths=[2*inch, 1.5*inch, 1.5*inch, 1.5*inch])
        type_summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ff6f00")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#ff8f00")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fff3e0")]),
        ]))
        elements.append(type_summary_table)
        elements.append(Spacer(1, 0.2 * inch))
        
        # Detailed threat analysis
        elements.append(Paragraph("🚨 THREAT DETAILS & CLASSIFICATION", heading_style))
        
        # Show malicious threats first
        malicious_scans = [s for s in scans if s.get("threat_level") == "malicious"]
        suspicious_scans = [s for s in scans if s.get("threat_level") == "suspicious"]
        
        if malicious_scans:
            elements.append(Paragraph("<b>CRITICAL MALICIOUS THREATS:</b>", ParagraphStyle("RedBold", parent=styles["Normal"], textColor=colors.red, fontName="Helvetica-Bold")))
            elements.append(Spacer(1, 0.1 * inch))
            
            for i, scan in enumerate(malicious_scans[:20], 1):  # Limit to 20
                threat_data = [
                    ["Scan #", str(i)],
                    ["Target URL/File", scan.get("target", "Unknown")[:100]],
                    ["Scan Type", scan.get("target_type", "Unknown").upper()],
                    ["Threat Level", "🚨 MALICIOUS"],
                    ["Confidence", f"{scan.get('confidence', 0)*100:.1f}%"],
                    ["Threats Found", str(scan.get("threats_detected", 0))],
                    ["Detected At", scan.get("timestamp", "Unknown")[:19]],
                ]
                
                # Always add forensic metadata display
                forensic = scan.get("forensic_metadata", {})
                analysis = scan.get("analysis", {})
                warnings = analysis.get("warnings", [])
                
                if forensic:
                    corr_count = forensic.get("corroboration_count", 0)
                    corr_met = forensic.get("corroboration_threshold_met", False)
                    evidence_sources = forensic.get("evidence_sources", [])
                    apis_checked = forensic.get("apis_checked", 0)
                    scan_coverage = forensic.get("scan_coverage", "")
                    
                    if corr_count > 0:
                        # Threats found and corroborated
                        threat_data.append(["Forensic Status", 
                            f"{'✓ CORROBORATED' if corr_met else '⚠ SINGLE SOURCE'} ({corr_count} source{'s' if corr_count != 1 else ''})"])
                        if evidence_sources:
                            threat_data.append(["Evidence Sources", ", ".join(evidence_sources[:5])])
                    else:
                        # No threats, but show which APIs checked it
                        if evidence_sources and len(evidence_sources) > 0:
                            threat_data.append(["Forensic Status", f"✓ VERIFIED CLEAN ({len(evidence_sources)} APIs checked)"])
                            threat_data.append(["APIs Checked", ", ".join(evidence_sources)])
                        elif apis_checked > 0:
                            threat_data.append(["Forensic Status", f"✓ VERIFIED CLEAN ({scan_coverage})"])
                        else:
                            # Check if APIs are not configured
                            if warnings and any("not configured" in w.lower() for w in warnings):
                                threat_data.append(["Forensic Status", "⚠ APIs NOT CONFIGURED"])
                                threat_data.append(["Configuration Note", "Please configure API keys (VirusTotal, URLScan, etc.) for verification"])
                            else:
                                threat_data.append(["Forensic Status", "⚠ NO API VERIFICATION"])
                else:
                    # Check if APIs are not configured from warnings
                    if warnings and any("not configured" in w.lower() for w in warnings):
                        threat_data.append(["Forensic Status", "⚠ APIs NOT CONFIGURED"])
                        threat_data.append(["Configuration Note", "Please configure API keys for threat verification"])
                    else:
                        threat_data.append(["Forensic Status", "⚠ FORENSIC DATA NOT AVAILABLE"])
                
                # Add analysis details if available
                analysis = scan.get("analysis", {})
                if analysis:
                    if "malware_families" in analysis:
                        threat_data.append(["Malware Type", ", ".join(analysis["malware_families"][:3])])
                    if "attack_type" in analysis:
                        threat_data.append(["Attack Type", analysis["attack_type"]])
                    if "risk_score" in analysis:
                        threat_data.append(["Risk Score", f"{analysis['risk_score']}/100"])
                
                threat_table = Table(threat_data, colWidths=[1.5*inch, 5*inch])
                threat_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ffebee")),
                    ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#ffcdd2")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#212121")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.red),
                    ("ALIGN", (0, 0), (0, -1), "RIGHT"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                elements.append(threat_table)
                elements.append(Spacer(1, 0.15 * inch))
        
        if suspicious_scans:
            elements.append(Paragraph("<b>SUSPICIOUS ACTIVITIES:</b>", ParagraphStyle("OrangeBold", parent=styles["Normal"], textColor=colors.HexColor("#ff6f00"), fontName="Helvetica-Bold")))
            elements.append(Spacer(1, 0.1 * inch))
            
            for i, scan in enumerate(suspicious_scans[:15], 1):  # Limit to 15
                susp_data = [
                    ["Scan #", str(i)],
                    ["Target URL/File", scan.get("target", "Unknown")[:100]],
                    ["Scan Type", scan.get("target_type", "Unknown").upper()],
                    ["Threat Level", "⚠️  SUSPICIOUS"],
                    ["Confidence", f"{scan.get('confidence', 0)*100:.1f}%"],
                    ["Threats Found", str(scan.get("threats_detected", 0))],
                    ["Detected At", scan.get("timestamp", "Unknown")[:19]],
                ]
                
                # Always add forensic metadata display
                forensic = scan.get("forensic_metadata", {})
                analysis = scan.get("analysis", {})
                warnings = analysis.get("warnings", [])
                
                if forensic:
                    corr_count = forensic.get("corroboration_count", 0)
                    corr_met = forensic.get("corroboration_threshold_met", False)
                    evidence_sources = forensic.get("evidence_sources", [])
                    apis_checked = forensic.get("apis_checked", 0)
                    scan_coverage = forensic.get("scan_coverage", "")
                    
                    if corr_count > 0:
                        # Threats found and corroborated
                        susp_data.append(["Forensic Status", 
                            f"{'✓ CORROBORATED' if corr_met else '⚠ SINGLE SOURCE'} ({corr_count} source{'s' if corr_count != 1 else ''})"])
                        if evidence_sources:
                            susp_data.append(["Evidence Sources", ", ".join(evidence_sources[:5])])
                    else:
                        # No threats, but show which APIs checked it
                        if evidence_sources and len(evidence_sources) > 0:
                            susp_data.append(["Forensic Status", f"✓ VERIFIED CLEAN ({len(evidence_sources)} APIs checked)"])
                            susp_data.append(["APIs Checked", ", ".join(evidence_sources)])
                        elif apis_checked > 0:
                            susp_data.append(["Forensic Status", f"✓ VERIFIED CLEAN ({scan_coverage})"])
                        else:
                            # Check if APIs are not configured
                            if warnings and any("not configured" in w.lower() for w in warnings):
                                susp_data.append(["Forensic Status", "⚠ APIs NOT CONFIGURED"])
                                susp_data.append(["Configuration Note", "Please configure API keys (VirusTotal, URLScan, etc.) for verification"])
                            else:
                                susp_data.append(["Forensic Status", "⚠ NO API VERIFICATION"])
                else:
                    # Check if APIs are not configured from warnings
                    if warnings and any("not configured" in w.lower() for w in warnings):
                        susp_data.append(["Forensic Status", "⚠ APIs NOT CONFIGURED"])
                        susp_data.append(["Configuration Note", "Please configure API keys for threat verification"])
                    else:
                        susp_data.append(["Forensic Status", "⚠ FORENSIC DATA NOT AVAILABLE"])
                
                susp_table = Table(susp_data, colWidths=[1.5*inch, 5*inch])
                susp_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#fff8e1")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#ff8f00")),
                    ("ALIGN", (0, 0), (0, -1), "RIGHT"),
                ]))
                elements.append(susp_table)
                elements.append(Spacer(1, 0.1 * inch))
        
        # Safe scans summary
        safe_scans = [s for s in scans if s.get("threat_level") == "safe"]
        if safe_scans:
            elements.append(Paragraph("<b>✅ SAFE SCANS:</b>", ParagraphStyle("GreenBold", parent=styles["Normal"], textColor=colors.HexColor("#2e7d32"), fontName="Helvetica-Bold")))
            elements.append(Paragraph(f"{len(safe_scans)} target(s) were scanned and found to be safe with no threats detected.", styles["Normal"]))
            elements.append(Spacer(1, 0.1 * inch))
            
            # Show first 10 safe scans with details
            for i, scan in enumerate(safe_scans[:10], 1):
                safe_data = [
                    ["Scan #", str(i)],
                    ["Target URL/File", scan.get("target", "Unknown")[:100]],
                    ["Scan Type", scan.get("target_type", "Unknown").upper()],
                    ["Status", "✅ SAFE - No Threats"],
                    ["Confidence", f"{scan.get('confidence', 0)*100:.1f}%"],
                    ["Scanned At", scan.get("timestamp", "Unknown")[:19]],
                ]
                
                # Add forensic status for safe scans too
                forensic = scan.get("forensic_metadata", {})
                analysis = scan.get("analysis", {})
                warnings = analysis.get("warnings", [])
                
                if forensic:
                    corr_count = forensic.get("corroboration_count", 0)
                    evidence_sources = forensic.get("evidence_sources", [])
                    apis_checked = forensic.get("apis_checked", 0)
                    scan_coverage = forensic.get("scan_coverage", "")
                    
                    # For safe scans, show which APIs verified it
                    if evidence_sources and len(evidence_sources) > 0:
                        safe_data.append(["Forensic Status", f"✓ VERIFIED SAFE ({len(evidence_sources)} APIs)"])
                        safe_data.append(["APIs Checked", ", ".join(evidence_sources)])
                    elif apis_checked > 0:
                        safe_data.append(["Forensic Status", f"✓ VERIFIED ({scan_coverage})"])
                    else:
                        # Check if APIs are not configured
                        if warnings and any("not configured" in w.lower() for w in warnings):
                            safe_data.append(["Forensic Status", "⚠ APIs NOT CONFIGURED"])
                            safe_data.append(["Configuration Note", "Configure API keys for full verification"])
                        else:
                            safe_data.append(["Forensic Status", "⚠ LIMITED VERIFICATION"])
                else:
                    # Check if APIs are not configured from warnings
                    if warnings and any("not configured" in w.lower() for w in warnings):
                        safe_data.append(["Forensic Status", "⚠ APIs NOT CONFIGURED"])
                        safe_data.append(["Configuration Note", "Configure API keys for verification"])
                    else:
                        safe_data.append(["Forensic Status", "⚠ NO VERIFICATION DATA"])
                
                safe_table = Table(safe_data, colWidths=[1.5*inch, 5*inch])
                safe_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8f5e9")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#4caf50")),
                    ("ALIGN", (0, 0), (0, -1), "RIGHT"),
                ]))
                elements.append(safe_table)
                elements.append(Spacer(1, 0.1 * inch))
            
            if len(safe_scans) > 10:
                elements.append(Paragraph(f"<i>... and {len(safe_scans) - 10} more safe scan(s).</i>", styles["Normal"]))
                elements.append(Spacer(1, 0.1 * inch))
    
    # Recommendations
    elements.append(Paragraph("💡 SECURITY RECOMMENDATIONS", heading_style))
    
    recommendations = []
    if stats["malicious"] > 0:
        recommendations.append("• <b>IMMEDIATE ACTION REQUIRED:</b> Quarantine and remove all malicious threats identified in this report.")
        recommendations.append("• Conduct a full system audit on affected machines.")
    if stats["suspicious"] > 0:
        recommendations.append("• Investigate all suspicious activities for potential false positives.")
        recommendations.append("• Implement additional monitoring on flagged resources.")
    if stats["malicious"] == 0 and stats["suspicious"] == 0:
        recommendations.append("• No immediate threats detected. Continue regular security monitoring.")
    
    recommendations.append("• Keep all security software and definitions up to date.")
    recommendations.append("• Schedule regular security scans based on the interval analyzed.")
    recommendations.append("• Review and update security policies based on findings.")
    
    for rec in recommendations:
        elements.append(Paragraph(rec, styles["Normal"]))
        elements.append(Spacer(1, 0.05 * inch))
    
    elements.append(Spacer(1, 0.2 * inch))
    
    # Add Threat Taxonomy Section
    if malicious_scans or suspicious_scans:
        elements.append(PageBreak())
        elements.append(Paragraph("🔬 THREAT TAXONOMY & CLASSIFICATION", heading_style))
        elements.append(Spacer(1, 0.1 * inch))
        
        # Categorize threats by type
        threat_categories = {}
        all_threats = malicious_scans + suspicious_scans
        
        for threat in all_threats:
            analysis = threat.get("analysis", {})
            target_type = threat.get("target_type", "unknown").upper()
            
            if target_type not in threat_categories:
                threat_categories[target_type] = {
                    "count": 0,
                    "malware_families": set(),
                    "attack_types": set(),
                    "threat_names": []
                }
            
            threat_categories[target_type]["count"] += 1
            
            # Extract threat details
            if "malware_families" in analysis:
                threat_categories[target_type]["malware_families"].update(analysis["malware_families"])
            if "attack_type" in analysis:
                threat_categories[target_type]["attack_types"].add(analysis["attack_type"])
            if "threats_detected" in threat and threat["threats_detected"]:
                threat_categories[target_type]["threat_names"].append(threat.get("target_name", "Unknown"))
        
        # Create taxonomy table
        taxonomy_data = [["Category", "Count", "Malware Families", "Attack Types"]]
        
        for cat, details in sorted(threat_categories.items()):
            malware = ", ".join(list(details["malware_families"])[:5]) if details["malware_families"] else "N/A"
            attacks = ", ".join(list(details["attack_types"])[:3]) if details["attack_types"] else "N/A"
            taxonomy_data.append([
                cat,
                str(details["count"]),
                malware[:50] + "..." if len(malware) > 50 else malware,
                attacks[:50] + "..." if len(attacks) > 50 else attacks
            ])
        
        taxonomy_table = Table(taxonomy_data, colWidths=[1.2*inch, 0.8*inch, 2.2*inch, 2.3*inch])
        taxonomy_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#311b92")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#512da8")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#ede7f6")]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elements.append(taxonomy_table)
        elements.append(Spacer(1, 0.2 * inch))
        
        # Add Attack Vector Analysis
        elements.append(Paragraph("🎯 ATTACK VECTOR ANALYSIS", heading_style))
        elements.append(Spacer(1, 0.1 * inch))
        
        vector_info = f"""
        <para>
        <b>Primary Attack Vectors Identified:</b><br/>
        • Network-based attacks: {len([t for t in all_threats if t.get('target_type') in ['ip', 'domain']])} incidents<br/>
        • Web-based attacks: {len([t for t in all_threats if t.get('target_type') == 'url'])} incidents<br/>
        • File-based attacks: {len([t for t in all_threats if t.get('target_type') in ['file', 'hash']])} incidents<br/>
        <br/>
        <b>Common Attack Patterns:</b><br/>
        • Port scanning and reconnaissance attempts<br/>
        • SQL injection and web application exploitation<br/>
        • Malware delivery through file downloads<br/>
        • Phishing and social engineering attempts<br/>
        </para>
        """
        elements.append(Paragraph(vector_info, styles["Normal"]))
        elements.append(Spacer(1, 0.2 * inch))
        
        # Add Mitigation Strategies
        elements.append(Paragraph("🛡️ DETAILED MITIGATION STRATEGIES", heading_style))
        elements.append(Spacer(1, 0.1 * inch))
        
        mitigation_data = [
            ["Threat Type", "Priority", "Mitigation Actions"],
            [
                "Malicious Files",
                "CRITICAL",
                "• Quarantine immediately\n• Update antivirus signatures\n• Scan all connected systems\n• Review download policies"
            ],
            [
                "Suspicious URLs",
                "HIGH",
                "• Block at firewall/proxy level\n• Update DNS blacklists\n• Educate users on phishing\n• Implement URL filtering"
            ],
            [
                "Malicious IPs",
                "CRITICAL",
                "• Block at firewall immediately\n• Update IPS/IDS rules\n• Monitor for lateral movement\n• Review access logs"
            ],
            [
                "Suspicious Network Activity",
                "HIGH",
                "• Enable enhanced monitoring\n• Review firewall rules\n• Implement rate limiting\n• Deploy honeypots if needed"
            ]
        ]
        
        mitigation_table = Table(mitigation_data, colWidths=[1.5*inch, 1*inch, 4*inch])
        mitigation_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b5e20")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#388e3c")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#e8f5e9")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (1, 1), (1, -1), "CENTER"),
        ]))
        elements.append(mitigation_table)
        elements.append(Spacer(1, 0.2 * inch))
    
    # Footer
    footer_style = ParagraphStyle(
        "Footer",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.HexColor("#757575"),
        alignment=TA_CENTER,
    )
    elements.append(Paragraph("=" * 80, footer_style))
    elements.append(Paragraph("SentinelAI - Advanced Threat Detection & Analysis System", footer_style))
    elements.append(Paragraph(f"Report Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | Confidential", footer_style))

    doc.build(elements)
    buffer.seek(0)
    return buffer.read()
