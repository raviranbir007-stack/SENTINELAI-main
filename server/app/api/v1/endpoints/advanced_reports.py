"""
Advanced Reporting Endpoints
Generates structured reports for multiple time intervals (24h, 7d, 30d)
"""

import io
import logging
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import and_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ....database import get_db
from ....models import (
    AttackEvent,
    ClientInstallation,
    DefenseAction,
    ScanHistory,
    ThreatSeverity,
)

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


@router.post("/generate-comprehensive")
async def generate_comprehensive_report(
    request: AdvancedReportRequest, db: AsyncSession = Depends(get_db)
):
    """
    Generate comprehensive security report across multiple time intervals
    Includes all scans (files, URLs, IPs, domains, hashes), attacks, and defense actions
    """
    try:
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

            pdf_bytes = await _generate_comprehensive_pdf(report_data, request)

            filename = f"security_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"

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
    """Convert ScanHistory object to dictionary with full details"""
    analysis_data = scan.analysis_data or {}
    
    return {
        "scan_id": scan.scan_id,
        "target": scan.target,
        "target_type": scan.target_type,
        "target_name": scan.target_name,
        "threat_level": scan.threat_level,
        "confidence": scan.confidence,
        "threats_detected": scan.threats_detected,
        "timestamp": scan.scan_timestamp.isoformat() if scan.scan_timestamp else None,
        "analysis": analysis_data,  # Full analysis data
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
    """Generate comprehensive PDF report"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5 * inch, bottomMargin=0.5 * inch)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title",
        parent=styles["Heading1"],
        fontSize=20,
        textColor=colors.HexColor("#1a1a1a"),
        spaceAfter=12,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
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

    # Title
    elements.append(Paragraph("COMPREHENSIVE SECURITY REPORT", title_style))
    elements.append(
        Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles["Normal"])
    )
    if request.client_id:
        elements.append(Paragraph(f"Client ID: {request.client_id}", styles["Normal"]))
    elements.append(Spacer(1, 0.3 * inch))

    # Process each interval
    for interval_key, data in report_data.items():
        elements.append(PageBreak())
        elements.append(Paragraph(f"REPORT FOR: {data['interval'].upper()}", heading_style))
        elements.append(Spacer(1, 0.1 * inch))

        stats = data["statistics"]

        # Statistics table
        stats_data = [
            ["Metric", "Count"],
            ["Total Scans", str(stats["total_scans"])],
            ["Files Scanned", str(stats["files_scanned"])],
            ["URLs Scanned", str(stats["urls_scanned"])],
            ["IPs Scanned", str(stats["ips_scanned"])],
            ["Domains Scanned", str(stats["domains_scanned"])],
            ["Hashes Scanned", str(stats["hashes_scanned"])],
            ["Threats Detected", str(stats["threats_detected"])],
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
                elements.append(Paragraph(f"{scan_type.upper()} Scans:", heading_style))

                # Show top 10 malicious/suspicious
                threat_scans = [s for s in scans if s["threat_level"] in ["suspicious", "malicious"]]
                threat_scans = sorted(threat_scans, key=lambda x: x["confidence"], reverse=True)[:10]

                if threat_scans:
                    scan_data = [["Target", "Threat Level", "Confidence"]]
                    for scan in threat_scans:
                        target = scan["target"][:40] + "..." if len(scan["target"]) > 40 else scan["target"]
                        scan_data.append([target, scan["threat_level"].upper(), f"{scan['confidence']:.2f}"])

                    scan_table = Table(scan_data, colWidths=[3 * inch, 1.5 * inch, 1.5 * inch])
                    scan_table.setStyle(
                        TableStyle(
                            [
                                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#cc0000")),
                                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                                ("FONTSIZE", (0, 0), (-1, -1), 9),
                                ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                            ]
                        )
                    )
                    elements.append(scan_table)
                else:
                    elements.append(Paragraph(f"No threats detected in {scan_type}", styles["Normal"]))

                elements.append(Spacer(1, 0.1 * inch))

    # Build PDF
    doc.build(elements)
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
                    ["Threat #", str(i)],
                    ["Target", scan.get("target", "Unknown")[:80]],
                    ["Type", scan.get("target_type", "Unknown").upper()],
                    ["Threat Level", "🚨 MALICIOUS"],
                    ["Confidence", f"{scan.get('confidence', 0)*100:.1f}%"],
                    ["Threats Found", str(scan.get("threats_detected", 0))],
                    ["Detected At", scan.get("timestamp", "Unknown")[:19]],
                ]
                
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
                    ["Activity #", str(i)],
                    ["Target", scan.get("target", "Unknown")[:80]],
                    ["Type", scan.get("target_type", "Unknown").upper()],
                    ["Threat Level", "⚠️  SUSPICIOUS"],
                    ["Confidence", f"{scan.get('confidence', 0)*100:.1f}%"],
                    ["Detected At", scan.get("timestamp", "Unknown")[:19]],
                ]
                
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
            elements.append(Paragraph(f"<b>✅ SAFE SCANS:</b> {len(safe_scans)} targets were scanned and found to be safe with no threats detected.", styles["Normal"]))
            elements.append(Spacer(1, 0.2 * inch))
    
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
    buffer.seek(0)
    return buffer.read()
