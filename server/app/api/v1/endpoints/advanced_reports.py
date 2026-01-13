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
    """Convert ScanHistory object to dictionary"""
    return {
        "scan_id": scan.scan_id,
        "target": scan.target,
        "target_type": scan.target_type,
        "target_name": scan.target_name,
        "threat_level": scan.threat_level,
        "confidence": scan.confidence,
        "threats_detected": scan.threats_detected,
        "timestamp": scan.scan_timestamp.isoformat() if scan.scan_timestamp else None,
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
    """Generate simple PDF for single interval"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)

    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph(f"Security Report - {report['interval']}", styles["Title"]))
    elements.append(Paragraph(f"Period: {report['since']} to {report['until']}", styles["Normal"]))
    elements.append(Spacer(1, 0.2 * inch))

    # Statistics
    stats = report["statistics"]
    elements.append(Paragraph("Statistics:", styles["Heading2"]))

    stats_data = [
        ["Total Scans", str(stats["total_scans"])],
        ["Safe", str(stats["safe"])],
        ["Suspicious", str(stats["suspicious"])],
        ["Malicious", str(stats["malicious"])],
        ["Unknown", str(stats["unknown"])],
    ]

    stats_table = Table(stats_data)
    stats_table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 1, colors.black)]))
    elements.append(stats_table)

    doc.build(elements)
    buffer.seek(0)
    return buffer.read()
