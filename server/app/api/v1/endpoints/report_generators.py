"""
Report Type Generators for Advanced Reporting
Generates Executive Summary and Technical Analysis reports
"""

import io
from datetime import datetime
from typing import Dict, Any, List

from app.gemini_integration import get_gemini_client

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


async def generate_executive_summary_pdf(report_data: Dict[str, Any], request: Any) -> bytes:
    """
    Generate Executive Summary Report
    High-level overview suitable for management and decision makers
    Focus on key metrics, trends, and actionable recommendations
    """
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("ReportLab not installed")
    
    buffer = io.BytesIO()
    
    def add_page_number(canvas, doc):
        """Add page number and footer to each page"""
        page_num = canvas.getPageNumber()
        text = f"Page {page_num} | SentinelAI Executive Summary Report | {datetime.utcnow().strftime('%Y-%m-%d')}"
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
    
    # Title Page
    elements.append(Spacer(1, 1.5 * inch))
    elements.append(Paragraph("🛡️ SENTINELAI", title_style))
    elements.append(Paragraph("EXECUTIVE SUMMARY REPORT", subtitle_style))
    elements.append(Spacer(1, 0.3 * inch))
    
    # Report metadata
    report_info = [
        ["Report Type:", "Executive Summary"],
        ["Generated:", datetime.utcnow().strftime('%B %d, %Y at %H:%M:%S UTC')],
        ["Intervals Covered:", ", ".join(data["interval"] for data in report_data.values())],
        ["Report ID:", f"EXEC-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"],
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
        "<i>This report contains sensitive security information. Treat as confidential and distribute only to authorized personnel.</i>",
        notice_style
    ))
    
    # EXECUTIVE OVERVIEW
    elements.append(PageBreak())
    elements.append(Paragraph("EXECUTIVE OVERVIEW", heading_style))
    elements.append(Spacer(1, 0.1 * inch))
    
    # Calculate aggregated metrics across all intervals
    total_scans = sum(data["statistics"]["total_scans"] for data in report_data.values())
    total_threats = sum(data["statistics"]["threats_detected"] for data in report_data.values())
    total_safe = sum(data["statistics"]["safe_scans"] for data in report_data.values())
    total_suspicious = sum(data["statistics"]["suspicious_scans"] for data in report_data.values())
    total_malicious = sum(data["statistics"]["malicious_scans"] for data in report_data.values())
    total_attacks = sum(data["statistics"]["attacks_detected"] for data in report_data.values())
    total_corroborated = sum(data["statistics"]["corroborated_threats"] for data in report_data.values())
    
    # Summary paragraph
    threat_status = "CLEAN" if total_threats == 0 else ("MALICIOUS DETECTED" if total_malicious > 0 else "SUSPICIOUS DETECTED")
    
    safe_pct = (total_safe / total_scans * 100) if total_scans else 0
    threat_pct = (total_threats / total_scans * 100) if total_scans else 0

    summary_text = f"""
Over the reporting period, {total_scans} security scans were performed across your infrastructure. 
Overall Assessment: <b>{threat_status}</b><br/>
<br/>
Key Findings:<br/>
• {total_safe} scans returned clean ({safe_pct:.1f}%)<br/>
• {total_threats} potential threats detected ({threat_pct:.1f}%)<br/>
• {total_malicious} confirmed malicious detections<br/>
• {total_corroborated} threats verified by multiple security sources<br/>
• {total_attacks} attack events detected and logged<br/>
<br/>
<b>Risk Level:</b> {_calculate_risk_level(total_scans, total_malicious, total_corroborated)}<br/>
"""
    
    elements.append(Paragraph(summary_text, styles["Normal"]))
    elements.append(Spacer(1, 0.2 * inch))
    
    # KEY METRICS AT A GLANCE
    elements.append(Paragraph("KEY METRICS AT A GLANCE", heading_style))
    elements.append(Spacer(1, 0.1 * inch))
    
    metrics_data = [
        ["Metric", "Count", "Status"],
        ["Total Scans Performed", str(total_scans), "✓"],
        ["Clean Scans", str(total_safe), "✓"],
        ["Suspicious Items", str(total_suspicious), "⚠" if total_suspicious > 0 else "✓"],
        ["Malicious Items", str(total_malicious), "🔴" if total_malicious > 0 else "✓"],
        ["Corroborated Threats", str(total_corroborated), "✓"],
        ["Attack Events", str(total_attacks), "⚠" if total_attacks > 0 else "✓"],
    ]
    
    metrics_table = Table(metrics_data, colWidths=[2.5 * inch, 1.5 * inch, 1 * inch])
    metrics_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("ALIGN", (2, 0), (2, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
    ]))
    elements.append(metrics_table)
    elements.append(Spacer(1, 0.3 * inch))

    # FORENSIC POSTURE SUMMARY (Executive-focused)
    total_scans_with_forensic = sum(data["statistics"].get("scans_with_forensic_data", 0) for data in report_data.values())
    avg_coverage = (total_scans_with_forensic / total_scans * 100) if total_scans else 0
    avg_apis = (
        sum(data["statistics"].get("avg_apis_per_scan", 0) * data["statistics"].get("total_scans", 0) for data in report_data.values())
        / max(total_scans, 1)
    )

    if avg_coverage >= 80 and avg_apis >= 3:
        posture = "HARDENED"
    elif avg_coverage >= 60 and avg_apis >= 2:
        posture = "STRONG"
    elif avg_coverage >= 40:
        posture = "MODERATE"
    else:
        posture = "LIMITED"

    elements.append(Paragraph("FORENSIC POSTURE SUMMARY", heading_style))
    elements.append(Spacer(1, 0.05 * inch))
    elements.append(Paragraph(
        f"Current forensic posture is assessed as <b>{posture}</b>. "
        f"Evidence coverage spans <b>{avg_coverage:.1f}%</b> of scans with an average of "
        f"<b>{avg_apis:.1f}</b> API check(s) per scan. "
        f"Corroborated threats recorded: <b>{total_corroborated}</b>.",
        styles["Normal"],
    ))
    elements.append(Spacer(1, 0.2 * inch))
    
    # TIMELINE ANALYSIS
    elements.append(Paragraph("TIMELINE ANALYSIS", heading_style))
    elements.append(Spacer(1, 0.1 * inch))
    
    timeline_data = [["Period", "Scans", "Threats", "Attacks", "Risk Level"]]
    for interval_key, data in report_data.items():
        stats = data["statistics"]
        risk = _calculate_risk_level(stats["total_scans"], stats["malicious_scans"], stats["corroborated_threats"])
        timeline_data.append([
            data["interval"],
            str(stats["total_scans"]),
            str(stats["threats_detected"]),
            str(stats["attacks_detected"]),
            risk
        ])
    
    timeline_table = Table(timeline_data, colWidths=[1.5 * inch, 1 * inch, 1 * inch, 1 * inch, 1.5 * inch])
    timeline_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0066cc")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9f9f9")]),
    ]))
    elements.append(timeline_table)
    elements.append(Spacer(1, 0.3 * inch))

    # POINT-IN-TIME SUMMARY
    temporal = _get_temporal_stats(report_data)
    elements.append(Paragraph("POINT-IN-TIME SUMMARY", heading_style))
    elements.append(Spacer(1, 0.1 * inch))
    elements.append(Paragraph(
        f"Captured scan evidence between <b>{temporal['first_seen']}</b> and <b>{temporal['last_seen']}</b>. "
        f"Total scan events recorded: <b>{temporal['total_scans']}</b> across <b>{temporal['intervals']}</b> interval(s).",
        styles["Normal"],
    ))
    elements.append(Spacer(1, 0.2 * inch))
    
    # THREAT DISTRIBUTION
    if total_threats > 0:
        elements.append(Paragraph("THREAT DISTRIBUTION BY CATEGORY", heading_style))
        elements.append(Spacer(1, 0.1 * inch))
        
        threat_dist_data = [["Category", "Count", "Percentage"]]
        
        for interval_key, data in report_data.items():
            stats = data["statistics"]
            if stats["total_scans"] > 0:
                threat_dist_data.append([
                    f"{data['interval']} - Safe",
                    str(stats["safe_scans"]),
                    f"{stats['safe_scans']/stats['total_scans']*100:.1f}%"
                ])
                threat_dist_data.append([
                    f"{data['interval']} - Suspicious",
                    str(stats["suspicious_scans"]),
                    f"{stats['suspicious_scans']/stats['total_scans']*100:.1f}%"
                ])
                threat_dist_data.append([
                    f"{data['interval']} - Malicious",
                    str(stats["malicious_scans"]),
                    f"{stats['malicious_scans']/stats['total_scans']*100:.1f}%"
                ])
        
        threat_dist_table = Table(threat_dist_data, colWidths=[2.5 * inch, 1.5 * inch, 1.5 * inch])
        threat_dist_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#cc6600")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ALIGN", (1, 0), (-1, 0), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 1, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fff3e0")]),
        ]))
        elements.append(threat_dist_table)
        elements.append(Spacer(1, 0.3 * inch))

    # IOC SUMMARY
    elements.append(Paragraph("IOC SUMMARY", heading_style))
    elements.append(Spacer(1, 0.1 * inch))
    ioc_summary = _get_ioc_summary(report_data)
    if ioc_summary["items"]:
        for item in ioc_summary["items"]:
            elements.append(Paragraph(f"• {item}", styles["Normal"]))
    else:
        elements.append(Paragraph("No high-confidence IOCs were identified in this period.", styles["Normal"]))
    elements.append(Spacer(1, 0.2 * inch))

    # SCAN CARDS (SAFE / SUSPICIOUS / MALICIOUS)
    elements.append(Paragraph("SCAN DETAILS (SAFE / SUSPICIOUS / MALICIOUS)", heading_style))
    elements.append(Spacer(1, 0.1 * inch))
    all_scans = _collect_scans(report_data)
    if all_scans:
        # Keep ordering by timestamp for readability
        def _ts_key(s):
            return s.get("timestamp") or ""

        all_scans_sorted = sorted(all_scans, key=_ts_key)
        elements.extend(_build_scan_cards(all_scans_sorted, styles, colors))
    else:
        elements.append(Paragraph("No scans recorded for this period.", styles["Normal"]))
        elements.append(Spacer(1, 0.2 * inch))
    
    # RECOMMENDATIONS & ACTIONS
    elements.append(PageBreak())
    elements.append(Paragraph("RECOMMENDATIONS & ACTION ITEMS", heading_style))
    elements.append(Spacer(1, 0.1 * inch))
    
    recommendations = []
    if total_malicious > 0:
        recommendations.append("🔴 <b>CRITICAL:</b> Review all malicious detections immediately. Implement incident response procedures.")
    
    if total_corroborated > 0:
        recommendations.append(f"⚠ <b>HIGH PRIORITY:</b> {total_corroborated} threats have been corroborated by multiple sources. These require immediate investigation.")
    
    if total_attacks > 0:
        recommendations.append(f"⚠ <b>ACTION REQUIRED:</b> {total_attacks} attack events detected. Review defense logs and firewall rules.")
    
    if total_suspicious > 0:
        recommendations.append(f"📊 <b>REVIEW:</b> {total_suspicious} suspicious items detected. Consider manual review for suspicious items.")
    
    if total_scans > 0 and (total_safe / total_scans) > 0.95:
        recommendations.append("✅ <b>GOOD:</b> Over 95% of scans returned clean. Security posture is strong.")
    
    if not recommendations:
        recommendations.append("✅ <b>STATUS:</b> All systems clean. Continue regular monitoring and maintain current security practices.")
    
    for rec in recommendations:
        elements.append(Paragraph(f"• {rec}", styles["Normal"]))
        elements.append(Spacer(1, 0.1 * inch))

    # CHAIN OF CUSTODY & E-DISCOVERY
    elements.append(Paragraph("CHAIN OF CUSTODY & E-DISCOVERY", heading_style))
    elements.append(Spacer(1, 0.1 * inch))
    elements.append(Paragraph(
        "Each scan is stored with a unique scan ID, timestamps, evidence sources, and analyst verification fields. "
        "This preserves provenance for audit trails, point-in-time review, and e-discovery workflows.",
        styles["Normal"],
    ))

    # FORENSIC NARRATIVE SUMMARY
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(Paragraph("FORENSIC NARRATIVE SUMMARY", heading_style))
    elements.append(Spacer(1, 0.1 * inch))
    narrative = (
        "SENTINEL-AI orchestrates multiple intelligence sources to reduce single-source bias, "
        "corroborate indicators, and preserve a time-bound record of findings. Confidence scores reflect "
        "evidence convergence rather than probability. Temporal changes are highlighted to explain SAFE→MALICIOUS "
        "contradictions and support investigative reasoning."
    )
    elements.append(Paragraph(narrative, styles["Normal"]))
    
    # CONCLUSION
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(Paragraph("CONCLUSION", heading_style))
    elements.append(Spacer(1, 0.1 * inch))
    
    conclusion_text = f"""
Based on analysis of {total_scans} security scans across {len(report_data)} reporting periods, 
your security infrastructure shows <b>{_get_health_status(total_scans, total_malicious, total_corroborated)}</b> status.<br/>
<br/>
{_get_conclusion_text(total_scans, total_threats, total_malicious, total_corroborated)}<br/>
<br/>
Continue monitoring systems regularly and update security policies based on detected threats.
"""
    
    elements.append(Paragraph(conclusion_text, styles["Normal"]))
    elements.append(Spacer(1, 0.3 * inch))
    
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
    elements.append(Paragraph(f"Executive Summary Report | Confidential - For Authorized Use Only", footer_style))
    
    doc.build(elements, onFirstPage=add_page_number, onLaterPages=add_page_number)
    buffer.seek(0)
    return buffer.read()


async def generate_technical_analysis_pdf(report_data: Dict[str, Any], request: Any) -> bytes:
    """
    Generate Technical Analysis Report
    Detailed technical information for security teams
    Focus on specific indicators, API results, forensic data, and technical recommendations
    """
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("ReportLab not installed")
    
    buffer = io.BytesIO()
    
    def add_page_number(canvas, doc):
        """Add page number and footer to each page"""
        page_num = canvas.getPageNumber()
        text = f"Page {page_num} | SentinelAI Technical Analysis Report | {datetime.utcnow().strftime('%Y-%m-%d')}"
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
        textColor=colors.HexColor("#d32f2f"),
        spaceAfter=10,
        spaceBefore=10,
        fontName="Helvetica-Bold",
    )
    
    elements = []
    
    # Title Page
    elements.append(Spacer(1, 1.5 * inch))
    elements.append(Paragraph("🛡️ SENTINELAI", title_style))
    elements.append(Paragraph("TECHNICAL ANALYSIS REPORT", subtitle_style))
    elements.append(Spacer(1, 0.3 * inch))
    
    # Report metadata
    report_info = [
        ["Report Type:", "Technical Analysis"],
        ["Generated:", datetime.utcnow().strftime('%B %d, %Y at %H:%M:%S UTC')],
        ["Intervals Covered:", ", ".join(data["interval"] for data in report_data.values())],
        ["Report ID:", f"TECH-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"],
    ]
    if request.client_id:
        report_info.append(["Client ID:", request.client_id])
    
    info_table = Table(report_info, colWidths=[2 * inch, 3.5 * inch])
    info_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ffebee")),
        ("BACKGROUND", (1, 0), (1, -1), colors.white),
        ("ALIGN", (0, 0), (0, -1), "RIGHT"),
        ("ALIGN", (1, 0), (1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#ef9a9a")),
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
        "<i>This is a technical report containing detailed security analysis. Intended for security professionals and infrastructure teams only.</i>",
        notice_style
    ))

    # Gemini AI Technical Insights (if available)
    ai_insights = await _generate_gemini_technical_insights(report_data)
    if ai_insights:
        elements.append(PageBreak())
        elements.append(Paragraph("AI-ASSISTED TECHNICAL INSIGHTS", heading_style))
        elements.append(Spacer(1, 0.1 * inch))
        elements.append(Paragraph(ai_insights.replace("\n", "<br/>") , styles["Normal"]))
        elements.append(Spacer(1, 0.2 * inch))
    
    # For each interval, generate detailed analysis
    for interval_key, data in report_data.items():
        elements.append(PageBreak())
        elements.append(Paragraph(f"DETAILED ANALYSIS: {data['interval'].upper()}", heading_style))
        elements.append(Spacer(1, 0.1 * inch))
        
        stats = data["statistics"]
        
        # Detailed statistics
        detailed_stats = [
            ["Metric", "Value"],
            ["Total Scans", str(stats["total_scans"])],
            ["Files", str(stats["files_scanned"])],
            ["URLs", str(stats["urls_scanned"])],
            ["IPs", str(stats["ips_scanned"])],
            ["Domains", str(stats["domains_scanned"])],
            ["Hashes", str(stats["hashes_scanned"])],
            ["Safe Scans", str(stats["safe_scans"])],
            ["Suspicious Scans", str(stats["suspicious_scans"])],
            ["Malicious Scans", str(stats["malicious_scans"])],
            ["Threats Detected", str(stats["threats_detected"])],
            ["High Confidence Threats", str(stats["high_confidence_threats"])],
            ["Corroborated Threats", str(stats["corroborated_threats"])],
        ]
        
        stats_table = Table(detailed_stats, colWidths=[3 * inch, 2 * inch])
        stats_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d32f2f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 1, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#ffebee")]),
        ]))
        elements.append(stats_table)
        elements.append(Spacer(1, 0.2 * inch))
        
        # Forensic Analysis
        elements.append(Paragraph("FORENSIC RELIABILITY ANALYSIS", heading_style))
        elements.append(Spacer(1, 0.1 * inch))
        
        forensic_data = [
            ["Forensic Metric", "Value"],
            ["Scans with Forensic Data", f"{stats['scans_with_forensic_data']} ({stats['forensic_coverage_pct']:.1f}%)"],
            ["Avg APIs per Scan", f"{stats['avg_apis_per_scan']:.1f}/5"],
            ["Multi-Source Corroborated", str(stats['corroborated_threats'])],
            ["Average Confidence", f"{stats['avg_confidence']*100:.1f}%"],
            ["Forensic Posture", (
                "HARDENED" if stats['forensic_coverage_pct'] >= 80 and stats['avg_apis_per_scan'] >= 3
                else "STRONG" if stats['forensic_coverage_pct'] >= 60 and stats['avg_apis_per_scan'] >= 2
                else "MODERATE" if stats['forensic_coverage_pct'] >= 40
                else "LIMITED"
            )],
            ["Manual Review Load", (
                "HIGH" if stats['threats_detected'] > 0 and stats['corroborated_threats'] == 0
                else "MEDIUM" if stats['threats_detected'] > stats['corroborated_threats']
                else "LOW"
            )],
            ["Attacks Detected", str(stats['attacks_detected'])],
            ["Defense Actions", str(stats['defense_actions_taken'])],
        ]
        
        forensic_table = Table(forensic_data, colWidths=[3 * inch, 2 * inch])
        forensic_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2e7d32")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#388e3c")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#e8f5e9")]),
        ]))
        elements.append(forensic_table)
        elements.append(Spacer(1, 0.2 * inch))

        # Forensic heuristics summary
        heuristics = []
        if stats["forensic_coverage_pct"] < 50:
            heuristics.append("Low forensic coverage; enable additional API sources to improve validation.")
        elif stats["forensic_coverage_pct"] >= 80:
            heuristics.append("High forensic coverage; multi-source verification is strong.")

        if stats["corroborated_threats"] > 0:
            heuristics.append("Corroborated threats detected; prioritize these for response and documentation.")

        if stats["avg_confidence"] < 0.5:
            heuristics.append("Average confidence is low; increase data sources and re-scan critical targets.")

        if heuristics:
            elements.append(Paragraph("FORENSIC HEURISTICS", heading_style))
            elements.append(Spacer(1, 0.05 * inch))
            for note in heuristics:
                elements.append(Paragraph(f"• {note}", styles["Normal"]))
            elements.append(Spacer(1, 0.15 * inch))

        # Detection method overview
        methods = _get_detection_method_stats(report_data)
        elements.append(Paragraph("DETECTION METHODS OVERVIEW", heading_style))
        elements.append(Spacer(1, 0.05 * inch))
        elements.append(Paragraph(
            f"Heuristic indicators: <b>{methods['heuristic']}</b> | "
            f"Signature-based detections: <b>{methods['signature']}</b> | "
            f"Threat-intel corroborations: <b>{methods['intel']}</b>",
            styles["Normal"],
        ))
        elements.append(Spacer(1, 0.15 * inch))

        # IOC summary
        ioc_summary = _get_ioc_summary(report_data)
        elements.append(Paragraph("IOC SUMMARY", heading_style))
        elements.append(Spacer(1, 0.05 * inch))
        if ioc_summary["items"]:
            for item in ioc_summary["items"]:
                elements.append(Paragraph(f"• {item}", styles["Normal"]))
        else:
            elements.append(Paragraph("No high-confidence IOCs were identified in this period.", styles["Normal"]))
        elements.append(Spacer(1, 0.15 * inch))

        # Detailed scan analysis (top items by confidence)
        all_scans = _collect_scans(report_data)
        if all_scans:
            elements.append(Paragraph("DETAILED SCAN ANALYSIS", heading_style))
            elements.append(Spacer(1, 0.05 * inch))
            top_scans = sorted(all_scans, key=lambda s: s.get("confidence", 0), reverse=True)[:20]
            scan_table_data = [["Target", "Type", "Verdict", "Confidence", "Evidence", "APIs"]]
            for scan in top_scans:
                analysis = scan.get("analysis", {}) or {}
                forensic = scan.get("forensic_metadata", {}) or {}
                apis_called = analysis.get("api_results", {}).get("apis_called", []) or []
                evidence_sources = forensic.get("evidence_sources", []) or []
                target = scan.get("target", "")
                scan_table_data.append([
                    target[:40] + "..." if len(target) > 40 else target,
                    str(scan.get("target_type", "")),
                    str(scan.get("threat_level", "")),
                    f"{(scan.get('confidence', 0) * 100):.1f}%",
                    str(len(evidence_sources)),
                    str(len(apis_called)),
                ])

            scan_table = Table(scan_table_data, colWidths=[2.2 * inch, 0.8 * inch, 0.9 * inch, 1.0 * inch, 0.7 * inch, 0.7 * inch])
            scan_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#90a4ae")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eceff1")]),
            ]))
            elements.append(scan_table)
            elements.append(Spacer(1, 0.2 * inch))

            # Full scan cards for forensic review
            elements.append(Paragraph("FORENSIC SCAN CARDS", heading_style))
            elements.append(Spacer(1, 0.05 * inch))
            elements.extend(_build_scan_cards(all_scans, styles, colors))

        # Digital investigation & SOAR guidance
        elements.append(Paragraph("DIGITAL INVESTIGATION & RESPONSE GUIDANCE", heading_style))
        elements.append(Spacer(1, 0.05 * inch))
        elements.append(Paragraph(
            "Use scan IDs and timestamps for chain-of-custody tracking. Correlate IOCs across intervals to detect "
            "temporal clustering, typosquatting patterns, and AI‑in‑the‑middle (AITM) attempts. "
            "Automate response playbooks (SOAR) for high-confidence, corroborated detections and require analyst "
            "verification for low-confidence or single-source findings.",
            styles["Normal"],
        ))
        elements.append(Spacer(1, 0.2 * inch))

        # FORENSIC & INVESTIGATION GLOSSARY (CONDENSED)
        elements.append(Paragraph("FORENSIC & INVESTIGATION GLOSSARY", heading_style))
        elements.append(Spacer(1, 0.05 * inch))
        glossary_items = [
            "Heuristic Scan: pattern/behavior-based detection for unknown threats.",
            "Signature-Based Detection: matches known malicious signatures.",
            "Multi-Source Corroboration: verdict validation across independent APIs.",
            "Confidence Score: weighted evidence convergence (not probability).",
            "IOC: observable indicator such as IP, URL, domain, or hash.",
            "Temporal Analysis: tracks SAFE→MALICIOUS changes over time.",
            "Point-in-Time Scan: snapshot of verdict at a single moment.",
            "Chain of Custody: preserved provenance and audit trail for evidence.",
            "AiTM: adversary-in-the-middle phishing capturing sessions/MFA.",
            "Typosquatting: look‑alike domains used for deception.",
        ]
        for item in glossary_items:
            elements.append(Paragraph(f"• {item}", styles["Normal"]))
        elements.append(Spacer(1, 0.2 * inch))
        
        # Scan types breakdown
        scans_by_type = data["scans_by_type"]
        for scan_type, scans in scans_by_type.items():
            if scans and len(scans) > 0:
                threat_scans = [s for s in scans if s["threat_level"] in ["suspicious", "malicious"]]
                if threat_scans:
                    elements.append(Paragraph(f"THREATS - {scan_type.upper()} ({len(threat_scans)} items)", heading_style))
                    elements.append(Spacer(1, 0.05 * inch))
                    
                    # Top threats
                    threat_scans = sorted(threat_scans, key=lambda x: x["confidence"], reverse=True)[:10]
                    
                    threat_table_data = [["Target", "Level", "Confidence", "APIs", "Verdict"]]
                    for scan in threat_scans:
                        target = scan["target"][:30] + "..." if len(scan["target"]) > 30 else scan["target"]
                        forensic = scan.get("forensic_metadata", {})
                        apis = str(forensic.get("apis_checked", 0))
                        verdict = scan.get("verdict", "unknown")
                        
                        threat_table_data.append([
                            target,
                            scan["threat_level"].upper(),
                            f"{scan['confidence']*100:.1f}%",
                            apis,
                            verdict[:15] + "..." if len(verdict) > 15 else verdict
                        ])
                    
                    threat_table = Table(threat_table_data, colWidths=[1.5 * inch, 1 * inch, 1 * inch, 0.7 * inch, 1.3 * inch])
                    threat_table.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#c62828")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("ALIGN", (1, 0), (-1, 0), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#ffcdd2")]),
                    ]))
                    elements.append(threat_table)
                    elements.append(Spacer(1, 0.15 * inch))
    
    # Technical Recommendations
    elements.append(PageBreak())
    elements.append(Paragraph("TECHNICAL RECOMMENDATIONS", heading_style))
    elements.append(Spacer(1, 0.1 * inch))
    
    recommendations = [
        ("Threat Intelligence Integration", "Enable continuous integration with threat intelligence feeds for real-time updates."),
        ("API Coverage Optimization", "Ensure all 5 security APIs (VirusTotal, AbuseIPDB, Shodan, URLScan, Hybrid Analysis) are enabled for comprehensive analysis."),
        ("Automated Response", "Configure automated response rules for high-confidence threats exceeding corroboration thresholds."),
        ("Forensic Logging", "Maintain detailed forensic metadata for all scans to ensure audit trail compliance."),
        ("Regular Updates", "Update threat signatures and detection rules weekly to maintain effectiveness."),
    ]
    
    for title, desc in recommendations:
        elements.append(Paragraph(f"<b>• {title}:</b> {desc}", styles["Normal"]))
        elements.append(Spacer(1, 0.08 * inch))
    
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
    elements.append(Paragraph(f"Technical Analysis Report | For Security Teams Only | Confidential", footer_style))
    
    doc.build(elements, onFirstPage=add_page_number, onLaterPages=add_page_number)
    buffer.seek(0)
    return buffer.read()


async def _generate_gemini_technical_insights(report_data: Dict[str, Any]) -> str:
    """Generate AI-assisted technical insights for the report."""
    try:
        client = get_gemini_client()
        if not client.is_available():
            return _fallback_technical_insights(report_data)

        # Aggregate summary for prompt
        total_scans = sum(data["statistics"]["total_scans"] for data in report_data.values())
        total_threats = sum(data["statistics"]["threats_detected"] for data in report_data.values())
        total_malicious = sum(data["statistics"]["malicious_scans"] for data in report_data.values())
        total_suspicious = sum(data["statistics"]["suspicious_scans"] for data in report_data.values())
        total_attacks = sum(data["statistics"]["attacks_detected"] for data in report_data.values())
        total_corroborated = sum(data["statistics"]["corroborated_threats"] for data in report_data.values())

        interval_breakdown = ", ".join(
            f"{data['interval']}: {data['statistics']['threats_detected']} threats"
            for data in report_data.values()
        )

        prompt = (
            "You are a senior security analyst. Create a concise technical insight section for a SOC report. "
            "Use the provided metrics only. Output 4 short sections with headings: "
            "Summary, Key Indicators, Likely Vectors, Hardening Actions. "
            "Each section 2-4 bullets, no fluff.\n\n"
            f"Metrics: total_scans={total_scans}, threats={total_threats}, malicious={total_malicious}, "
            f"suspicious={total_suspicious}, attacks={total_attacks}, corroborated={total_corroborated}.\n"
            f"Interval breakdown: {interval_breakdown}.\n"
            "Do not mention data sources that are not in metrics."
        )

        response = await client.analyze_with_gemini(prompt)
        if response.get("success"):
            return response.get("response", "").strip()

        return _fallback_technical_insights(report_data)
    except Exception:
        return _fallback_technical_insights(report_data)


def _fallback_technical_insights(report_data: Dict[str, Any]) -> str:
    """Fallback technical insights when AI is unavailable."""
    total_scans = sum(data["statistics"]["total_scans"] for data in report_data.values())
    total_threats = sum(data["statistics"]["threats_detected"] for data in report_data.values())
    total_malicious = sum(data["statistics"]["malicious_scans"] for data in report_data.values())
    total_suspicious = sum(data["statistics"]["suspicious_scans"] for data in report_data.values())
    total_attacks = sum(data["statistics"]["attacks_detected"] for data in report_data.values())
    total_corroborated = sum(data["statistics"]["corroborated_threats"] for data in report_data.values())

    return (
        "Summary:\n"
        f"• Total scans: {total_scans}\n"
        f"• Threats detected: {total_threats} (Malicious: {total_malicious}, Suspicious: {total_suspicious})\n"
        f"• Attacks detected: {total_attacks}\n\n"
        "Key Indicators:\n"
        f"• Corroborated threats: {total_corroborated}\n"
        "• Focus on items with high confidence and multi-source confirmation\n\n"
        "Likely Vectors:\n"
        "• Review URL and IP detections for repeated patterns\n"
        "• Correlate attack events with suspicious scans\n\n"
        "Hardening Actions:\n"
        "• Enforce automated blocking for high-confidence threats\n"
        "• Increase monitoring on top recurring indicators\n"
    )


def _calculate_risk_level(total_scans: int, malicious_count: int, corroborated_count: int) -> str:
    """Calculate risk level based on metrics"""
    if total_scans == 0:
        return "UNKNOWN"
    
    malicious_ratio = malicious_count / total_scans
    
    if malicious_ratio > 0.1 or (malicious_count > 0 and corroborated_count >= malicious_count):
        return "CRITICAL"
    elif malicious_ratio > 0.05 or corroborated_count > 0:
        return "HIGH"
    elif malicious_count > 0:
        return "MEDIUM"
    else:
        return "LOW"


def _get_health_status(total_scans: int, malicious_count: int, corroborated_count: int) -> str:
    """Get overall health status"""
    risk = _calculate_risk_level(total_scans, malicious_count, corroborated_count)
    
    if risk == "CRITICAL":
        return "CRITICAL - Immediate Action Required"
    elif risk == "HIGH":
        return "HIGH RISK - Investigation Needed"
    elif risk == "MEDIUM":
        return "MEDIUM RISK - Monitor Closely"
    else:
        return "GOOD - No Critical Issues"


def _get_conclusion_text(total_scans: int, total_threats: int, malicious_count: int, corroborated_count: int) -> str:
    """Generate conclusion text based on metrics"""
    if malicious_count > 0:
        return f"Critical threats have been detected. {corroborated_count} threats have been verified by multiple security sources. Immediate incident response is recommended."
    elif total_threats > 0:
        return f"{total_threats} suspicious items were identified during the analysis period. Review and investigation of these items is recommended."
    else:
        return "All scans performed during the analysis period returned clean results. No threats were detected."


def _collect_scans(report_data: Dict[str, Any]) -> List[dict]:
    """Flatten scans across intervals and types."""
    scans: List[dict] = []
    for interval_key, data in report_data.items():
        scans_by_type = data.get("scans_by_type", {})
        for scan_list in scans_by_type.values():
            for scan in scan_list:
                scan_copy = dict(scan)
                scan_copy["interval"] = data.get("interval", interval_key)
                scans.append(scan_copy)
    return scans


def _get_temporal_stats(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """Compute first/last timestamps from scan data."""
    scans = _collect_scans(report_data)
    timestamps = [s.get("timestamp") for s in scans if s.get("timestamp")]
    timestamps = sorted(timestamps)
    return {
        "first_seen": timestamps[0] if timestamps else "N/A",
        "last_seen": timestamps[-1] if timestamps else "N/A",
        "total_scans": len(scans),
        "intervals": len(report_data),
    }


def _get_ioc_summary(report_data: Dict[str, Any], limit: int = 10) -> Dict[str, Any]:
    """Summarize IOCs from suspicious/malicious scans."""
    scans = _collect_scans(report_data)
    items = []
    seen = set()
    for scan in scans:
        level = (scan.get("threat_level") or "").lower()
        if level in {"suspicious", "malicious"}:
            target = scan.get("target")
            target_type = scan.get("target_type")
            if target and target not in seen:
                items.append(f"{target} ({target_type})")
                seen.add(target)
        if len(items) >= limit:
            break
    return {"items": items}


def _get_detection_method_stats(report_data: Dict[str, Any]) -> Dict[str, int]:
    """Estimate detection method counts from threat indicators and API usage."""
    scans = _collect_scans(report_data)
    heuristic = 0
    signature = 0
    intel = 0
    for scan in scans:
        analysis = scan.get("analysis", {}) or {}
        indicators = analysis.get("threat_indicators", []) or []
        for ind in indicators:
            source = str(ind.get("source", "")).lower()
            if "heuristic" in source:
                heuristic += 1
            elif "virustotal" in source or "hybrid" in source:
                signature += 1
            elif "abuseipdb" in source or "shodan" in source or "urlscan" in source:
                intel += 1
        apis_called = analysis.get("api_results", {}).get("apis_called", []) or []
        if apis_called:
            intel += 1
    return {"heuristic": heuristic, "signature": signature, "intel": intel}


def _format_forensic_status(scan: dict) -> str:
    """Format forensic status label for scan card."""
    forensic = _effective_forensic(scan)
    apis_checked = forensic.get("apis_checked", 0)
    corroboration_count = forensic.get("corroboration_count", 0)
    corroborated = forensic.get("corroboration_threshold_met", False)
    threats_detected = int(scan.get("threats_detected", 0) or 0)
    _, tier = _compute_forensic_integrity(scan)

    if corroborated:
        return f"MULTI-SOURCE VERIFIED ({corroboration_count} sources, {tier})"

    if corroboration_count == 1:
        return f"LIMITED CORROBORATION (1 source, {tier})"

    if apis_checked > 0 and corroboration_count <= 0:
        if threats_detected > 0:
            return f"API-VERIFIED, UNCORROBORATED ({apis_checked} API{'s' if apis_checked != 1 else ''}, {tier})"
        return f"VERIFIED CLEAN ({apis_checked} API{'s' if apis_checked != 1 else ''} checked, {tier})"

    if threats_detected > 0:
        return f"HEURISTIC-ONLY DETECTION ({tier}, manual validation recommended)"

    return "NO API VERIFICATION"


def _scan_action_hint(scan: dict) -> str:
    """Provide an action hint based on threat level and confidence."""
    level = (scan.get("threat_level") or scan.get("verdict") or "").lower()
    confidence = scan.get("confidence", 0)

    if level in {"critical", "malicious", "high"}:
        return "ACTION: Block, isolate, document, and escalate to incident response."

    if level in {"suspicious", "medium"} or confidence < 0.3:
        return "ACTION: Monitor, re-scan, and document for analyst review."

    return "ACTION: No action required; continue monitoring."


def _derive_detection_methods(scan: dict) -> Dict[str, int]:
    """Derive method counts from indicators if advanced forensic block is missing."""
    analysis = _effective_analysis(scan)
    forensic = _effective_forensic(scan)
    indicators = _effective_threat_indicators(scan)

    heuristic = 0
    signature = 0
    intel = 0

    for ind in indicators:
        source = str(ind.get("source", "")).lower()
        if "heuristic" in source:
            heuristic += 1
        elif "virustotal" in source or "hybrid" in source:
            signature += 1
        elif "abuseipdb" in source or "shodan" in source or "urlscan" in source:
            intel += 1

    heuristic_meta = forensic.get("heuristic_indicators", {}) if isinstance(forensic.get("heuristic_indicators"), dict) else {}
    if heuristic_meta:
        heuristic = max(
            heuristic,
            int(heuristic_meta.get("critical", 0) or 0)
            + int(heuristic_meta.get("medium", 0) or 0)
            + int(heuristic_meta.get("low", 0) or 0),
        )

    apis_called = (analysis.get("api_results", {}) or {}).get("apis_called", []) or []
    if apis_called:
        intel = max(intel, len(apis_called))

    return {
        "heuristic_indicators": heuristic,
        "signature_based_indicators": signature,
        "threat_intel_indicators": intel,
    }


def _derive_mitre_mapping(scan: dict) -> List[dict]:
    """Derive lightweight MITRE ATT&CK mapping from indicator text."""
    analysis = scan.get("analysis", {}) or {}
    indicators = analysis.get("threat_indicators", []) or []
    text = " ".join(
        f"{i.get('indicator', '')} {i.get('details', '')} {i.get('source', '')}" for i in indicators
    ).lower()

    rules = [
        ("T1566", "Phishing", "Initial Access", ["phish", "credential", "login", "spoof"]),
        ("T1557", "Adversary-in-the-Middle", "Credential Access", ["aitm", "mfa", "token", "session", "cookie"]),
        ("T1046", "Network Service Discovery", "Discovery", ["port", "scan", "recon", "shodan"]),
        ("T1583.001", "Acquire Infrastructure: Domains", "Resource Development", ["domain", "typosquat", "homograph", "idn"]),
        ("T1204.001", "User Execution: Malicious Link", "Execution", ["url", "redirect", "malicious link"]),
        ("T1204.002", "User Execution: Malicious File", "Execution", ["file", "hash", "payload", "document"]),
    ]

    mapped = []
    seen = set()
    for tid, name, tactic, keys in rules:
        if any(k in text for k in keys):
            key = f"{tid}:{name}"
            if key in seen:
                continue
            seen.add(key)
            mapped.append({"technique_id": tid, "technique": name, "tactic": tactic})

    return mapped[:4]


def _derive_campaign_hypotheses(scan: dict) -> List[dict]:
    """Derive campaign-style hypotheses (non-attributional)."""
    analysis = scan.get("analysis", {}) or {}
    indicators = analysis.get("threat_indicators", []) or []
    text = " ".join(
        f"{i.get('indicator', '')} {i.get('details', '')}" for i in indicators
    ).lower()

    hypotheses = []
    if any(k in text for k in ["aitm", "mfa", "session", "token", "cookie"]):
        hypotheses.append({"pattern": "AiTM-style credential/session interception", "confidence": "medium"})
    if any(k in text for k in ["phish", "credential", "spoof", "homograph"]):
        hypotheses.append({"pattern": "APT36-style phishing tradecraft resemblance", "confidence": "low"})

    return hypotheses[:2]


def _derive_soar_recommendations(scan: dict) -> List[dict]:
    """Derive practical SOAR guidance for scan cards."""
    level = (scan.get("threat_level") or scan.get("verdict") or "").lower()
    if level in {"malicious", "critical", "high"}:
        return [
            {"priority": "P1", "playbook": "Containment"},
            {"priority": "P1", "playbook": "Credential Protection"},
            {"priority": "P2", "playbook": "Forensic Preservation"},
        ]
    if level in {"suspicious", "medium"}:
        return [
            {"priority": "P2", "playbook": "Validation & Re-scan"},
            {"priority": "P2", "playbook": "Enhanced Monitoring"},
            {"priority": "P3", "playbook": "Analyst Triage"},
        ]
    return [{"priority": "P3", "playbook": "Baseline Monitoring"}]


def _extract_advanced_forensic(scan: dict) -> dict:
    """Get advanced forensic analysis regardless of storage location."""
    forensic = _effective_forensic(scan)
    analysis = _effective_analysis(scan)
    existing = (
        scan.get("forensic_analysis")
        or analysis.get("forensic_analysis")
        or forensic.get("advanced_analysis")
        or {}
    )

    if existing:
        return existing

    apis_checked = int(forensic.get("apis_checked", 0) or 0)
    apis_called = (analysis.get("api_results", {}) or {}).get("apis_called", []) or []
    methods = _derive_detection_methods(scan)
    mitre = _derive_mitre_mapping(scan)
    campaigns = _derive_campaign_hypotheses(scan)
    soar = _derive_soar_recommendations(scan)

    return {
        "orchestration": {
            "apis_expected": len((analysis.get("api_results", {}) or {}).get("apis_expected", []) or []),
            "apis_called": len(apis_called) if apis_called else apis_checked,
            "coverage_percent": 0,
        },
        "detection_methods": methods,
        "mitre_attack_mapping": mitre,
        "campaign_hypotheses": campaigns,
        "soar_recommendations": soar,
    }


def _effective_analysis(scan: dict) -> Dict[str, Any]:
    """Get analysis block from all known storage paths."""
    return scan.get("analysis", {}) or scan.get("analysis_data", {}) or {}


def _effective_forensic(scan: dict) -> Dict[str, Any]:
    """Get forensic metadata from all known storage paths."""
    analysis = _effective_analysis(scan)
    return scan.get("forensic_metadata", {}) or analysis.get("forensic_metadata", {}) or {}


def _effective_threat_indicators(scan: dict) -> List[dict]:
    """Get threat indicators from scan or nested analysis."""
    analysis = _effective_analysis(scan)
    return scan.get("threat_indicators", []) or analysis.get("threat_indicators", []) or []


def _compute_forensic_integrity(scan: dict) -> tuple:
    """Compute forensic integrity score and tier for stronger reporting posture."""
    analysis = _effective_analysis(scan)
    forensic = _effective_forensic(scan)
    methods = _derive_detection_methods(scan)

    apis_checked = int(forensic.get("apis_checked", 0) or len((analysis.get("api_results", {}) or {}).get("apis_called", []) or []))
    corroboration_count = int(forensic.get("corroboration_count", 0) or 0)
    confidence = float(scan.get("confidence", analysis.get("confidence", 0.0)) or 0.0)

    method_channels = sum(
        1 for k in ["heuristic_indicators", "signature_based_indicators", "threat_intel_indicators"]
        if int(methods.get(k, 0) or 0) > 0
    )

    score = 0
    score += min(35, apis_checked * 7)
    score += min(30, corroboration_count * 15)
    score += min(20, int(confidence * 20))
    score += method_channels * 5

    if score >= 80:
        tier = "HARDENED"
    elif score >= 60:
        tier = "STRONG"
    elif score >= 40:
        tier = "MODERATE"
    else:
        tier = "LIMITED"

    return score, tier


def _build_scan_cards(scans: List[dict], styles, colors) -> List[Any]:
    """Build scan cards similar to the requested report layout."""
    elements: List[Any] = []
    for idx, scan in enumerate(scans, 1):
        target = scan.get("target", "N/A")
        scan_type = (scan.get("target_type") or "unknown").upper()
        threat_level = (scan.get("threat_level") or "unknown").upper()
        threat_level_key = (scan.get("threat_level") or "unknown").lower()
        confidence = f"{(scan.get('confidence', 0) * 100):.1f}%"
        threats_found = str(scan.get("threats_detected", 0))
        detected_at = scan.get("timestamp") or "N/A"
        forensic_status = _format_forensic_status(scan)
        action_hint = _scan_action_hint(scan)
        advanced_forensic = _extract_advanced_forensic(scan)
        integrity_score, integrity_tier = _compute_forensic_integrity(scan)

        methods = advanced_forensic.get("detection_methods", {}) if advanced_forensic else {}

        if threat_level_key in {"safe", "clean", "trusted", "low"}:
            header_bg = colors.HexColor("#e8f5e9")
            body_bg = colors.HexColor("#f1f8e9")
            grid_color = colors.HexColor("#66bb6a")
        elif threat_level_key in {"suspicious", "warning", "medium", "high"}:
            header_bg = colors.HexColor("#fff3e0")
            body_bg = colors.HexColor("#fff8e1")
            grid_color = colors.HexColor("#ffb74d")
        elif threat_level_key in {"malicious", "critical", "threat"}:
            header_bg = colors.HexColor("#ffebee")
            body_bg = colors.HexColor("#fff5f5")
            grid_color = colors.HexColor("#ef5350")
        else:
            header_bg = colors.HexColor("#eceff1")
            body_bg = colors.HexColor("#fafafa")
            grid_color = colors.HexColor("#90a4ae")

        card_data = [
            ["Scan #", str(idx)],
            ["Target URL/File", target],
            ["Scan Type", scan_type],
            ["Threat Level", threat_level],
            ["Confidence", confidence],
            ["Threats Found", threats_found],
            ["Detected At", detected_at],
            ["Forensic Status", forensic_status],
            ["Forensic Integrity", f"{integrity_score}/100 ({integrity_tier})"],
            [
                "Detection Methods",
                f"Heuristic={methods.get('heuristic_indicators', 0)}, "
                f"Signature={methods.get('signature_based_indicators', 0)}, "
                f"Intel={methods.get('threat_intel_indicators', 0)}",
            ],
            ["Action", action_hint],
        ]

        card_table = Table(card_data, colWidths=[1.6 * inch, 4.9 * inch])
        card_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), header_bg),
            ("BACKGROUND", (0, 1), (-1, -1), body_bg),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#212121")),
            ("ALIGN", (0, 0), (0, -1), "RIGHT"),
            ("ALIGN", (1, 0), (1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.6, grid_color),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))

        elements.append(card_table)
        elements.append(Spacer(1, 0.15 * inch))

    return elements
