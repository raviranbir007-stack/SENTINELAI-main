"""
Report Type Generators for Advanced Reporting
Generates Executive Summary and Technical Analysis reports
"""

import io
from datetime import datetime
from typing import Dict, Any, List
from xml.sax.saxutils import escape

from server.app.gemini_integration import get_gemini_client

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

    wrapped_header_exec = ParagraphStyle(
        "ExecTableHeaderWrap",
        parent=styles["Normal"],
        fontSize=9,
        leading=10,
        textColor=colors.whitesmoke,
        fontName="Helvetica-Bold",
    )

    wrapped_body_exec = ParagraphStyle(
        "ExecTableBodyWrap",
        parent=styles["Normal"],
        fontSize=9,
        leading=10,
        textColor=colors.HexColor("#212121"),
        fontName="Helvetica",
    )

    def _wrap_rows_exec(rows: List[List[Any]], has_header: bool = True) -> List[List[Any]]:
        wrapped: List[List[Any]] = []
        for ridx, row in enumerate(rows):
            style = wrapped_header_exec if (has_header and ridx == 0) else wrapped_body_exec
            wrapped.append([
                Paragraph(escape(str(cell)).replace("\n", "<br/>"), style)
                for cell in row
            ])
        return wrapped
    
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
    
    info_table = Table(_wrap_rows_exec(report_info, has_header=False), colWidths=[2 * inch, 3.5 * inch])
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
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
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
    
    metrics_table = Table(_wrap_rows_exec(metrics_data), colWidths=[2.5 * inch, 1.5 * inch, 1 * inch])
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
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
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
    
    timeline_table = Table(_wrap_rows_exec(timeline_data), colWidths=[1.5 * inch, 1 * inch, 1 * inch, 1 * inch, 1.5 * inch])
    timeline_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0066cc")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9f9f9")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
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

    # FORENSIC TREND ANALYSIS ACROSS 24h / 7d / 30d
    elements.append(Paragraph("FORENSIC TREND ANALYSIS", heading_style))
    elements.append(Spacer(1, 0.1 * inch))
    forensic_trend_rows = _build_forensic_trend_rows(report_data)
    forensic_trend_table = Table(_wrap_rows_exec(forensic_trend_rows), colWidths=[1.1 * inch, 0.8 * inch, 0.7 * inch, 0.8 * inch, 0.8 * inch, 0.9 * inch, 0.9 * inch])
    forensic_trend_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2e7d32")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("ALIGN", (0, 0), (0, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#66bb6a")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#e8f5e9")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
    ]))
    elements.append(forensic_trend_table)
    elements.append(Spacer(1, 0.12 * inch))

    forensic_summary = _summarize_forensic_strength(report_data)
    elements.append(Paragraph(
        f"Forensic confidence across selected intervals is assessed as <b>{forensic_summary['overall_grade']}</b>. "
        f"Average integrity score is <b>{forensic_summary['avg_integrity']:.1f}/100</b>, "
        f"with corroboration rate <b>{forensic_summary['avg_corroboration']:.1f}%</b> and "
        f"mean API verification success <b>{forensic_summary['avg_api_success']:.1f}%</b>. "
        f"Primary evidence gap observed: <b>{forensic_summary['dominant_gap']}</b>.",
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
        
        threat_dist_table = Table(_wrap_rows_exec(threat_dist_data), colWidths=[2.5 * inch, 1.5 * inch, 1.5 * inch])
        threat_dist_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#cc6600")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ALIGN", (1, 0), (-1, 0), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 1, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fff3e0")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
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

    forensic_summary = _summarize_forensic_strength(report_data)
    if forensic_summary["avg_integrity"] < 60:
        recommendations.append(
            f"🔬 <b>FORENSIC IMPROVEMENT:</b> Forensic integrity average is {forensic_summary['avg_integrity']:.1f}/100. "
            "Increase multi-source corroboration and API verification depth for high-risk scans."
        )
    if forensic_summary["avg_corroboration"] < 55:
        recommendations.append(
            "🧭 <b>CORROBORATION GAP:</b> Cross-source corroboration is below target. Prioritize re-scan workflows for suspicious/malicious findings."
        )
    if forensic_summary["avg_api_success"] < 75:
        recommendations.append(
            f"⚙ <b>API RELIABILITY:</b> Verification success is {forensic_summary['avg_api_success']:.1f}%. "
            f"Focus on fixing dominant failure mode: {forensic_summary['dominant_gap']}."
        )
    
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

    wrapped_header_style = ParagraphStyle(
        "TechTableHeaderWrap",
        parent=styles["Normal"],
        fontSize=8,
        leading=9,
        textColor=colors.whitesmoke,
        fontName="Helvetica-Bold",
    )

    wrapped_body_style = ParagraphStyle(
        "TechTableBodyWrap",
        parent=styles["Normal"],
        fontSize=7.5,
        leading=9,
        textColor=colors.HexColor("#212121"),
        fontName="Helvetica",
    )

    def _wrap_rows(rows: List[List[Any]]) -> List[List[Any]]:
        wrapped: List[List[Any]] = []
        for ridx, row in enumerate(rows):
            style = wrapped_header_style if ridx == 0 else wrapped_body_style
            wrapped_row = [
                Paragraph(escape(str(cell)).replace("\n", "<br/>"), style)
                for cell in row
            ]
            wrapped.append(wrapped_row)
        return wrapped
    
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
    
    info_table = Table(_wrap_rows(report_info), colWidths=[2 * inch, 3.5 * inch])
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
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
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

    # Global SOC-style technical overview
    all_scans_global = _collect_scans(report_data)
    total_scans_global = len(all_scans_global)
    total_threats_global = sum(1 for s in all_scans_global if (s.get("threat_level") or "").lower() in {"suspicious", "malicious", "critical", "high"})
    total_attacks_global = sum(len((d.get("attacks") or [])) for d in report_data.values())
    total_defense_global = sum(len((d.get("defense_actions") or [])) for d in report_data.values())
    successful_defense_global = sum(
        1
        for d in report_data.values()
        for a in (d.get("defense_actions") or [])
        if a.get("successful")
    )
    defense_success_pct = (successful_defense_global / total_defense_global * 100) if total_defense_global else 0.0
    avg_conf_global = (
        sum(float(s.get("confidence", 0) or 0) for s in all_scans_global) / max(total_scans_global, 1)
    )

    elements.append(PageBreak())
    elements.append(Paragraph("GLOBAL TECHNICAL OVERVIEW", heading_style))
    elements.append(Spacer(1, 0.08 * inch))

    global_overview_rows = [
        ["Technical Metric", "Value"],
        ["Total Scan Events", str(total_scans_global)],
        ["Threat-bearing Scan Events", str(total_threats_global)],
        ["Attack Events", str(total_attacks_global)],
        ["Defense Actions Executed", str(total_defense_global)],
        ["Defense Success Rate", f"{defense_success_pct:.1f}%"],
        ["Average Scan Confidence", f"{avg_conf_global * 100:.1f}%"],
    ]
    global_table = Table(_wrap_rows(global_overview_rows), colWidths=[3.2 * inch, 1.8 * inch])
    global_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#607d8b")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eceff1")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
    ]))
    elements.append(global_table)
    elements.append(Spacer(1, 0.14 * inch))

    elements.append(Paragraph("API RELIABILITY MATRIX (GLOBAL)", heading_style))
    elements.append(Spacer(1, 0.05 * inch))
    api_reliability_rows = _build_global_api_reliability_rows(report_data)
    api_reliability_table = Table(
        _wrap_rows(api_reliability_rows),
        colWidths=[1.25 * inch, 0.6 * inch, 0.6 * inch, 0.65 * inch, 0.65 * inch, 0.55 * inch, 0.75 * inch, 0.7 * inch],
    )
    api_reliability_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b5e20")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("ALIGN", (0, 0), (0, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#66bb6a")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#e8f5e9")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
    ]))
    elements.append(api_reliability_table)
    elements.append(Spacer(1, 0.14 * inch))

    elements.append(Paragraph("PRIORITY INVESTIGATION QUEUE (GLOBAL)", heading_style))
    elements.append(Spacer(1, 0.05 * inch))
    triage_rows = _build_priority_investigation_rows(report_data, limit=15)
    triage_table = Table(_wrap_rows(triage_rows), colWidths=[0.6 * inch, 1.95 * inch, 0.7 * inch, 0.7 * inch, 0.7 * inch, 0.65 * inch, 1.3 * inch])
    triage_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4a148c")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ("ALIGN", (2, 0), (5, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#b39ddb")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3e5f5")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
    ]))
    elements.append(triage_table)
    elements.append(Spacer(1, 0.12 * inch))
    
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
        
        stats_table = Table(_wrap_rows(detailed_stats), colWidths=[3 * inch, 2 * inch])
        stats_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d32f2f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 1, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#ffebee")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
        ]))
        elements.append(stats_table)
        elements.append(Spacer(1, 0.2 * inch))

        # Interval analyst triage queue
        interval_scans = _collect_scans({interval_key: data})
        elements.append(Paragraph("ANALYST TRIAGE QUEUE (INTERVAL)", heading_style))
        elements.append(Spacer(1, 0.05 * inch))
        interval_triage_rows = _build_interval_triage_rows(interval_scans, limit=10)
        interval_triage_table = Table(_wrap_rows(interval_triage_rows), colWidths=[0.7 * inch, 2.0 * inch, 0.8 * inch, 0.8 * inch, 0.8 * inch, 0.7 * inch])
        interval_triage_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#6a1b9a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
            ("ALIGN", (2, 0), (5, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#ce93d8")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3e5f5")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
        ]))
        elements.append(interval_triage_table)
        elements.append(Spacer(1, 0.15 * inch))

        # Interval API gap diagnostics
        elements.append(Paragraph("EVIDENCE GAPS & FAILURE MODES", heading_style))
        elements.append(Spacer(1, 0.05 * inch))
        gap_rows = _build_interval_api_gap_rows(interval_scans)
        gap_table = Table(_wrap_rows(gap_rows), colWidths=[1.4 * inch, 0.7 * inch, 0.7 * inch, 0.7 * inch, 0.8 * inch, 1.5 * inch])
        gap_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#bf360c")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("ALIGN", (0, 0), (0, -1), "LEFT"),
            ("ALIGN", (5, 0), (5, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#ffab91")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fbe9e7")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
        ]))
        elements.append(gap_table)
        elements.append(Spacer(1, 0.15 * inch))

        # Attack event correlation matrix (technical SOC view)
        attack_rows = _build_attack_correlation_rows(data, limit=20)
        elements.append(Paragraph("ATTACK EVENT CORRELATION", heading_style))
        elements.append(Spacer(1, 0.05 * inch))
        attack_table = Table(
            _wrap_rows(attack_rows),
            colWidths=[1.6 * inch, 1.3 * inch, 0.9 * inch, 0.7 * inch, 0.6 * inch, 0.9 * inch],
        )
        attack_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4a148c")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ALIGN", (2, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#b39ddb")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3e5f5")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
        ]))
        elements.append(attack_table)
        elements.append(Spacer(1, 0.15 * inch))

        # Defense action execution matrix
        defense_rows = _build_defense_action_rows(data, limit=20)
        elements.append(Paragraph("DEFENSE ACTION EXECUTION", heading_style))
        elements.append(Spacer(1, 0.05 * inch))
        defense_table = Table(
            _wrap_rows(defense_rows),
            colWidths=[1.4 * inch, 1.6 * inch, 1.3 * inch, 0.8 * inch, 0.8 * inch, 0.8 * inch],
        )
        defense_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d47a1")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ALIGN", (3, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#90caf9")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#e3f2fd")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
        ]))
        elements.append(defense_table)
        defense_count = len(data.get("defense_actions", []) or [])
        attack_count = len(data.get("attacks", []) or [])
        success_count = sum(1 for a in (data.get("defense_actions", []) or []) if a.get("successful"))
        if defense_count == 0 and attack_count > 0:
            elements.append(Paragraph(
                f"<b>Defense Status:</b> No defense action taken for {attack_count} detected attack event(s) in this interval.",
                styles["Normal"],
            ))
        elif defense_count == 0:
            elements.append(Paragraph(
                "<b>Defense Status:</b> No defense action taken in this interval.",
                styles["Normal"],
            ))
        else:
            elements.append(Paragraph(
                f"<b>Defense Status:</b> {defense_count} action(s) executed, {success_count} succeeded.",
                styles["Normal"],
            ))
        elements.append(Spacer(1, 0.2 * inch))
        
        # Forensic Analysis
        elements.append(Paragraph("FORENSIC RELIABILITY ANALYSIS", heading_style))
        elements.append(Spacer(1, 0.1 * inch))
        
        forensic_data = [
            ["Forensic Metric", "Value"],
            ["Scans with Forensic Data", f"{stats['scans_with_forensic_data']} ({stats['forensic_coverage_pct']:.1f}%)"],
            ["Avg APIs per Scan", f"{stats['avg_apis_per_scan']:.1f}/5"],
            ["Multi-Source Corroborated", str(stats['corroborated_threats'])],
            ["Corroboration Rate", f"{float(stats.get('corroboration_rate_pct', 0.0)):.1f}%"],
            ["Average Confidence", f"{stats['avg_confidence']*100:.1f}%"],
            ["Avg Forensic Integrity", f"{float(stats.get('avg_forensic_integrity_score', 0.0)):.1f}/100"],
            [
                "Integrity Distribution",
                (
                    f"H:{int(stats.get('forensic_integrity_hardened', 0))} "
                    f"S:{int(stats.get('forensic_integrity_strong', 0))} "
                    f"M:{int(stats.get('forensic_integrity_moderate', 0))} "
                    f"L:{int(stats.get('forensic_integrity_limited', 0))}"
                ),
            ],
            ["Threats Without Forensic Validation", str(int(stats.get('threats_without_forensic', 0)))],
            ["API Verification Success", f"{float(stats.get('api_verification_success_pct', 0.0)):.1f}%"],
            ["Primary API Failure Mode", str(stats.get('primary_api_failure_mode', 'none')).replace('_', ' ').title()],
            ["Forensic Posture", (
                str(stats.get('forensic_posture', ''))
                or (
                    "HARDENED" if stats['forensic_coverage_pct'] >= 80 and stats['avg_apis_per_scan'] >= 3
                    else "STRONG" if stats['forensic_coverage_pct'] >= 60 and stats['avg_apis_per_scan'] >= 2
                    else "MODERATE" if stats['forensic_coverage_pct'] >= 40
                    else "LIMITED"
                )
            )],
            ["Manual Review Load", (
                "HIGH" if stats['threats_detected'] > 0 and stats['corroborated_threats'] == 0
                else "MEDIUM" if stats['threats_detected'] > stats['corroborated_threats']
                else "LOW"
            )],
            ["Attacks Detected", str(stats['attacks_detected'])],
            ["Defense Actions", str(stats['defense_actions_taken'])],
        ]
        
        forensic_table = Table(_wrap_rows(forensic_data), colWidths=[3 * inch, 2 * inch])
        forensic_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2e7d32")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#388e3c")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#e8f5e9")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
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

        if float(stats.get("avg_forensic_integrity_score", 0.0)) < 60:
            heuristics.append(
                "Forensic integrity score is below target; raise corroboration depth and ensure at least 2+ API validations for high-risk findings."
            )

        if int(stats.get("threats_without_forensic", 0)) > 0:
            heuristics.append(
                f"{int(stats.get('threats_without_forensic', 0))} threat-bearing scan(s) lacked API verification; mark these as priority manual review cases."
            )

        if float(stats.get("api_verification_success_pct", 0.0)) < 75:
            heuristics.append(
                f"API verification success is degraded ({float(stats.get('api_verification_success_pct', 0.0)):.1f}%). "
                f"Most frequent failure: {str(stats.get('primary_api_failure_mode', 'unknown')).replace('_', ' ')}."
            )

        if heuristics:
            elements.append(Paragraph("FORENSIC HEURISTICS", heading_style))
            elements.append(Spacer(1, 0.05 * inch))
            for note in heuristics:
                elements.append(Paragraph(f"• {note}", styles["Normal"]))
            elements.append(Spacer(1, 0.15 * inch))

        elements.append(Paragraph("FORENSIC INTERPRETATION", heading_style))
        elements.append(Spacer(1, 0.05 * inch))
        elements.append(Paragraph(
            (
                f"Interval forensic posture is <b>{str(stats.get('forensic_posture', 'LIMITED'))}</b>. "
                f"Coverage={stats['forensic_coverage_pct']:.1f}%, "
                f"AvgIntegrity={float(stats.get('avg_forensic_integrity_score', 0.0)):.1f}/100, "
                f"CorroborationRate={float(stats.get('corroboration_rate_pct', 0.0)):.1f}%. "
                "Use this score set to prioritize containment and evidence-preservation decisions."
            ),
            styles["Normal"],
        ))
        elements.append(Spacer(1, 0.12 * inch))

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
        if interval_scans:
            elements.append(Paragraph("DETAILED SCAN ANALYSIS", heading_style))
            elements.append(Spacer(1, 0.05 * inch))
            top_scans = sorted(interval_scans, key=lambda s: s.get("confidence", 0), reverse=True)[:20]
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

            scan_table = Table(_wrap_rows(scan_table_data), colWidths=[2.2 * inch, 0.8 * inch, 0.9 * inch, 1.0 * inch, 0.7 * inch, 0.7 * inch])
            scan_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#90a4ae")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eceff1")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
            ]))
            elements.append(scan_table)
            elements.append(Spacer(1, 0.2 * inch))

            # Full scan cards for forensic review
            elements.append(Paragraph("FORENSIC SCAN CARDS", heading_style))
            elements.append(Spacer(1, 0.05 * inch))
            elements.extend(_build_scan_cards(interval_scans, styles, colors))

            # MITRE ATT&CK mapping (derived from technical indicators)
            mitre_rows = _build_interval_mitre_rows(interval_scans)
            elements.append(Paragraph("MITRE ATT&CK MAPPING MATRIX (DERIVED)", heading_style))
            elements.append(Spacer(1, 0.05 * inch))
            mitre_table = Table(_wrap_rows(mitre_rows), colWidths=[1.0 * inch, 2.2 * inch, 1.5 * inch, 1.8 * inch])
            mitre_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#90a4ae")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eceff1")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
            ]))
            elements.append(mitre_table)
            elements.append(Spacer(1, 0.15 * inch))

            # SIEM query starter pack for IR workflows
            elements.append(Paragraph("SIEM QUERY STARTER PACK (KQL / SPL)", heading_style))
            elements.append(Spacer(1, 0.05 * inch))
            for query_line in _build_siem_query_pack(interval_scans):
                elements.append(Paragraph(f"• {query_line}", styles["Normal"]))
            elements.append(Spacer(1, 0.15 * inch))

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
                    
                    threat_table = Table(_wrap_rows(threat_table_data), colWidths=[1.5 * inch, 1 * inch, 1 * inch, 0.7 * inch, 1.3 * inch])
                    threat_table.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#c62828")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("ALIGN", (1, 0), (-1, 0), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#ffcdd2")]),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
                    ]))
                    elements.append(threat_table)
                    elements.append(Spacer(1, 0.15 * inch))

    # IR case-file appendix
    elements.append(PageBreak())
    elements.append(Paragraph("APPENDIX A — RAW IOC EXPORT", heading_style))
    elements.append(Spacer(1, 0.08 * inch))
    elements.append(Paragraph(
        "Raw indicator export for analyst pivoting. Includes source, type, confidence, first/last seen, and linked scan IDs.",
        styles["Normal"],
    ))
    elements.append(Spacer(1, 0.06 * inch))

    ioc_rows = _build_raw_ioc_export_rows(report_data, limit=120)
    ioc_table = Table(_wrap_rows(ioc_rows), colWidths=[1.9 * inch, 0.7 * inch, 1.1 * inch, 0.7 * inch, 1.1 * inch, 1.1 * inch])
    ioc_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("ALIGN", (1, 0), (3, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#90a4ae")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eceff1")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
    ]))
    elements.append(ioc_table)
    elements.append(Spacer(1, 0.14 * inch))

    elements.append(Paragraph("APPENDIX B — INCIDENT TIMELINE RECONSTRUCTION", heading_style))
    elements.append(Spacer(1, 0.08 * inch))
    elements.append(Paragraph(
        "Chronological reconstruction across scan events, detected attacks, and defense actions for incident response case handling.",
        styles["Normal"],
    ))
    elements.append(Spacer(1, 0.06 * inch))

    timeline_rows = _build_incident_timeline_rows(report_data, limit=140)
    timeline_table = Table(_wrap_rows(timeline_rows), colWidths=[1.2 * inch, 0.9 * inch, 0.7 * inch, 1.7 * inch, 1.0 * inch, 1.0 * inch])
    timeline_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3e2723")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("ALIGN", (1, 0), (2, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#bcaaa4")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#efebe9")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
    ]))
    elements.append(timeline_table)
    elements.append(Spacer(1, 0.14 * inch))
    
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


def _forensic_grade_from_score(score: float) -> str:
    if score >= 80:
        return "HARDENED"
    if score >= 65:
        return "STRONG"
    if score >= 45:
        return "MODERATE"
    return "LIMITED"


def _build_forensic_trend_rows(report_data: Dict[str, Any]) -> List[List[str]]:
    """Build cross-interval forensic trend matrix for executive reporting."""
    rows: List[List[str]] = [["Interval", "Coverage", "APIs", "Corrobor.", "Integrity", "Unverified", "Grade"]]

    if not report_data:
        rows.append(["-", "0%", "0.0", "0%", "0/100", "0", "LIMITED"])
        return rows

    order_hint = {"24h": 1, "7d": 2, "30d": 3}
    ordered_items = sorted(report_data.items(), key=lambda kv: order_hint.get(kv[0], 99))

    for interval_key, data in ordered_items:
        stats = data.get("statistics", {}) if isinstance(data, dict) else {}
        label = str(data.get("interval") or interval_key)
        coverage = float(stats.get("forensic_coverage_pct", 0.0) or 0.0)
        apis = float(stats.get("avg_apis_per_scan", 0.0) or 0.0)
        corroboration = float(stats.get("corroboration_rate_pct", 0.0) or 0.0)
        integrity = float(stats.get("avg_forensic_integrity_score", 0.0) or 0.0)
        unverified = int(stats.get("threats_without_forensic", 0) or 0)
        grade = str(stats.get("forensic_posture") or _forensic_grade_from_score(integrity))

        rows.append([
            label,
            f"{coverage:.1f}%",
            f"{apis:.1f}",
            f"{corroboration:.1f}%",
            f"{integrity:.1f}/100",
            str(unverified),
            grade,
        ])

    return rows


def _summarize_forensic_strength(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregate forensic strength summary for recommendations and narrative."""
    stats_list = [
        (item.get("statistics") or {})
        for item in report_data.values()
        if isinstance(item, dict)
    ]
    if not stats_list:
        return {
            "avg_integrity": 0.0,
            "avg_corroboration": 0.0,
            "avg_api_success": 0.0,
            "dominant_gap": "none",
            "overall_grade": "LIMITED",
        }

    n = len(stats_list)
    avg_integrity = sum(float(s.get("avg_forensic_integrity_score", 0.0) or 0.0) for s in stats_list) / n
    avg_corroboration = sum(float(s.get("corroboration_rate_pct", 0.0) or 0.0) for s in stats_list) / n
    avg_api_success = sum(float(s.get("api_verification_success_pct", 0.0) or 0.0) for s in stats_list) / n

    gap_counts: Dict[str, int] = {}
    for s in stats_list:
        gap = str(s.get("primary_api_failure_mode", "none") or "none").strip().lower()
        gap_counts[gap] = gap_counts.get(gap, 0) + 1
    dominant_gap_raw = max(gap_counts.items(), key=lambda kv: kv[1])[0] if gap_counts else "none"

    return {
        "avg_integrity": avg_integrity,
        "avg_corroboration": avg_corroboration,
        "avg_api_success": avg_api_success,
        "dominant_gap": dominant_gap_raw.replace("_", " ").title(),
        "overall_grade": _forensic_grade_from_score(avg_integrity),
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


def _build_attack_correlation_rows(interval_data: Dict[str, Any], limit: int = 20) -> List[List[str]]:
    """Build rows for per-interval attack correlation table."""
    rows: List[List[str]] = [["Detected At", "Attack Type", "Severity", "Status", "Blocked", "Source IP"]]
    attacks = interval_data.get("attacks", []) or []
    if not attacks:
        rows.append(["-", "No attack events", "-", "-", "-", "-"])
        return rows

    for attack in attacks[:limit]:
        detected_at = str(attack.get("detected_at") or "-")[:19]
        attack_type = str(attack.get("attack_type") or "-")
        severity = str(attack.get("severity") or "-").upper()
        status = str(attack.get("status") or "-")
        blocked = "YES" if bool(attack.get("blocked")) else "NO"
        src_ip = str(attack.get("source_ip") or "-")
        rows.append([
            detected_at,
            attack_type[:28] + ("..." if len(attack_type) > 28 else ""),
            severity,
            status[:12] + ("..." if len(status) > 12 else ""),
            blocked,
            src_ip,
        ])

    return rows


def _build_defense_action_rows(interval_data: Dict[str, Any], limit: int = 20) -> List[List[str]]:
    """Build rows for defense action execution table."""
    rows: List[List[str]] = [["Created At", "Action Type", "Target", "Status", "Success", "Action ID"]]
    actions = interval_data.get("defense_actions", []) or []
    if not actions:
        rows.append(["-", "No defense action taken", "-", "-", "-", "-"])
        return rows

    for action in actions[:limit]:
        created_at = str(action.get("created_at") or "-")[:19]
        action_type = str(action.get("action_type") or "-")
        target = str(action.get("target") or "-")
        status = str(action.get("status") or "-")
        success = "YES" if bool(action.get("successful")) else "NO"
        action_id = str(action.get("action_id") or "-")
        rows.append([
            created_at,
            action_type[:24] + ("..." if len(action_type) > 24 else ""),
            target[:20] + ("..." if len(target) > 20 else ""),
            status[:12] + ("..." if len(status) > 12 else ""),
            success,
            action_id[:14] + ("..." if len(action_id) > 14 else ""),
        ])

    return rows


def _build_interval_mitre_rows(scans: List[dict], limit: int = 12) -> List[List[str]]:
    """Build a compact MITRE ATT&CK mapping table for interval scans."""
    rows: List[List[str]] = [["ID", "Technique", "Tactic", "Observed In"]]
    seen = set()

    for scan in scans:
        target = str(scan.get("target") or "-")
        for item in _derive_mitre_mapping(scan):
            tid = str(item.get("technique_id") or "-")
            technique = str(item.get("technique") or "-")
            tactic = str(item.get("tactic") or "-")
            key = (tid, technique, tactic)
            if key in seen:
                continue
            seen.add(key)
            rows.append([
                tid,
                technique[:34] + ("..." if len(technique) > 34 else ""),
                tactic[:20] + ("..." if len(tactic) > 20 else ""),
                target[:26] + ("..." if len(target) > 26 else ""),
            ])
            if len(rows) - 1 >= limit:
                return rows

    if len(rows) == 1:
        rows.append(["-", "No mapped techniques", "-", "-"])

    return rows


def _build_siem_query_pack(scans: List[dict]) -> List[str]:
    """Return practical SIEM query snippets tailored to observed targets."""
    iocs: List[str] = []
    for scan in scans:
        target = str(scan.get("target") or "").strip()
        level = str(scan.get("threat_level") or "").lower()
        if target and level in {"suspicious", "malicious", "critical", "high"}:
            iocs.append(target)
    iocs = list(dict.fromkeys(iocs))[:5]

    if not iocs:
        return [
            "KQL: SecurityEvent | where TimeGenerated > ago(24h) | summarize count() by EventID",
            "SPL: index=* earliest=-24h | stats count by sourcetype",
        ]

    ioc_filter = " OR ".join(iocs)
    return [
        f"KQL: DeviceNetworkEvents | where TimeGenerated > ago(24h) | where RemoteUrl has_any ({', '.join(repr(i) for i in iocs)}) or RemoteIP has_any ({', '.join(repr(i) for i in iocs)}) | project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, ActionType",
        f"SPL: index=* earliest=-24h ({ioc_filter}) | stats count by src, dest, user, process",
        f"KQL: EmailEvents | where TimeGenerated > ago(24h) | where SenderFromDomain has_any ({', '.join(repr(i) for i in iocs)}) or Subject has_any ({', '.join(repr(i) for i in iocs)}) | project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes",
        "KQL: DeviceProcessEvents | where TimeGenerated > ago(24h) | where ProcessCommandLine has_any ('powershell','curl','wget','mshta','rundll32') | summarize count() by DeviceName, InitiatingProcessFileName",
    ]


def _extract_api_status_map(scan: dict) -> Dict[str, dict]:
    """Extract per-API status map from forensic or analysis storage paths."""
    forensic = _effective_forensic(scan)
    analysis = _effective_analysis(scan)

    forensic_api_status = forensic.get("api_status") if isinstance(forensic.get("api_status"), dict) else {}
    analysis_api_status = (
        (analysis.get("api_results", {}) or {}).get("api_status", {})
        if isinstance((analysis.get("api_results", {}) or {}).get("api_status", {}), dict)
        else {}
    )

    # Prefer forensic projection when available, fallback to analysis map.
    return forensic_api_status or analysis_api_status or {}


def _build_global_api_reliability_rows(report_data: Dict[str, Any]) -> List[List[str]]:
    """Build global API reliability matrix across all scans."""
    scans = _collect_scans(report_data)
    counters: Dict[str, Dict[str, int]] = {}

    for scan in scans:
        for _api_key, entry in _extract_api_status_map(scan).items():
            name = str(entry.get("name") or _api_key or "unknown")
            status = str(entry.get("status") or "unknown").lower()
            if status == "not_applicable":
                continue

            bucket = counters.setdefault(name, {
                "checked": 0,
                "pending": 0,
                "rate_limited": 0,
                "not_authorized": 0,
                "error": 0,
                "not_configured": 0,
                "unknown": 0,
            })
            if status in bucket:
                bucket[status] += 1
            else:
                bucket["unknown"] += 1

    if not counters:
        return [["API", "Checked", "Pending", "Rate", "Auth", "Error", "Not Config", "Success %"], ["-", "0", "0", "0", "0", "0", "0", "0.0%"]]

    rows: List[List[str]] = [["API", "Checked", "Pending", "Rate", "Auth", "Error", "Not Config", "Success %"]]
    for api_name in sorted(counters.keys()):
        c = counters[api_name]
        total = c["checked"] + c["pending"] + c["rate_limited"] + c["not_authorized"] + c["error"] + c["not_configured"] + c["unknown"]
        success_pct = (c["checked"] / total * 100) if total else 0.0
        rows.append([
            api_name,
            str(c["checked"]),
            str(c["pending"]),
            str(c["rate_limited"]),
            str(c["not_authorized"]),
            str(c["error"] + c["unknown"]),
            str(c["not_configured"]),
            f"{success_pct:.1f}%",
        ])

    return rows


def _build_priority_investigation_rows(report_data: Dict[str, Any], limit: int = 15) -> List[List[str]]:
    """Build global prioritized analyst queue for threat-bearing scans."""
    scans = _collect_scans(report_data)
    risky = [
        s for s in scans
        if (s.get("threat_level") or "").lower() in {"malicious", "critical", "high", "suspicious", "medium"}
    ]

    def _priority_score(scan: dict) -> tuple:
        level = (scan.get("threat_level") or "").lower()
        level_rank = 3 if level in {"malicious", "critical", "high"} else 2
        confidence = float(scan.get("confidence", 0) or 0)
        threats = int(scan.get("threats_detected", 0) or 0)
        return (level_rank, confidence, threats)

    risky = sorted(risky, key=_priority_score, reverse=True)[:limit]
    rows: List[List[str]] = [["Prio", "Target", "Type", "Level", "Conf", "IOCs", "Action"]]
    if not risky:
        rows.append(["-", "No threat-bearing scans", "-", "-", "-", "-", "No immediate analyst action"])
        return rows

    for idx, scan in enumerate(risky, 1):
        target = str(scan.get("target") or "-")
        action = _scan_action_hint(scan)
        rows.append([
            f"P{1 if idx <= 5 else 2}",
            target[:40] + ("..." if len(target) > 40 else ""),
            str(scan.get("target_type") or "-")[:10],
            str(scan.get("threat_level") or "-")[:10].upper(),
            f"{float(scan.get('confidence', 0) or 0) * 100:.1f}%",
            str(int(scan.get("threats_detected", 0) or 0)),
            action[:44] + ("..." if len(action) > 44 else ""),
        ])

    return rows


def _build_interval_triage_rows(scans: List[dict], limit: int = 10) -> List[List[str]]:
    """Build per-interval triage queue by level + confidence."""
    risky = [
        s for s in scans
        if (s.get("threat_level") or "").lower() in {"malicious", "critical", "high", "suspicious", "medium"}
    ]
    risky = sorted(risky, key=lambda s: (float(s.get("confidence", 0) or 0), int(s.get("threats_detected", 0) or 0)), reverse=True)[:limit]

    rows: List[List[str]] = [["Queue", "Target", "Type", "Level", "Confidence", "Threats"]]
    if not risky:
        rows.append(["-", "No interval threats", "-", "-", "-", "-"])
        return rows

    for idx, scan in enumerate(risky, 1):
        target = str(scan.get("target") or "-")
        rows.append([
            str(idx),
            target[:44] + ("..." if len(target) > 44 else ""),
            str(scan.get("target_type") or "-")[:10],
            str(scan.get("threat_level") or "-")[:10].upper(),
            f"{float(scan.get('confidence', 0) or 0) * 100:.1f}%",
            str(int(scan.get("threats_detected", 0) or 0)),
        ])
    return rows


def _build_interval_api_gap_rows(scans: List[dict]) -> List[List[str]]:
    """Build interval view of API failure and evidence gaps."""
    counts: Dict[str, Dict[str, int]] = {}
    for scan in scans:
        for _key, entry in _extract_api_status_map(scan).items():
            name = str(entry.get("name") or _key or "unknown")
            status = str(entry.get("status") or "unknown").lower()
            if status == "not_applicable":
                continue
            bucket = counts.setdefault(name, {
                "checked": 0,
                "pending": 0,
                "rate_limited": 0,
                "not_authorized": 0,
                "error": 0,
                "not_configured": 0,
                "unknown": 0,
            })
            if status in bucket:
                bucket[status] += 1
            else:
                bucket["unknown"] += 1

    rows: List[List[str]] = [["API", "Checked", "Pending", "Rate", "Auth", "Primary Gap"]]
    if not counts:
        rows.append(["-", "0", "0", "0", "0", "No API telemetry in interval"])
        return rows

    for api_name in sorted(counts.keys()):
        c = counts[api_name]
        failure_candidates = {
            "rate_limited": c["rate_limited"],
            "not_authorized": c["not_authorized"],
            "error": c["error"] + c["unknown"],
            "not_configured": c["not_configured"],
            "pending": c["pending"],
        }
        top_gap = max(failure_candidates, key=lambda k: failure_candidates[k])
        gap_label_map = {
            "rate_limited": "Rate limiting",
            "not_authorized": "Authorization",
            "error": "Request/API error",
            "not_configured": "Key missing",
            "pending": "Async result delay",
        }
        primary_gap = gap_label_map[top_gap] if failure_candidates[top_gap] > 0 else "None"
        rows.append([
            api_name,
            str(c["checked"]),
            str(c["pending"]),
            str(c["rate_limited"]),
            str(c["not_authorized"]),
            primary_gap,
        ])

    return rows


def _classify_ioc_type(value: str) -> str:
    """Best-effort IOC type classifier for report appendix exports."""
    v = (value or "").strip().lower()
    if not v:
        return "unknown"
    if v.startswith("http://") or v.startswith("https://"):
        return "url"
    if len(v) in {32, 40, 64} and all(c in "0123456789abcdef" for c in v):
        return "hash"
    # rudimentary IPv4 check
    parts = v.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return "ip"
    if "." in v and " " not in v:
        return "domain"
    return "artifact"


def _build_raw_ioc_export_rows(report_data: Dict[str, Any], limit: int = 120) -> List[List[str]]:
    """Build appendix table rows for raw IOC export with first/last seen and source metadata."""
    scans = _collect_scans(report_data)
    ioc_index: Dict[str, Dict[str, Any]] = {}

    for scan in scans:
        scan_id = str(scan.get("scan_id") or "-")
        ts = str(scan.get("timestamp") or "-")
        level = str(scan.get("threat_level") or "unknown").lower()
        confidence = float(scan.get("confidence", 0) or 0)
        indicators = _effective_threat_indicators(scan)

        # Include the scanned target itself as IOC candidate when suspicious/malicious.
        target = str(scan.get("target") or "").strip()
        if target and level in {"suspicious", "malicious", "critical", "high", "medium"}:
            indicators = indicators + [{"indicator": target, "source": "scan_target"}]

        for ind in indicators:
            ioc = str(ind.get("indicator") or "").strip()
            if not ioc:
                continue
            key = ioc.lower()
            row = ioc_index.setdefault(key, {
                "ioc": ioc,
                "type": _classify_ioc_type(ioc),
                "source": set(),
                "max_conf": 0.0,
                "first_seen": ts,
                "last_seen": ts,
                "scan_ids": [],
            })

            src = str(ind.get("source") or "unknown")
            row["source"].add(src)
            row["max_conf"] = max(row["max_conf"], confidence)
            if ts != "-":
                row["first_seen"] = min(row["first_seen"], ts)
                row["last_seen"] = max(row["last_seen"], ts)
            if scan_id not in row["scan_ids"]:
                row["scan_ids"].append(scan_id)

    rows: List[List[str]] = [["IOC", "Type", "Source", "Conf", "First Seen", "Last Seen"]]
    if not ioc_index:
        rows.append(["-", "-", "No IOCs extracted", "-", "-", "-"])
        return rows

    sorted_iocs = sorted(
        ioc_index.values(),
        key=lambda r: (r["max_conf"], len(r["scan_ids"])),
        reverse=True,
    )[:limit]

    for rec in sorted_iocs:
        source_label = ",".join(sorted(rec["source"]))
        if len(source_label) > 18:
            source_label = source_label[:18] + "..."
        ioc_text = rec["ioc"]
        if len(ioc_text) > 46:
            ioc_text = ioc_text[:46] + "..."
        rows.append([
            ioc_text,
            rec["type"],
            source_label,
            f"{rec['max_conf'] * 100:.1f}%",
            str(rec["first_seen"])[:19],
            str(rec["last_seen"])[:19],
        ])

    return rows


def _build_incident_timeline_rows(report_data: Dict[str, Any], limit: int = 140) -> List[List[str]]:
    """Build chronological event rows combining scans, attack events, and defense actions."""
    events: List[Dict[str, str]] = []

    for interval_key, data in report_data.items():
        interval_name = str(data.get("interval") or interval_key)

        scans = _collect_scans({interval_key: data})
        for scan in scans:
            events.append({
                "ts": str(scan.get("timestamp") or "-"),
                "etype": "scan",
                "severity": str(scan.get("threat_level") or "unknown").upper(),
                "target": str(scan.get("target") or "-")[:42],
                "source": interval_name,
                "ref": str(scan.get("scan_id") or "-"),
            })

        for attack in (data.get("attacks") or []):
            events.append({
                "ts": str(attack.get("detected_at") or "-"),
                "etype": "attack",
                "severity": str(attack.get("severity") or "unknown").upper(),
                "target": str(attack.get("source_ip") or "-")[:42],
                "source": str(attack.get("attack_type") or interval_name)[:24],
                "ref": str(attack.get("event_id") or "-")[:20],
            })

        for action in (data.get("defense_actions") or []):
            status = "SUCCESS" if action.get("successful") else str(action.get("status") or "-" ).upper()
            events.append({
                "ts": str(action.get("created_at") or "-"),
                "etype": "defense",
                "severity": status[:10],
                "target": str(action.get("target") or "-")[:42],
                "source": str(action.get("action_type") or interval_name)[:24],
                "ref": str(action.get("action_id") or "-")[:20],
            })

    events = sorted(events, key=lambda e: e.get("ts") or "")[:limit]

    rows: List[List[str]] = [["Timestamp", "Event", "Severity", "Target", "Source", "Reference"]]
    if not events:
        rows.append(["-", "-", "-", "No timeline events", "-", "-"])
        return rows

    for ev in events:
        rows.append([
            str(ev.get("ts") or "-")[:19],
            str(ev.get("etype") or "-").upper(),
            str(ev.get("severity") or "-")[:10],
            str(ev.get("target") or "-")[:42],
            str(ev.get("source") or "-")[:24],
            str(ev.get("ref") or "-")[:20],
        ])

    return rows


def _format_forensic_status(scan: dict) -> str:
    """Format forensic status label for scan card."""
    forensic = _effective_forensic(scan)
    apis_checked = forensic.get("apis_checked", 0)
    corroboration_count = forensic.get("corroboration_count", 0)
    corroborated = forensic.get("corroboration_threshold_met", False)
    threats_detected = int(scan.get("threats_detected", 0) or 0)
    total_apis_available = int(forensic.get("total_apis_available", 0) or 0)
    unavailable_reasons = forensic.get("external_corroboration_unavailable_reasons", [])
    _, tier = _compute_forensic_integrity(scan)

    if corroborated:
        return f"MULTI-SOURCE VERIFIED ({corroboration_count} sources, {tier})"

    if corroboration_count == 1:
        return f"LIMITED CORROBORATION (1 source, {tier})"

    if apis_checked > 0 and corroboration_count <= 0:
        if threats_detected > 0:
            return f"API-VERIFIED, UNCORROBORATED ({apis_checked} API{'s' if apis_checked != 1 else ''}, {tier})"
        return f"VERIFIED CLEAN ({apis_checked} API{'s' if apis_checked != 1 else ''} checked, {tier})"

    if threats_detected > 0 and total_apis_available > 0 and apis_checked == 0:
        if unavailable_reasons:
            reason_text = ", ".join(unavailable_reasons[:2])
            return f"EVIDENCE-LIMITED ({reason_text}, {tier})"
        return f"EVIDENCE-LIMITED (external corroboration unavailable, {tier})"

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

    card_label_style = ParagraphStyle(
        "CardLabelWrap",
        parent=styles["Normal"],
        fontSize=9,
        leading=10,
        textColor=colors.HexColor("#212121"),
        fontName="Helvetica-Bold",
    )
    card_value_style = ParagraphStyle(
        "CardValueWrap",
        parent=styles["Normal"],
        fontSize=9,
        leading=10,
        textColor=colors.HexColor("#212121"),
        fontName="Helvetica",
    )
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

        wrapped_card_data = [
            [
                Paragraph(escape(str(label)).replace("\n", "<br/>"), card_label_style),
                Paragraph(escape(str(value)).replace("\n", "<br/>"), card_value_style),
            ]
            for label, value in card_data
        ]

        card_table = Table(wrapped_card_data, colWidths=[1.6 * inch, 4.9 * inch])
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
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
        ]))

        elements.append(card_table)
        elements.append(Spacer(1, 0.15 * inch))

    return elements
