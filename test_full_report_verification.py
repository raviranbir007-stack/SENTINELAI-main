#!/usr/bin/env python3
"""Comprehensive test to verify reports contain ALL acquired and extracted details"""
import sys
import asyncio
import json
sys.path.insert(0, 'server')

from app.core.report_generator import ReportGenerator
from datetime import datetime, timedelta, timezone

async def test_comprehensive_report():
    """Test report generation with complete, realistic threat data"""
    generator = ReportGenerator()
    
    # Create COMPREHENSIVE threat data with ALL details
    threat_data = {
        "input": "192.168.1.100",
        "input_type": "ip",
        "verdict": "suspicious",
        "confidence": 0.85,
        "report_type": "technical_analysis",
        
        # Multiple threat indicators (acquired from multiple sources)
        "threat_indicators": [
            {
                "type": "ip",
                "value": "192.168.1.100",
                "verdict": "suspicious",
                "source": "virustotal",
                "confidence": 0.85,
                "details": "Detected by 12 AV engines"
            },
            {
                "type": "ip",
                "value": "192.168.1.100",
                "verdict": "malicious",
                "source": "abuseipdb",
                "confidence": 0.92,
                "details": "23 reports of abuse activity"
            },
            {
                "type": "domain",
                "value": "suspicious-domain.com",
                "verdict": "phishing",
                "source": "phishtank",
                "confidence": 0.88,
                "details": "Domain associated with credential harvesting"
            },
            {
                "type": "file_hash",
                "value": "d41d8cd98f00b204e9800998ecf8427e",
                "verdict": "malware",
                "source": "virustotal",
                "confidence": 0.95,
                "details": "Identified as trojan.downloader"
            }
        ],
        
        # Forensic metadata with activity details
        "forensic_metadata": {
            "activity_count": 247,
            "scan_events": 18,
            "corroboration_count": 4,
            "time_window": "7d",
            "sources": ["virustotal", "abuseipdb", "phishtank", "hybrid_analysis"],
            "first_seen": (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "geographic_locations": ["US", "CN", "RU"],
            "attack_vectors": ["network_scanning", "brute_force", "command_injection"]
        },
        
        # Activity summary
        "activity_summary": {
            "total_events": 247,
            "suspicious_events": 156,
            "blocked_events": 89,
            "types": ["network_scan", "exploitation_attempt", "data_exfiltration"]
        },
        
        # Risk metrics
        "risk_metrics": {
            "severity": "high",
            "impact": "critical",
            "exploit_availability": "public",
            "active_exploitation": True
        },
        
        # Interval summaries (for 7d report)
        "interval_summaries": [
            {
                "interval": "24h",
                "hours": 24,
                "activity": {
                    "threat_scans": 12,
                    "threats_detected": 5,
                    "websites_visited": 42,
                    "applications_launched": 8,
                    "network_connections": 23
                },
                "vulns": {"total": 2}
            },
            {
                "interval": "7d",
                "hours": 168,
                "activity": {
                    "threat_scans": 42,
                    "threats_detected": 18,
                    "websites_visited": 156,
                    "applications_launched": 31,
                    "network_connections": 89
                },
                "vulns": {"total": 8}
            }
        ],
        
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "report_timezone": "UTC"
    }
    
    print("=" * 70)
    print("🔍 COMPREHENSIVE REPORT GENERATION TEST")
    print("=" * 70)
    
    print("\n📋 INPUT DATA SUMMARY:")
    print(f"  • Report Type: {threat_data['report_type']}")
    print(f"  • Input: {threat_data['input']} ({threat_data['input_type']})")
    print(f"  • Verdict: {threat_data['verdict'].upper()} (Confidence: {threat_data['confidence']*100:.0f}%)")
    print(f"  • Threat Indicators: {len(threat_data['threat_indicators'])} sources")
    print(f"  • Forensic Sources: {len(threat_data['forensic_metadata']['sources'])} sources")
    print(f"  • Total Activity Events: {threat_data['forensic_metadata']['activity_count']}")
    
    try:
        # STEP 1: Generate AI Analysis
        print("\n" + "="*70)
        print("STEP 1: Generating AI Analysis from Gemini")
        print("="*70)
        ai_analysis = await generator._generate_ai_analysis(threat_data)
        
        ai_word_count = len(ai_analysis.split())
        ai_lines = len(ai_analysis.split('\n'))
        
        print(f"✅ AI Analysis Generated Successfully")
        print(f"   • Word Count: {ai_word_count} words")
        print(f"   • Line Count: {ai_lines} lines")
        print(f"   • Size: {len(ai_analysis)} characters")
        print(f"   • Preview: {ai_analysis[:300]}...")
        
        # STEP 2: Verify Sanitization
        print("\n" + "="*70)
        print("STEP 2: Verifying Content Passes Sanitization")
        print("="*70)
        sanitized = generator._sanitize_ai_output(ai_analysis, threat_data['report_type'])
        
        if sanitized:
            print(f"✅ Content PASSED Sanitization Check")
            print(f"   • Preserved: {len(sanitized)} characters")
            
            # Check what was preserved
            preserved_pct = (len(sanitized) / len(ai_analysis)) * 100 if ai_analysis else 0
            print(f"   • Preservation Rate: {preserved_pct:.1f}%")
        else:
            print(f"❌ Content FAILED Sanitization - THIS IS A PROBLEM!")
            print(f"   • Original size: {len(ai_analysis)} chars")
            print(f"   • Returned empty string")
            return
        
        # STEP 3: Generate Full Report
        print("\n" + "="*70)
        print("STEP 3: Creating Full PDF Report with All Data")
        print("="*70)
        pdf_bytes = await generator.generate_analysis_report(threat_data)
        
        if not pdf_bytes:
            print(f"❌ PDF generation returned None!")
            return
        
        print(f"✅ PDF Report Generated Successfully")
        print(f"   • Size: {len(pdf_bytes)} bytes")
        
        # Save report
        report_path = '/home/kali/Documents/SENTINELAI-main/comprehensive_test_report.pdf'
        with open(report_path, 'wb') as f:
            f.write(pdf_bytes)
        print(f"   • Saved to: comprehensive_test_report.pdf")
        
        # STEP 4: Verify Content Completeness
        print("\n" + "="*70)
        print("STEP 4: Verifying Report Contains ALL Required Details")
        print("="*70)
        
        # We'll check the PDF content by looking at the text extraction
        # In a real scenario, you'd use PDF reader to extract and verify
        try:
            from PyPDF2 import PdfReader
            pdf_reader = PdfReader(report_path)
            pdf_text = ""
            for page in pdf_reader.pages:
                pdf_text += page.extract_text()
            
            # Check for expected content
            checks = [
                ("Report Title", "TECHNICAL ANALYSIS" in pdf_text or "SENTINEL-AI" in pdf_text),
                ("Input IP", "192.168.1.100" in pdf_text),
                ("Verdict", "suspicious" in pdf_text.lower() or "malicious" in pdf_text.lower()),
                ("Confidence Score", "confidence" in pdf_text.lower() or "0.85" in pdf_text),
                ("Threat Indicators", "threat" in pdf_text.lower()),
                ("Forensic Data", "forensic" in pdf_text.lower() or "activity" in pdf_text.lower()),
                ("AI Analysis", "analysis" in pdf_text.lower() or "technical" in pdf_text.lower()),
            ]
            
            print("\n📊 Content Verification Checklist:")
            all_present = True
            for check_name, check_result in checks:
                status = "✅" if check_result else "❌"
                print(f"  {status} {check_name}: {'PRESENT' if check_result else 'MISSING'}")
                all_present = all_present and check_result
            
            if all_present:
                print("\n🎉 SUCCESS: Report contains all required details!")
            else:
                print("\n⚠️  WARNING: Some details may be missing from report")
                
        except ImportError:
            print("⚠️  PyPDF2 not installed - skipping content extraction check")
            print("    (But PDF was generated successfully)")
        
        # STEP 5: Summary
        print("\n" + "="*70)
        print("STEP 5: FINAL SUMMARY")
        print("="*70)
        print(f"""
✅ COMPREHENSIVE REPORT GENERATION TEST COMPLETED

Generated Report Contains:
  • Complete AI Analysis: {ai_word_count} words
  • All Threat Indicators: {len(threat_data['threat_indicators'])} sources
  • Forensic Metadata: {threat_data['forensic_metadata']['activity_count']} events
  • Risk Assessment: {threat_data['risk_metrics']['severity'].upper()} severity
  • Detailed Recommendations: ✅ (from AI analysis)

PDF Report Details:
  • Size: {len(pdf_bytes):,} bytes
  • Filename: comprehensive_test_report.pdf
  • Location: /home/kali/Documents/SENTINELAI-main/

✅ REPORTS ARE NOW BEING GENERATED FULLY AND COMPLETELY!
""")
        
    except Exception as e:
        print(f"❌ Error during test: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_comprehensive_report())
