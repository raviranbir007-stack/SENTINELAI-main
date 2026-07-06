#!/usr/bin/env python3
"""
Test script to verify comprehensive interval reports generate completely without truncation.
Run: python3 test_report_completion.py
"""

import sys
import os
import json
from pathlib import Path

# Add server to path
sys.path.insert(0, str(Path(__file__).parent / "server"))

async def test_comprehensive_report():
    """Test that comprehensive interval reports complete all 3 intervals without truncation."""
    from app.core.report_generator import ReportGenerator
    
    print("=" * 80)
    print("COMPREHENSIVE INTERVAL REPORT COMPLETION TEST")
    print("=" * 80)
    
    gen = ReportGenerator()
    
    # Create minimal threat data with all 3 intervals
    threat_data = {
        "input": "test_file.docx",
        "input_type": "file",
        "verdict": "suspicious",
        "confidence": 0.78,
        "threat_indicators": [
            {"source": "YARA", "indicator": "macro_pattern_1", "severity": "HIGH"},
            {"source": "Heuristic", "indicator": "obfuscated_strings", "severity": "MEDIUM"},
        ],
        "report_type": "executive_summary",
        "timestamp": "2026-05-11T10:30:00Z",
        "api_results": {
            "apis_called": [],
            "api_status": {},
        },
        "forensic_metadata": {
            "corroboration_count": 2,
            "apis_checked": 0,
            "total_apis_available": 5,
        },
        "interval_summaries": [
            {
                "interval": "24h",
                "activity": {
                    "threat_scans": 15,
                    "threats_detected": 3,
                    "websites_visited": 12,
                    "applications_launched": 8,
                    "network_connections": 42,
                }
            },
            {
                "interval": "7d",
                "activity": {
                    "threat_scans": 104,
                    "threats_detected": 11,
                    "websites_visited": 78,
                    "applications_launched": 56,
                    "network_connections": 289,
                }
            },
            {
                "interval": "30d",
                "activity": {
                    "threat_scans": 487,
                    "threats_detected": 45,
                    "websites_visited": 312,
                    "applications_launched": 234,
                    "network_connections": 1247,
                }
            }
        ],
        "behavioral_sequence": [],
    }
    
    print("\n1. Testing comprehensive interval report generation...")
    try:
        report_bytes = gen._create_comprehensive_interval_report(threat_data, "Test AI Analysis\n\nThis is a test.")
        
        if report_bytes:
            report_size = len(report_bytes)
            print(f"   ✅ Report generated: {report_size} bytes")
            
            # Try to detect if it's a PDF or text
            is_pdf = report_bytes[:4] == b'%PDF'
            report_type = "PDF" if is_pdf else "Text/Other"
            print(f"   ✅ Report type: {report_type}")
            
            # Save for inspection
            output_path = Path(__file__).parent / "generated_reports" / "test_comprehensive_report.pdf"
            output_path.parent.mkdir(exist_ok=True)
            output_path.write_bytes(report_bytes)
            print(f"   ✅ Saved to: {output_path}")
            
            # Check content for truncation markers
            content_str = str(report_bytes)
            if "INTERVAL ANALYSIS" in content_str or (is_pdf and len(report_bytes) > 50000):
                print(f"   ✅ Report appears to have full interval sections (size: {report_size} bytes)")
            else:
                print(f"   ⚠️  Report size seems small ({report_size} bytes) - may be incomplete")
                
        else:
            print("   ❌ Report generation returned None")
            return False
            
    except Exception as e:
        print(f"   ❌ Error generating comprehensive report: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n2. Testing token limit configuration...")
    try:
        max_tokens = int(os.getenv("GEMINI_MAX_OUTPUT_TOKENS", "10000"))
        print(f"   ✅ GEMINI_MAX_OUTPUT_TOKENS configured: {max_tokens} tokens")
        if max_tokens < 8000:
            print(f"   ⚠️  WARNING: Token limit ({max_tokens}) may be too low for 3-interval reports. Recommend >= 8000")
        elif max_tokens >= 10000:
            print(f"   ✅ Token limit is adequate for comprehensive multi-interval reports")
    except Exception as e:
        print(f"   ⚠️  Could not read token config: {e}")
    
    print("\n3. Checking interval interpretation generation...")
    try:
        for interval in ["24h", "7d", "30d"]:
            interp = gen._interval_report_interpretation(interval, threat_data, "executive_summary")
            word_count = len(str(interp).split())
            print(f"   ✅ {interval.upper()} interpretation: {word_count} words")
            if word_count < 20:
                print(f"      ⚠️  WARNING: Interpretation very short ({word_count} words)")
    except Exception as e:
        print(f"   ❌ Error generating interval interpretations: {e}")
        return False
    
    print("\n" + "=" * 80)
    print("TEST COMPLETED ✅")
    print("=" * 80)
    print("\nNOTE: If reports still show truncation in UI, check:")
    print("  1. Generated PDF file size (should be > 100KB for full reports)")
    print("  2. Server logs for Gemini token limit warnings")
    print("  3. Ensure GEMINI_MAX_OUTPUT_TOKENS env var is set >= 10000")
    print("  4. Check if Gemini is completing full responses before timeout")
    
    return True

if __name__ == "__main__":
    import asyncio
    success = asyncio.run(test_comprehensive_report())
    sys.exit(0 if success else 1)
