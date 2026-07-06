#!/usr/bin/env python3
"""Test script to verify report generation fix"""
import sys
import asyncio
sys.path.insert(0, 'server')

from app.core.report_generator import ReportGenerator
from datetime import datetime, timedelta, timezone

async def test_report_generation():
    """Test report generation with sample threat data"""
    generator = ReportGenerator()
    
    # Create sample threat data
    threat_data = {
        "input": "192.168.1.100",
        "input_type": "ip",
        "verdict": "suspicious",
        "confidence": 0.75,
        "report_type": "technical_analysis",
        "threat_indicators": [
            {
                "type": "ip",
                "value": "192.168.1.100",
                "verdict": "suspicious",
                "source": "threat_intel",
                "confidence": 0.75
            }
        ],
        "forensic_metadata": {
            "activity_count": 42,
            "scan_events": 5,
            "corroboration_count": 2,
            "time_window": "7d"
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    
    print("🔍 Testing report generation...")
    print(f"Report type: {threat_data['report_type']}")
    print(f"Threat confidence: {threat_data['confidence']}")
    
    try:
        # Generate AI analysis
        print("\n📊 Generating AI analysis...")
        ai_analysis = await generator._generate_ai_analysis(threat_data)
        
        # Check if AI analysis is complete
        ai_word_count = len(ai_analysis.split())
        print(f"✅ AI analysis generated")
        print(f"   Word count: {ai_word_count}")
        print(f"   Length: {len(ai_analysis)} chars")
        print(f"   Preview: {ai_analysis[:200]}...")
        
        # Check sanitization
        sanitized = generator._sanitize_ai_output(ai_analysis, threat_data['report_type'])
        if sanitized:
            print(f"✅ AI analysis passed sanitization")
            print(f"   Sanitized length: {len(sanitized)} chars")
        else:
            print(f"❌ AI analysis FAILED sanitization!")
            print(f"   Original word count: {ai_word_count}")
            print(f"   This indicates the validation is too strict")
        
        # Try to generate full report
        print("\n📄 Generating PDF report...")
        pdf_bytes = await generator.generate_analysis_report(threat_data)
        if pdf_bytes:
            print(f"✅ Report generated successfully")
            print(f"   Size: {len(pdf_bytes)} bytes")
            
            # Save for inspection
            with open('/home/kali/Documents/SENTINELAI-main/test_report_output.pdf', 'wb') as f:
                f.write(pdf_bytes)
            print(f"   Saved to: test_report_output.pdf")
        else:
            print(f"❌ Report generation returned None")
        
    except Exception as e:
        print(f"❌ Error during test: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_report_generation())
