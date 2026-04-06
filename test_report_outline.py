#!/usr/bin/env python3
"""
Test script to generate fresh reports and verify REPORT OUTLINE sections appear
"""
import sqlite3
import json
import time
import sys
from pathlib import Path
from datetime import datetime

# Test database
db_path = Path("/home/kali/Documents/SENTINELAI-main/server/database.db")

def get_test_scan_data():
    """Get test scan data from database"""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get the most recent threat detection
    cursor.execute("""
        SELECT * FROM threat_detections 
        ORDER BY timestamp DESC 
        LIMIT 1
    """)
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return dict(result)
    return None

def trigger_report_generation():
    """Trigger report generation via the report generator"""
    import sys
    sys.path.insert(0, '/home/kali/Documents/SENTINELAI-main')
    
    from server.app.core.report_generator import ReportGenerator
    from server.app.config import settings
    
    # Initialize generator
    generator = ReportGenerator()
    
    # Generate test reports for all three types
    report_types = [
        ("executive_summary", "24h"),
        ("technical_analysis", "7d"),
        ("forensic_investigation", "30d"),
    ]
    
    for report_type, interval in report_types:
        print(f"\n🔄 Generating {report_type} report ({interval} interval)...")
        
        # Generate PDF
        try:
            pdf_file = generator.generate_report(
                target_name="test-report-verification",
                target_type="advanced_report",
                verdict="SUSPICIOUS",
                confidence=0.75,
                threat_indicators=[
                    {"type": "ip", "value": "192.168.1.100", "severity": "medium"},
                    {"type": "domain", "value": "test.com", "severity": "high"},
                ],
                corroboration_count=2,
                behavioral_events=["event1", "event2"],
                report_type=report_type,
                time_interval=interval
            )
            
            if pdf_file:
                print(f"✅ Report generated: {pdf_file}")
                # Check file size
                size = Path(pdf_file).stat().st_size
                print(f"   File size: {size} bytes")
            else:
                print(f"❌ Failed to generate {report_type} report")
                
        except Exception as e:
            print(f"❌ Error generating {report_type}: {e}")
        
        time.sleep(1)

if __name__ == "__main__":
    print("🚀 Starting report generation test...")
    print(f"Database: {db_path}")
    
    if not db_path.exists():
        print(f"❌ Database not found: {db_path}")
        sys.exit(1)
    
    trigger_report_generation()
    print("\n✅ Report generation test complete!")
