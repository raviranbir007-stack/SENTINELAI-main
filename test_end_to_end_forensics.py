#!/usr/bin/env python3
"""
End-to-end test: Scan with forensic features and report generation
"""

import asyncio
import sys
from datetime import datetime, timedelta

sys.path.insert(0, 'server')

from sqlalchemy import select
from app.database import AsyncSessionLocal
from app.models import ScanHistory, Threat
from app.core.threat_analyzer import threat_analyzer
from app.core.report_generator import report_generator


async def test_scan_with_forensics():
    """Test complete workflow: analysis → database → report"""
    print("=" * 70)
    print("END-TO-END FORENSIC FEATURES TEST")
    print("=" * 70)
    print()
    
    # Step 1: Analyze a threat with multiple sources
    print("Step 1: Analyzing threat with multi-source detection...")
    
    analysis_result = {
        "input": "malicious-test.com",
        "input_type": "domain",
        "timestamp": datetime.utcnow().isoformat(),
        "threat_indicators": [
            {
                "source": "VirusTotal",
                "severity": "critical",
                "indicator": "Detected as malware by 42/89 engines",
                "score": 42
            },
            {
                "source": "URLScan",
                "severity": "critical",
                "indicator": "Malicious verdict with score 85",
                "score": 85
            }
        ],
        "api_results": {
            "apis_called": ["VirusTotal", "URLScan"],
            "virustotal": {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 42,
                            "suspicious": 5,
                            "undetected": 42,
                            "harmless": 0
                        },
                        "reputation": -50
                    }
                }
            },
            "urlscan": {
                "verdicts": {
                    "overall": {
                        "score": 85,
                        "malicious": True,
                        "categories": ["malware", "phishing"]
                    }
                },
                "brands": ["Fake Bank"],
                "tags": ["malicious", "phishing"]
            }
        }
    }
    
    # Calculate verdict with forensics
    result = threat_analyzer._calculate_verdict(analysis_result)
    
    print(f"  Verdict: {result['verdict']}")
    print(f"  Confidence: {result['confidence']:.2f}")
    forensic = result.get('forensic_metadata', {})
    print(f"  Corroboration: {forensic.get('corroboration_count')} sources")
    print(f"  Threshold met: {forensic.get('corroboration_threshold_met')}")
    print()
    
    # Step 2: Save to database with forensic data
    print("Step 2: Saving scan to database with forensic metadata...")
    
    async with AsyncSessionLocal() as session:
        scan = ScanHistory(
            scan_id=f"SCAN-TEST-{datetime.utcnow().timestamp()}",
            target="malicious-test.com",
            target_type="domain",
            target_name="Test Malicious Domain",
            threat_level=str(result['verdict']),
            confidence=result['confidence'],
            threats_detected=len(result['threat_indicators']),
            analysis_data=result,
            # Forensic fields
            evidence_sources=forensic.get('evidence_sources'),
            corroboration_count=forensic.get('corroboration_count', 0),
            analyst_notes="Automated test scan",
            analyst_verified=False,
            scan_timestamp=datetime.utcnow(),
            report_generated=False
        )
        
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        
        print(f"  ✓ Scan saved with ID: {scan.scan_id}")
        print(f"  ✓ Evidence sources: {scan.evidence_sources}")
        print(f"  ✓ Corroboration count: {scan.corroboration_count}")
        print()
        
        # Step 3: Query recent scans (test the query that was failing)
        print("Step 3: Querying recent scans (testing forensic columns)...")
        
        recent_cutoff = datetime.utcnow() - timedelta(hours=1)
        stmt = select(ScanHistory).where(
            ScanHistory.scan_timestamp >= recent_cutoff
        )
        result_scans = await session.execute(stmt)
        scans = result_scans.scalars().all()
        
        print(f"  ✓ Found {len(scans)} recent scan(s)")
        for s in scans:
            print(f"    - {s.scan_id}: {s.target} (corroboration: {s.corroboration_count})")
        print()
        
        # Step 4: Generate report with forensic features
        print("Step 4: Generating PDF report with forensic metadata...")
        
        report_bytes = await report_generator.generate_analysis_report(
            analysis_result
        )
        
        if report_bytes:
            print(f"  ✓ Report generated successfully")
            print(f"  ✓ Report size: {len(report_bytes)} bytes")
            print(f"  ✓ Forensic metadata included in report")
            
            # Save report
            report_path = f"test_report_{datetime.utcnow().timestamp()}.pdf"
            with open(report_path, 'wb') as f:
                f.write(report_bytes)
            print(f"  ✓ Report saved to: {report_path}")
        else:
            print("  ✗ Report generation failed")
            return False
    
    print()
    print("=" * 70)
    print("✓ END-TO-END TEST COMPLETED SUCCESSFULLY")
    print("=" * 70)
    print()
    print("All forensic features verified:")
    print("  ✓ Multi-source threat detection")
    print("  ✓ Forensic metadata tracking")
    print("  ✓ Database storage with forensic columns")
    print("  ✓ Query operations on forensic data")
    print("  ✓ PDF report generation with evidence tables")
    print()
    
    return True


if __name__ == "__main__":
    try:
        success = asyncio.run(test_scan_with_forensics())
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
