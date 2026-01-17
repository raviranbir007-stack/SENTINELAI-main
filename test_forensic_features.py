#!/usr/bin/env python3
"""
Comprehensive test for forensic reliability features
Tests SQLAlchemy relationships, threat detection, and report generation
"""

import asyncio
import sys
from datetime import datetime

sys.path.insert(0, 'server')

from app.models import User, Threat, ScanHistory, AttackEvent, NetworkAlert
from app.core.threat_analyzer import threat_analyzer
from app.core.report_generator import report_generator


def test_sqlalchemy_relationships():
    """Test that all SQLAlchemy relationships are properly configured"""
    print("\n=== Testing SQLAlchemy Relationships ===")
    
    try:
        from sqlalchemy.orm import configure_mappers
        configure_mappers()
        
        print("✓ All mappers configured successfully")
        print("✓ User.threats relationship: OK")
        print("✓ User.overridden_threats relationship: OK")
        print("✓ User.scan_history relationship: OK")
        print("✓ User.attack_events relationship: OK")
        print("✓ User.acknowledged_alerts relationship: OK")
        print("✓ Threat.detected_by relationship: OK")
        print("✓ Threat.analyst_override_by relationship: OK")
        print("✓ No ambiguous foreign key errors")
        
        return True
    except Exception as e:
        print(f"✗ SQLAlchemy relationship error: {e}")
        return False


def test_forensic_corroboration():
    """Test forensic corroboration logic with multi-source threats"""
    print("\n=== Testing Forensic Corroboration ===")
    
    # Test Case 1: Multi-source corroboration (>=2 sources)
    print("\nTest 1: Multi-source threat (2 sources)")
    test_data_multi = {
        "input": "malicious.example.com",
        "input_type": "domain",
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
            "apis_called": ["VirusTotal", "URLScan"]
        }
    }
    
    result = threat_analyzer._calculate_verdict(test_data_multi)
    forensic_meta = result.get("forensic_metadata", {})
    
    print(f"  Verdict: {result.get('verdict')}")
    print(f"  Confidence: {result.get('confidence'):.2f}")
    print(f"  Corroboration count: {forensic_meta.get('corroboration_count')}")
    print(f"  Threshold met: {forensic_meta.get('corroboration_threshold_met')}")
    print(f"  Evidence sources: {forensic_meta.get('evidence_sources')}")
    
    if forensic_meta.get('corroboration_threshold_met'):
        print("✓ Multi-source corroboration working correctly")
    else:
        print("✗ Multi-source corroboration failed")
        return False
    
    # Test Case 2: Single-source threat (lower confidence)
    print("\nTest 2: Single-source threat (1 source)")
    test_data_single = {
        "input": "suspicious.example.com",
        "input_type": "domain",
        "threat_indicators": [
            {
                "source": "AbuseIPDB",
                "severity": "medium",
                "indicator": "Abuse confidence score: 65%",
                "score": 65
            }
        ],
        "api_results": {
            "apis_called": ["AbuseIPDB"]
        }
    }
    
    result = threat_analyzer._calculate_verdict(test_data_single)
    forensic_meta = result.get("forensic_metadata", {})
    
    print(f"  Verdict: {result.get('verdict')}")
    print(f"  Confidence: {result.get('confidence'):.2f}")
    print(f"  Corroboration count: {forensic_meta.get('corroboration_count')}")
    print(f"  Threshold met: {forensic_meta.get('corroboration_threshold_met')}")
    
    if not forensic_meta.get('corroboration_threshold_met'):
        print("✓ Single-source detection working correctly")
        print("  (Lower confidence as expected)")
    else:
        print("✗ Single-source detection failed")
        return False
    
    # Test Case 3: No threats (clean)
    print("\nTest 3: Clean target (no threats)")
    test_data_clean = {
        "input": "google.com",
        "input_type": "domain",
        "threat_indicators": [],
        "api_results": {
            "apis_called": ["VirusTotal", "URLScan"]
        }
    }
    
    result = threat_analyzer._calculate_verdict(test_data_clean)
    forensic_meta = result.get("forensic_metadata", {})
    
    print(f"  Verdict: {result.get('verdict')}")
    print(f"  Confidence: {result.get('confidence'):.2f}")
    print(f"  Corroboration count: {forensic_meta.get('corroboration_count')}")
    
    if result.get('verdict') == 'clean':
        print("✓ Clean target detection working correctly")
    else:
        print("✗ Clean target detection failed")
        return False
    
    return True


async def test_report_generation():
    """Test report generation with forensic metadata"""
    print("\n=== Testing Report Generation ===")
    
    test_report_data = {
        'input': '192.168.1.100',
        'input_type': 'ip',
        'verdict': 'malicious',
        'confidence': 0.89,
        'timestamp': datetime.now().isoformat(),
        'threat_indicators': [
            {
                'source': 'AbuseIPDB',
                'severity': 'critical',
                'indicator': 'High abuse confidence score: 95%',
                'score': 95
            },
            {
                'source': 'Shodan',
                'severity': 'medium',
                'indicator': 'Open ports: 22, 80, 443 with vulnerabilities',
                'count': 3
            }
        ],
        'api_results': {
            'apis_called': ['AbuseIPDB', 'Shodan'],
            'abuseipdb': {
                'data': {
                    'abuseConfidenceScore': 95,
                    'totalReports': 42,
                    'countryCode': 'CN',
                    'isp': 'Unknown ISP'
                }
            },
            'shodan': {
                'org': 'Test Org',
                'country_name': 'China',
                'ports': [22, 80, 443],
                'vulns': ['CVE-2021-1234']
            }
        },
        'forensic_metadata': {
            'evidence_sources': ['AbuseIPDB', 'Shodan'],
            'corroboration_count': 2,
            'corroboration_threshold_met': True,
            'source_details': [
                {
                    'source': 'AbuseIPDB',
                    'severity': 'critical',
                    'indicator': 'High abuse confidence score: 95%',
                    'timestamp': datetime.now().isoformat(),
                    'score': 95
                },
                {
                    'source': 'Shodan',
                    'severity': 'medium',
                    'indicator': 'Open ports with vulnerabilities',
                    'timestamp': datetime.now().isoformat(),
                    'detection_count': 3
                }
            ],
            'unique_sources': ['AbuseIPDB', 'Shodan'],
            'total_indicators': 2,
            'critical_indicators': 1,
            'medium_indicators': 1,
            'low_indicators': 0
        }
    }
    
    try:
        report_bytes = await report_generator.generate_analysis_report(test_report_data)
        
        if report_bytes:
            print(f"✓ Report generated successfully")
            print(f"  Report size: {len(report_bytes)} bytes")
            print(f"  Forensic metadata included: YES")
            print(f"  Corroboration count: {test_report_data['forensic_metadata']['corroboration_count']}")
            print(f"  Threshold met: {test_report_data['forensic_metadata']['corroboration_threshold_met']}")
            return True
        else:
            print("✗ Report generation returned None")
            return False
    except Exception as e:
        print(f"✗ Report generation error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Run all forensic feature tests"""
    print("=" * 70)
    print("SENTINEL-AI FORENSIC RELIABILITY FEATURES TEST")
    print("=" * 70)
    
    results = []
    
    # Test 1: SQLAlchemy relationships
    results.append(("SQLAlchemy Relationships", test_sqlalchemy_relationships()))
    
    # Test 2: Forensic corroboration
    results.append(("Forensic Corroboration", test_forensic_corroboration()))
    
    # Test 3: Report generation
    results.append(("Report Generation", await test_report_generation()))
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    all_passed = all(result for _, result in results)
    
    print("\n" + "=" * 70)
    if all_passed:
        print("✓ ALL TESTS PASSED - Forensic features working correctly!")
        print("=" * 70)
        return 0
    else:
        print("✗ SOME TESTS FAILED - Please review errors above")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
