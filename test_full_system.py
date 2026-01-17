#!/usr/bin/env python3
"""
Comprehensive System Test for SentinelAI
Tests all APIs, scanning, and report generation
"""

import asyncio
import json
import sys
from pathlib import Path

# Add server to path
sys.path.insert(0, str(Path(__file__).parent / "server"))

from server.app.core.threat_analyzer import threat_analyzer
from server.app.core.report_generator import report_generator


async def test_ip_scan():
    """Test IP scanning with AbuseIPDB and Shodan"""
    print("\n" + "="*60)
    print("TEST 1: IP Address Scan (8.8.8.8 - Google DNS)")
    print("="*60)
    
    result = await threat_analyzer.analyze("8.8.8.8")
    
    print(f"\n✓ Target: {result['input']}")
    print(f"✓ Type: {result['input_type']}")
    print(f"✓ Verdict: {result['verdict']}")
    print(f"✓ Confidence: {result['confidence']:.2%}")
    print(f"✓ Summary: {result['summary']}")
    
    if result.get('api_results'):
        apis_called = result['api_results'].get('apis_called', [])
        print(f"✓ APIs Called: {', '.join(apis_called)}")
        
        # Check AbuseIPDB results
        if 'abuseipdb' in result['api_results']:
            abuse_data = result['api_results']['abuseipdb']
            if abuse_data.get('success') and abuse_data.get('data'):
                score = abuse_data['data'].get('abuseConfidenceScore', 0)
                country = abuse_data['data'].get('countryCode', 'N/A')
                print(f"  - AbuseIPDB: Score={score}%, Country={country}")
        
        # Check Shodan results
        if 'shodan' in result['api_results']:
            shodan_data = result['api_results']['shodan']
            if shodan_data.get('success'):
                org = shodan_data.get('data', {}).get('org', 'N/A')
                ports = shodan_data.get('data', {}).get('ports', [])
                print(f"  - Shodan: Org={org}, Ports={ports}")
    
    if result.get('threat_indicators'):
        print(f"✓ Threats: {len(result['threat_indicators'])} indicators")
        for indicator in result['threat_indicators'][:3]:  # Show first 3
            print(f"  - [{indicator['severity']}] {indicator['indicator']}")
    
    return result


async def test_url_scan():
    """Test URL scanning with VirusTotal and URLScan"""
    print("\n" + "="*60)
    print("TEST 2: URL Scan (https://google.com)")
    print("="*60)
    
    result = await threat_analyzer.analyze("https://google.com")
    
    print(f"\n✓ Target: {result['input']}")
    print(f"✓ Type: {result['input_type']}")
    print(f"✓ Verdict: {result['verdict']}")
    print(f"✓ Confidence: {result['confidence']:.2%}")
    print(f"✓ Summary: {result['summary']}")
    
    if result.get('api_results'):
        apis_called = result['api_results'].get('apis_called', [])
        print(f"✓ APIs Called: {', '.join(apis_called)}")
        
        # Check VirusTotal
        if 'virustotal' in result['api_results']:
            vt_data = result['api_results']['virustotal']
            if vt_data.get('success'):
                print(f"  - VirusTotal: Checked")
        
        # Check URLScan
        if 'urlscan' in result['api_results']:
            urlscan_data = result['api_results']['urlscan']
            if urlscan_data.get('success'):
                print(f"  - URLScan: Checked")
    
    if result.get('threat_indicators'):
        print(f"✓ Threats: {len(result['threat_indicators'])} indicators")
        for indicator in result['threat_indicators'][:3]:
            print(f"  - [{indicator['severity']}] {indicator['indicator']}")
    
    return result


async def test_domain_scan():
    """Test domain scanning"""
    print("\n" + "="*60)
    print("TEST 3: Domain Scan (example.com)")
    print("="*60)
    
    result = await threat_analyzer.analyze("example.com")
    
    print(f"\n✓ Target: {result['input']}")
    print(f"✓ Type: {result['input_type']}")
    print(f"✓ Verdict: {result['verdict']}")
    print(f"✓ Confidence: {result['confidence']:.2%}")
    print(f"✓ Summary: {result['summary']}")
    
    if result.get('api_results'):
        apis_called = result['api_results'].get('apis_called', [])
        print(f"✓ APIs Called: {', '.join(apis_called)}")
    
    return result


async def test_hash_scan():
    """Test file hash scanning"""
    print("\n" + "="*60)
    print("TEST 4: File Hash Scan (MD5)")
    print("="*60)
    
    # Sample MD5 hash (known EICAR test file)
    test_hash = "44d88612fea8a8f36de82e1278abb02f"
    
    result = await threat_analyzer.analyze(test_hash)
    
    print(f"\n✓ Target: {result['input']}")
    print(f"✓ Type: {result['input_type']}")
    print(f"✓ Verdict: {result['verdict']}")
    print(f"✓ Confidence: {result['confidence']:.2%}")
    print(f"✓ Summary: {result['summary']}")
    
    if result.get('api_results'):
        apis_called = result['api_results'].get('apis_called', [])
        print(f"✓ APIs Called: {', '.join(apis_called)}")
        
        # Check VirusTotal
        if 'virustotal' in result['api_results']:
            vt_data = result['api_results']['virustotal']
            if vt_data.get('success') and vt_data.get('data'):
                attrs = vt_data['data'].get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                print(f"  - VirusTotal: Malicious={malicious}, Suspicious={suspicious}")
    
    if result.get('threat_indicators'):
        print(f"✓ Threats: {len(result['threat_indicators'])} indicators")
        for indicator in result['threat_indicators'][:5]:
            print(f"  - [{indicator['severity']}] {indicator['indicator']}")
    
    return result


async def test_report_generation(scan_result):
    """Test PDF report generation with Gemini AI"""
    print("\n" + "="*60)
    print("TEST 5: Report Generation with Gemini AI")
    print("="*60)
    
    print(f"\n✓ Generating report for: {scan_result['input']}")
    
    # Add report_id for PDF generation
    scan_result['report_id'] = f"TEST_RPT_{int(asyncio.get_event_loop().time())}"
    
    pdf_bytes = await report_generator.generate_analysis_report(scan_result)
    
    if pdf_bytes:
        print(f"✓ Report generated: {len(pdf_bytes)} bytes")
        
        # Save to file for inspection
        output_file = f"/home/kali/Documents/SENTINELAI-main/test_report_{scan_result['input_type']}.pdf"
        with open(output_file, "wb") as f:
            f.write(pdf_bytes)
        print(f"✓ Saved to: {output_file}")
        
        return True
    else:
        print("✗ Report generation failed")
        return False


async def test_unique_reports():
    """Test that different scans produce unique reports"""
    print("\n" + "="*60)
    print("TEST 6: Report Uniqueness")
    print("="*60)
    
    # Scan two different targets
    targets = ["8.8.8.8", "1.1.1.1"]
    reports = []
    
    for target in targets:
        print(f"\n✓ Scanning {target}...")
        result = await threat_analyzer.analyze(target)
        result['report_id'] = f"UNIQUE_TEST_{target.replace('.', '_')}"
        
        pdf_bytes = await report_generator.generate_analysis_report(result)
        
        if pdf_bytes:
            reports.append({
                'target': target,
                'size': len(pdf_bytes),
                'verdict': result['verdict'],
                'confidence': result['confidence']
            })
            print(f"  - Generated: {len(pdf_bytes)} bytes, verdict={result['verdict']}")
    
    # Check uniqueness
    if len(reports) == 2:
        if reports[0]['size'] != reports[1]['size']:
            print("\n✓ SUCCESS: Reports have different sizes (unique content)")
        else:
            print("\n⚠ WARNING: Reports have same size (may be similar)")
        
        print("\nReport Comparison:")
        for r in reports:
            print(f"  - {r['target']}: {r['size']} bytes, {r['verdict']} ({r['confidence']:.0%} confidence)")
        
        return True
    
    return False


async def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("SENTINELAI COMPREHENSIVE SYSTEM TEST")
    print("="*60)
    print("\nThis will test:")
    print("1. IP scanning (AbuseIPDB + Shodan)")
    print("2. URL scanning (VirusTotal + URLScan)")
    print("3. Domain scanning")
    print("4. File hash scanning (VirusTotal + Hybrid Analysis)")
    print("5. PDF report generation with Gemini AI")
    print("6. Report uniqueness verification")
    
    results = {}
    
    try:
        # Test 1: IP Scan
        results['ip_scan'] = await test_ip_scan()
        
        # Test 2: URL Scan
        results['url_scan'] = await test_url_scan()
        
        # Test 3: Domain Scan
        results['domain_scan'] = await test_domain_scan()
        
        # Test 4: Hash Scan
        results['hash_scan'] = await test_hash_scan()
        
        # Test 5: Report Generation (use hash scan as it's likely to have threats)
        results['report_gen'] = await test_report_generation(results['hash_scan'])
        
        # Test 6: Unique Reports
        results['unique_reports'] = await test_unique_reports()
        
        # Summary
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        
        passed = sum(1 for k, v in results.items() if v and (isinstance(v, dict) or v is True))
        total = len(results)
        
        print(f"\n✓ Tests Passed: {passed}/{total}")
        
        if passed == total:
            print("\n🎉 ALL TESTS PASSED! System is working correctly.")
        else:
            print("\n⚠ Some tests failed. Check output above for details.")
        
        # Save detailed results
        with open("/home/kali/Documents/SENTINELAI-main/test_results.json", "w") as f:
            # Convert results to JSON-serializable format
            json_results = {}
            for key, value in results.items():
                if isinstance(value, dict):
                    # Remove non-serializable fields
                    json_results[key] = {
                        'input': value.get('input'),
                        'input_type': value.get('input_type'),
                        'verdict': value.get('verdict'),
                        'confidence': value.get('confidence'),
                        'threats': len(value.get('threat_indicators', [])),
                        'apis_called': value.get('api_results', {}).get('apis_called', [])
                    }
                else:
                    json_results[key] = value
            
            json.dump(json_results, f, indent=2)
        
        print("\n✓ Detailed results saved to: test_results.json")
        
    except Exception as e:
        print(f"\n✗ Test failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
