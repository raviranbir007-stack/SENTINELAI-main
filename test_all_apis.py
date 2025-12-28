#!/usr/bin/env python3
"""
Comprehensive API Integration Test
Tests all 5 external APIs to ensure they're functioning correctly
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add server to path
sys.path.insert(0, str(Path(__file__).parent.parent / "server"))

from app.services.virus_total import VirusTotalService
from app.services.abuseipdb import AbuseIPDBService
from app.services.shodan import ShodanService
from app.services.hybrid_analysis import HybridAnalysisService
from app.services.urlscan import URLScanService
from app.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def test_virustotal():
    """Test VirusTotal API"""
    print("\n" + "="*60)
    print("🔍 Testing VirusTotal API")
    print("="*60)
    
    # Test 1: Scan a known safe file hash (SHA256 of empty file)
    safe_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    print(f"\n📁 Test 1: Scanning safe file hash...")
    print(f"   Hash: {safe_hash}")
    
    result = await VirusTotalService.scan_file(safe_hash)
    
    if "error" in result:
        print(f"   ⚠️  Error: {result['error']}")
        if "not configured" in result['error']:
            print("   💡 Tip: Set VIRUSTOTAL_API_KEY in .env file")
        return False
    else:
        print(f"   ✅ Response received from VirusTotal")
        if "data" in result:
            stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            print(f"   📊 Stats: Malicious={stats.get('malicious', 0)}, "
                  f"Suspicious={stats.get('suspicious', 0)}, "
                  f"Undetected={stats.get('undetected', 0)}")
    
    # Test 2: Scan URL
    test_url = "https://www.google.com"
    print(f"\n🌐 Test 2: Scanning URL...")
    print(f"   URL: {test_url}")
    
    result = await VirusTotalService.scan_url(test_url)
    
    if "error" in result:
        print(f"   ⚠️  Error: {result['error']}")
        return False
    else:
        print(f"   ✅ URL scan submitted successfully")
        if "data" in result:
            print(f"   📊 Scan ID: {result.get('data', {}).get('id', 'N/A')}")
    
    return True


async def test_abuseipdb():
    """Test AbuseIPDB API"""
    print("\n" + "="*60)
    print("🔍 Testing AbuseIPDB API")
    print("="*60)
    
    # Test with Google DNS (known clean IP)
    test_ip = "8.8.8.8"
    print(f"\n📍 Testing IP: {test_ip} (Google DNS)")
    
    result = await AbuseIPDBService.check_ip(test_ip)
    
    if "error" in result:
        print(f"   ⚠️  Error: {result['error']}")
        if "not configured" in result['error']:
            print("   💡 Tip: Set ABUSEIPDB_API_KEY in .env file")
        return False
    else:
        print(f"   ✅ Response received from AbuseIPDB")
        if "data" in result:
            data = result.get("data", {})
            print(f"   📊 Abuse Confidence Score: {data.get('abuseConfidenceScore', 0)}%")
            print(f"   📊 Total Reports: {data.get('totalReports', 0)}")
            print(f"   📊 Country: {data.get('countryCode', 'N/A')}")
            print(f"   📊 ISP: {data.get('isp', 'N/A')[:50]}...")
    
    return True


async def test_shodan():
    """Test Shodan API"""
    print("\n" + "="*60)
    print("🔍 Testing Shodan API")
    print("="*60)
    
    # Test with Google DNS
    test_ip = "8.8.8.8"
    print(f"\n📍 Testing IP: {test_ip} (Google DNS)")
    
    result = await ShodanService.search_ip(test_ip)
    
    if "error" in result:
        print(f"   ⚠️  Error: {result['error']}")
        if "not configured" in result['error']:
            print("   💡 Tip: Set SHODAN_API_KEY in .env file")
        return False
    else:
        print(f"   ✅ Response received from Shodan")
        print(f"   📊 Organization: {result.get('org', 'N/A')}")
        print(f"   📊 Hostnames: {result.get('hostnames', [])}")
        ports = result.get('ports', [])
        print(f"   📊 Open Ports: {len(ports)} - {ports[:10]}")
        vulns = result.get('vulns', [])
        if vulns:
            print(f"   ⚠️  Vulnerabilities: {len(vulns)} found")
        else:
            print(f"   ✅ No vulnerabilities found")
    
    return True


async def test_hybrid_analysis():
    """Test Hybrid Analysis API"""
    print("\n" + "="*60)
    print("🔍 Testing Hybrid Analysis API")
    print("="*60)
    
    # Test with EICAR test file hash (standard malware test)
    eicar_hash = "44d88612fea8a8f36de82e1278abb02f"  # MD5 of EICAR
    print(f"\n📁 Testing hash: {eicar_hash}")
    print(f"   (EICAR test malware sample)")
    
    result = await HybridAnalysisService.search_hash(eicar_hash)
    
    if "error" in result:
        print(f"   ⚠️  Error: {result['error']}")
        if "not configured" in result['error']:
            print("   💡 Tip: Set HYBRID_ANALYSIS_API_KEY in .env file")
        return False
    else:
        print(f"   ✅ Response received from Hybrid Analysis")
        results = result.get("results", [])
        if results:
            print(f"   📊 Found {len(results)} analysis result(s)")
            for idx, item in enumerate(results[:3], 1):
                print(f"   📊 Result {idx}:")
                print(f"      Verdict: {item.get('verdict', 'N/A')}")
                print(f"      Threat Score: {item.get('threat_score', 0)}/100")
        else:
            print(f"   ℹ️  No previous analysis found for this hash")
    
    return True


async def test_urlscan():
    """Test URLScan.io API"""
    print("\n" + "="*60)
    print("🔍 Testing URLScan.io API")
    print("="*60)
    
    # Test with a less popular URL (popular ones get blocked)
    test_url = "https://example.org"
    print(f"\n🌐 Testing URL: {test_url}")
    print(f"   Note: Popular URLs like google.com may be blocked by URLScan policy")
    
    result = await URLScanService.scan_url(test_url)
    
    if "error" in result:
        error_msg = result['error']
        print(f"   ⚠️  Error: {error_msg}")
        
        # If it's blocked due to policy, API is still working
        if "blocked" in result.get("status", "") or "blocked" in error_msg.lower():
            print(f"   ✅ API is working but domain is blocked by policy")
            return True
        elif "not configured" in error_msg:
            print("   💡 Tip: Set URLSCAN_API_KEY in .env file")
            return False
        else:
            return False
    else:
        print(f"   ✅ Scan submitted to URLScan.io")
        print(f"   📊 Scan UUID: {result.get('uuid', 'N/A')}")
        print(f"   📊 API URL: {result.get('api', 'N/A')}")
        print(f"   📊 Result URL: {result.get('result', 'N/A')}")
        print(f"   ℹ️  Note: Scan results are typically available after 10-30 seconds")
    
    return True


async def main():
    """Run all API tests"""
    print("\n" + "="*70)
    print("🚀 SENTINEL-AI - API Integration Test Suite")
    print("="*70)
    print("\nTesting all 5 external APIs to verify functionality...")
    
    # Check configuration
    print("\n📋 Configuration Status:")
    print(f"   VirusTotal API Key: {'✅ Configured' if settings.VIRUSTOTAL_API_KEY else '❌ Not Set'}")
    print(f"   AbuseIPDB API Key: {'✅ Configured' if settings.ABUSEIPDB_API_KEY else '❌ Not Set'}")
    print(f"   Shodan API Key: {'✅ Configured' if settings.SHODAN_API_KEY else '❌ Not Set'}")
    print(f"   Hybrid Analysis API Key: {'✅ Configured' if settings.HYBRIDANALYSIS_API_KEY else '❌ Not Set'}")
    print(f"   URLScan API Key: {'✅ Configured' if settings.URLSCAN_API_KEY else '❌ Not Set'}")
    
    # Run tests
    results = {}
    
    results['VirusTotal'] = await test_virustotal()
    results['AbuseIPDB'] = await test_abuseipdb()
    results['Shodan'] = await test_shodan()
    results['Hybrid Analysis'] = await test_hybrid_analysis()
    results['URLScan.io'] = await test_urlscan()
    
    # Summary
    print("\n" + "="*70)
    print("📊 TEST SUMMARY")
    print("="*70)
    
    for api_name, success in results.items():
        status = "✅ WORKING" if success else "❌ FAILED"
        print(f"   {api_name:20} : {status}")
    
    # Overall status
    all_working = all(results.values())
    some_working = any(results.values())
    
    print("\n" + "="*70)
    if all_working:
        print("🎉 All APIs are working correctly!")
    elif some_working:
        print("⚠️  Some APIs are not configured or failing")
        print("   Check the error messages above and configure API keys in .env file")
    else:
        print("❌ No APIs are working - check configuration")
    print("="*70)
    
    return all_working


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
