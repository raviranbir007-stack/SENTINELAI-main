#!/usr/bin/env python3
"""
API Configuration Setup and Test Script
This script helps you test if your API keys are working correctly
"""

# Utility script (not a pytest test module)
__test__ = False

import asyncio
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from app.services.virus_total import VirusTotalService
from app.services.urlscan import URLScanService
from app.services.abuseipdb import AbuseIPDBService
from app.services.shodan import ShodanService
from app.services.hybrid_analysis import HybridAnalysisService
from app.config import settings


async def test_virustotal():
    """Test VirusTotal API"""
    print("\n" + "="*60)
    print("Testing VirusTotal API")
    print("="*60)
    
    if not settings.VIRUSTOTAL_API_KEY or settings.VIRUSTOTAL_API_KEY == "your_virustotal_api_key_here":
        print("❌ VirusTotal API key not configured")
        print("   Get your free API key at: https://www.virustotal.com/gui/join-us")
        return False
    
    print(f"✓ API Key found: {settings.VIRUSTOTAL_API_KEY[:10]}...")
    
    # Test with a known malicious URL
    test_url = "http://malware.wicar.org/data/eicar.com"
    print(f"Testing URL: {test_url}")
    
    result = await VirusTotalService.scan_url(test_url)
    
    if result.get("error"):
        print(f"❌ Error: {result['error']}")
        return False
    
    if "data" in result:
        stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        print(f"✓ Analysis complete:")
        print(f"   Malicious: {stats.get('malicious', 0)}")
        print(f"   Suspicious: {stats.get('suspicious', 0)}")
        print(f"   Clean: {stats.get('harmless', 0)}")
        print(f"   Undetected: {stats.get('undetected', 0)}")
        return True
    else:
        print("❌ Unexpected response format")
        print(f"   Response: {result}")
        return False


async def test_urlscan():
    """Test URLScan API"""
    print("\n" + "="*60)
    print("Testing URLScan.io API")
    print("="*60)
    
    if not settings.URLSCAN_API_KEY or settings.URLSCAN_API_KEY == "your_urlscan_api_key_here":
        print("❌ URLScan API key not configured")
        print("   Get your free API key at: https://urlscan.io/user/signup")
        return False
    
    print(f"✓ API Key found: {settings.URLSCAN_API_KEY[:10]}...")
    
    test_url = "https://example.com"
    print(f"Testing URL: {test_url}")
    
    result = await URLScanService.scan_url(test_url)
    
    if result.get("error"):
        print(f"❌ Error: {result['error']}")
        return False
    
    if "uuid" in result:
        print(f"✓ Scan submitted successfully")
        print(f"   UUID: {result['uuid']}")
        print(f"   API: {result.get('api')}")
        return True
    else:
        print("❌ Unexpected response format")
        return False


async def test_abuseipdb():
    """Test AbuseIPDB API"""
    print("\n" + "="*60)
    print("Testing AbuseIPDB API")
    print("="*60)
    
    if not settings.ABUSEIPDB_API_KEY or settings.ABUSEIPDB_API_KEY == "your_abuseipdb_api_key_here":
        print("❌ AbuseIPDB API key not configured")
        print("   Get your free API key at: https://www.abuseipdb.com/register")
        return False
    
    print(f"✓ API Key found: {settings.ABUSEIPDB_API_KEY[:10]}...")
    
    # Test with a known malicious IP (adjust as needed)
    test_ip = "8.8.8.8"
    print(f"Testing IP: {test_ip}")
    
    result = await AbuseIPDBService.check_ip(test_ip)
    
    if result.get("error"):
        print(f"❌ Error: {result['error']}")
        return False
    
    if "data" in result:
        data = result["data"]
        print(f"✓ IP check complete:")
        print(f"   Abuse Score: {data.get('abuseConfidenceScore', 0)}%")
        print(f"   Total Reports: {data.get('totalReports', 0)}")
        print(f"   Country: {data.get('countryCode', 'Unknown')}")
        return True
    else:
        print("❌ Unexpected response format")
        return False


async def test_shodan():
    """Test Shodan API"""
    print("\n" + "="*60)
    print("Testing Shodan API")
    print("="*60)
    
    if not settings.SHODAN_API_KEY or settings.SHODAN_API_KEY == "your_shodan_api_key_here":
        print("❌ Shodan API key not configured")
        print("   Get your API key at: https://account.shodan.io/register")
        return False
    
    print(f"✓ API Key found: {settings.SHODAN_API_KEY[:10]}...")
    
    test_ip = "8.8.8.8"
    print(f"Testing IP: {test_ip}")
    
    result = await ShodanService.search_ip(test_ip)
    
    if result.get("error"):
        print(f"❌ Error: {result['error']}")
        return False
    
    if "ip" in result or "ports" in result:
        print(f"✓ IP lookup complete:")
        print(f"   IP: {result.get('ip_str', test_ip)}")
        print(f"   Organization: {result.get('org', 'Unknown')}")
        print(f"   Ports: {result.get('ports', [])[:5]}")
        return True
    else:
        print("❌ Unexpected response format")
        return False


async def test_hybrid_analysis():
    """Test Hybrid Analysis API"""
    print("\n" + "="*60)
    print("Testing Hybrid Analysis API")
    print("="*60)
    
    if not settings.HYBRIDANALYSIS_API_KEY or settings.HYBRIDANALYSIS_API_KEY == "your_hybridanalysis_api_key_here":
        print("❌ Hybrid Analysis API key not configured")
        print("   Get your free API key at: https://www.hybrid-analysis.com/signup")
        return False
    
    print(f"✓ API Key found: {settings.HYBRIDANALYSIS_API_KEY[:10]}...")
    
    # Test with a known hash (EICAR test file SHA256)
    test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    print(f"Testing hash: {test_hash[:16]}...")
    
    result = await HybridAnalysisService.search_hash(test_hash)
    
    if result.get("error"):
        print(f"❌ Error: {result['error']}")
        return False
    
    if isinstance(result, list) or "count" in result:
        results = result if isinstance(result, list) else result.get("results", [])
        print(f"✓ Hash lookup complete:")
        print(f"   Results found: {len(results) if isinstance(results, list) else result.get('count', 0)}")
        if results and len(results) > 0:
            print(f"   First result verdict: {results[0].get('verdict', 'N/A')}")
        return True
    else:
        print("✓ API connection successful")
        print(f"   Response: {str(result)[:100]}")
        return True


async def main():
    """Run all API tests"""
    print("\n" + "="*60)
    print("SENTINEL-AI API Configuration Test")
    print("="*60)
    
    # Check .env file exists
    env_path = Path(__file__).parent / ".env"
    if not env_path.exists():
        print("\n⚠️  WARNING: .env file not found!")
        print("   Please copy .env.example to .env and add your API keys")
        print(f"   Command: cp {Path(__file__).parent}/.env.example {env_path}")
        return
    
    print(f"✓ .env file found at: {env_path}")
    
    results = {
        "VirusTotal": await test_virustotal(),
        "URLScan": await test_urlscan(),
        "AbuseIPDB": await test_abuseipdb(),
        "Shodan": await test_shodan(),
        "Hybrid Analysis": await test_hybrid_analysis(),
    }
    
    print("\n" + "="*60)
    print("Test Summary")
    print("="*60)
    
    for service, passed in results.items():
        status = "✓ PASS" if passed else "❌ FAIL"
        print(f"{service:20s} {status}")
    
    passed_count = sum(results.values())
    total_count = len(results)
    
    print("\n" + "="*60)
    print(f"Results: {passed_count}/{total_count} APIs working correctly")
    print("="*60)
    
    if passed_count < total_count:
        print("\n⚠️  Some APIs are not configured or failed")
        print("   Please check your API keys in the .env file")
        print("   The system will work with limited functionality")
    else:
        print("\n✓ All APIs configured correctly!")
        print("   SENTINEL-AI is ready to use")


if __name__ == "__main__":
    asyncio.run(main())
