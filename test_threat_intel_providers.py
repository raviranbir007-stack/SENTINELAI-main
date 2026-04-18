#!/usr/bin/env python3
"""
Test and diagnose threat intelligence provider connectivity
"""
import asyncio
import sys
import os
from pathlib import Path

# Add server to path
sys.path.insert(0, str(Path(__file__).parent / "server"))

from app.config import settings
from app.services.virus_total import VirusTotalService
from app.services.abuseipdb import AbuseIPDBService
from app.services.shodan import ShodanService
from app.services.urlscan import URLScanService
from app.services.hybrid_analysis import HybridAnalysisService


async def test_providers():
    """Test each threat intelligence provider"""
    
    print("\n" + "="*70)
    print("THREAT INTELLIGENCE PROVIDER DIAGNOSTIC")
    print("="*70)
    
    # Check configuration
    print("\n1. CONFIGURATION CHECK:")
    print(f"   EXTERNAL_APIS_ENABLED: {settings.EXTERNAL_APIS_ENABLED}")
    print(f"   VirusTotal configured: {bool(settings.VIRUSTOTAL_API_KEY)}")
    print(f"   AbuseIPDB configured: {bool(settings.ABUSEIPDB_API_KEY)}")
    print(f"   Shodan configured: {bool(settings.SHODAN_API_KEY)}")
    print(f"   HybridAnalysis configured: {bool(settings.HYBRIDANALYSIS_API_KEY)}")
    print(f"   URLScan configured: {bool(settings.URLSCAN_API_KEY)}")
    
    if not settings.EXTERNAL_APIS_ENABLED:
        print("\n   ⚠️  EXTERNAL_APIS_ENABLED is FALSE - APIs are disabled!")
        print("   FIX: Set EXTERNAL_APIS_ENABLED=true in .env")
        return
    
    # Test domains/IPs
    test_domain = "google.com"
    test_ip = "8.8.8.8"
    test_url = "https://google.com"
    test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # SHA256 of empty string
    
    print(f"\n2. PROVIDER CONNECTIVITY TESTS:")
    print(f"   Test Domain: {test_domain}")
    print(f"   Test IP: {test_ip}")
    print(f"   Test URL: {test_url}")
    print(f"   Test Hash: {test_hash}")
    
    # Test VirusTotal
    print("\n   Testing VirusTotal...")
    try:
        vt_result = await VirusTotalService.scan_domain(test_domain)
        if vt_result.get("error"):
            print(f"   ❌ VirusTotal ERROR: {vt_result.get('error')}")
        else:
            print(f"   ✅ VirusTotal OK - Response received ({len(str(vt_result))} bytes)")
    except Exception as e:
        print(f"   ❌ VirusTotal EXCEPTION: {str(e)}")
    
    # Test AbuseIPDB
    print("\n   Testing AbuseIPDB...")
    try:
        abuse_result = await AbuseIPDBService.check_ip(test_ip)
        if abuse_result.get("error"):
            print(f"   ❌ AbuseIPDB ERROR: {abuse_result.get('error')}")
        else:
            print(f"   ✅ AbuseIPDB OK - Response received ({len(str(abuse_result))} bytes)")
    except Exception as e:
        print(f"   ❌ AbuseIPDB EXCEPTION: {str(e)}")
    
    # Test Shodan
    print("\n   Testing Shodan...")
    try:
        shodan_result = await ShodanService.search_ip(test_ip)
        if shodan_result.get("error"):
            print(f"   ❌ Shodan ERROR: {shodan_result.get('error')}")
        else:
            print(f"   ✅ Shodan OK - Response received ({len(str(shodan_result))} bytes)")
    except Exception as e:
        print(f"   ❌ Shodan EXCEPTION: {str(e)}")
    
    # Test URLScan
    print("\n   Testing URLScan...")
    try:
        urlscan_result = await URLScanService.scan_url(test_url)
        if urlscan_result.get("error"):
            print(f"   ❌ URLScan ERROR: {urlscan_result.get('error')}")
        else:
            print(f"   ✅ URLScan OK - Response received ({len(str(urlscan_result))} bytes)")
    except Exception as e:
        print(f"   ❌ URLScan EXCEPTION: {str(e)}")
    
    # Test Hybrid Analysis
    print("\n   Testing Hybrid Analysis...")
    try:
        ha_result = await HybridAnalysisService.search_hash(test_hash)
        if ha_result.get("error"):
            print(f"   ❌ Hybrid Analysis ERROR: {ha_result.get('error')}")
        else:
            print(f"   ✅ Hybrid Analysis OK - Response received ({len(str(ha_result))} bytes)")
    except Exception as e:
        print(f"   ❌ Hybrid Analysis EXCEPTION: {str(e)}")
    
    print("\n" + "="*70)
    print("RECOMMENDATIONS:")
    print("="*70)
    print("""
1. Verify all API keys are valid and active:
   - VirusTotal: https://www.virustotal.com/gui/my-apikey
   - AbuseIPDB: https://www.abuseipdb.com/api
   - Shodan: https://account.shodan.io/
   - URLScan: https://urlscan.io/user/profile/
   - Hybrid Analysis: https://www.hybrid-analysis.com/manage-api

2. Check network connectivity:
   - Ensure outbound HTTPS is allowed on your network
   - Test with: curl -I https://www.virustotal.com/api/v3/domains/google.com

3. Verify .env file:
   - EXTERNAL_APIS_ENABLED=true
   - All API keys are populated (not empty or "your_*")
   - No extra quotes or spaces in keys

4. Check rate limits:
   - Some providers may have free tier rate limits
   - Check provider dashboards for usage/limits
""")


if __name__ == "__main__":
    asyncio.run(test_providers())
