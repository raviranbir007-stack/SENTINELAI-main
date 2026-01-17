#!/usr/bin/env python3
"""
Quick test script to verify SentinelAI API endpoints
"""

import requests
import json
from datetime import datetime

BASE_URL = "http://localhost:8000"

def test_endpoint(method, endpoint, data=None, description=""):
    """Test an API endpoint"""
    url = f"{BASE_URL}{endpoint}"
    print(f"\n{'='*60}")
    print(f"Testing: {description}")
    print(f"Method: {method}")
    print(f"URL: {url}")
    
    try:
        if method == "GET":
            response = requests.get(url, timeout=10)
        elif method == "POST":
            response = requests.post(url, json=data, timeout=10)
        else:
            print(f"❌ Unsupported method: {method}")
            return
        
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            print(f"✅ SUCCESS")
            try:
                result = response.json()
                print(f"Response (truncated): {json.dumps(result, indent=2)[:500]}...")
            except:
                print(f"Response length: {len(response.content)} bytes")
        else:
            print(f"❌ FAILED")
            print(f"Response: {response.text[:200]}")
            
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")

def main():
    print("="*60)
    print("SentinelAI API Endpoint Tests")
    print("="*60)
    print(f"Base URL: {BASE_URL}")
    print(f"Time: {datetime.now()}")
    
    # Test health endpoint
    test_endpoint("GET", "/api/v1/health", description="Health Check")
    
    # Test scan endpoint
    test_endpoint("POST", "/api/scan", 
                 data={"type": "ip", "target": "8.8.8.8"},
                 description="Perform IP Scan")
    
    # Test get scans
    test_endpoint("GET", "/api/scans", description="Get All Scans")
    
    # Test dashboard stats
    test_endpoint("GET", "/api/dashboard/stats", description="Dashboard Statistics")
    
    # Test threats list
    test_endpoint("GET", "/api/threats", description="Get All Threats")
    
    # Test reports list
    test_endpoint("GET", "/api/reports", description="Get All Reports")
    
    # Test report generation (will fail without Gemini API key)
    test_endpoint("POST", "/api/reports/generate",
                 data={"type": "executive", "timeRange": "24h", "target": "test.com"},
                 description="Generate Report (may fail without Gemini API)")
    
    print("\n" + "="*60)
    print("Test Complete")
    print("="*60)
    print("\nNote: Some endpoints may fail if:")
    print("  - Server is not running")
    print("  - Gemini API key is not configured")
    print("  - External APIs are not accessible")
    print("\n")

if __name__ == "__main__":
    main()
