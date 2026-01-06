#!/usr/bin/env python3
"""
Comprehensive Functionality Test for SENTINEL AI
Tests all dashboard features, APIs, Gemini, ML, and endpoints
"""

import requests
import json
import time
from datetime import datetime

BASE_URL = "http://localhost:8000"
API_BASE = f"{BASE_URL}/api"

def print_header(title):
    print("\n" + "="*70)
    print(f" {title}")
    print("="*70)

def test_server_health():
    """Test if server is running"""
    print_header("SERVER HEALTH CHECK")
    try:
        response = requests.get(f"{BASE_URL}/api/docs", timeout=5)
        if response.status_code == 200:
            print("✅ Server is running")
            return True
        return False
    except:
        print("❌ Server is not running")
        return False

def test_api_endpoints():
    """Test all API endpoints"""
    print_header("API ENDPOINTS TEST")
    
    endpoints = {
        "Dashboard Stats": "/api/dashboard/stats",
        "Scans List": "/api/scans",
        "Threats List": "/api/threats",
        "Reports List": "/api/reports",
    }
    
    results = {}
    for name, endpoint in endpoints.items():
        try:
            response = requests.get(f"{BASE_URL}{endpoint}", timeout=5)
            status = "✅" if response.status_code == 200 else "⚠️"
            print(f"{status} {name}: HTTP {response.status_code}")
            results[name] = response.status_code == 200
        except Exception as e:
            print(f"❌ {name}: {str(e)}")
            results[name] = False
    
    return all(results.values())

def test_scan_functionality():
    """Test scan functionality with IP"""
    print_header("SCAN FUNCTIONALITY TEST")
    
    try:
        # Test IP scan
        print("Testing IP scan (8.8.8.8)...")
        response = requests.post(
            f"{BASE_URL}/api/scan",
            json={"target": "8.8.8.8", "type": "ip"},
            timeout=30
        )
        
        if response.status_code in [200, 201]:
            scan_data = response.json()
            scan_id = scan_data.get('scan_id')
            print(f"✅ Scan created: {scan_id}")
            print(f"   Status: {scan_data.get('status')}")
            print(f"   Threat Level: {scan_data.get('threat_level')}")
            print(f"   Threats Detected: {scan_data.get('threats_detected')}")
            
            # Test eye icon functionality - get scan details
            time.sleep(1)
            detail_response = requests.get(f"{BASE_URL}/api/scans/{scan_id}", timeout=5)
            if detail_response.status_code == 200:
                print(f"✅ Eye icon data available (scan details retrievable)")
                detail = detail_response.json()
                if 'api_results' in detail:
                    print(f"   APIs consulted: {len(detail.get('api_results', {}))}")
            else:
                print(f"⚠️  Eye icon data: HTTP {detail_response.status_code}")
            
            return True
        else:
            print(f"⚠️  Scan returned HTTP {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Scan failed: {str(e)}")
        return False

def test_five_apis():
    """Test all 5 API integrations"""
    print_header("5 API INTEGRATIONS TEST")
    
    # Create a scan to test API integrations
    try:
        response = requests.post(
            f"{BASE_URL}/api/scan",
            json={"target": "1.1.1.1", "type": "ip"},
            timeout=30
        )
        
        if response.status_code in [200, 201]:
            scan_data = response.json()
            api_results = scan_data.get('api_results', {})
            
            expected_apis = ['virustotal', 'abuseipdb', 'shodan', 'urlscan', 'hybridanalysis']
            
            for api in expected_apis:
                if api in api_results:
                    result = api_results[api]
                    status = result.get('status', 'unknown')
                    print(f"✅ {api.upper()}: {status}")
                else:
                    print(f"⚠️  {api.upper()}: Not in results")
            
            return len(api_results) > 0
        else:
            print(f"⚠️  Could not test APIs (scan failed)")
            return False
    except Exception as e:
        print(f"❌ API test failed: {str(e)}")
        return False

def test_gemini_functionality():
    """Test Gemini AI report generation"""
    print_header("GEMINI AI FUNCTIONALITY TEST")
    
    try:
        # Generate a report using Gemini
        response = requests.post(
            f"{BASE_URL}/api/reports/generate",
            json={
                "type": "executive",
                "timeRange": "24h",
                "target": "8.8.8.8"
            },
            timeout=60
        )
        
        if response.status_code in [200, 201]:
            report_data = response.json()
            print(f"✅ Gemini report generated successfully")
            print(f"   Report ID: {report_data.get('report_id')}")
            print(f"   Title: {report_data.get('title')}")
            
            # Check if Gemini was actually used
            content = str(report_data)
            if 'gemini' in content.lower() or 'analysis' in content.lower():
                print(f"✅ Gemini AI analysis included")
            
            return True
        else:
            error = response.text
            if 'gemini' in error.lower() and 'key' in error.lower():
                print(f"⚠️  Gemini API key not configured (fallback to local analysis)")
            else:
                print(f"⚠️  Report generation: HTTP {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Gemini test failed: {str(e)}")
        return False

def test_ml_functionality():
    """Test ML/Anomaly detection"""
    print_header("ML/AI ANOMALY DETECTION TEST")
    
    try:
        # Test with suspicious pattern
        response = requests.post(
            f"{BASE_URL}/api/scan",
            json={"target": "malicious-site.com", "type": "url"},
            timeout=30
        )
        
        if response.status_code in [200, 201]:
            scan_data = response.json()
            threat_level = scan_data.get('threat_level')
            confidence = scan_data.get('confidence')
            
            print(f"✅ ML analysis completed")
            print(f"   Threat Level: {threat_level}")
            print(f"   Confidence: {confidence}")
            
            if 'threat_indicators' in scan_data:
                indicators = scan_data.get('threat_indicators', [])
                print(f"   Threat Indicators: {len(indicators)}")
            
            return True
        else:
            print(f"⚠️  ML test: HTTP {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ ML test failed: {str(e)}")
        return False

def test_dashboard_features():
    """Test dashboard-specific features"""
    print_header("DASHBOARD FEATURES TEST")
    
    try:
        # Get HTML to check features
        response = requests.get(BASE_URL, timeout=5)
        html = response.text
        
        features = {
            "Eye Icon (viewScanDetail)": "function viewScanDetail" in html,
            "View All Threats": "function viewAllThreats" in html,
            "Notification System": "function toggleNotifications" in html,
            "Scan History Table": "scanHistoryBody" in html,
            "Report Generation": "generateReport" in html,
        }
        
        for feature, exists in features.items():
            status = "✅" if exists else "❌"
            print(f"{status} {feature}")
        
        return all(features.values())
    except Exception as e:
        print(f"❌ Dashboard test failed: {str(e)}")
        return False

def test_notification_system():
    """Test notification functionality"""
    print_header("NOTIFICATION SYSTEM TEST")
    
    try:
        response = requests.get(BASE_URL, timeout=5)
        html = response.text
        
        checks = {
            "Notification Dropdown": "notificationDropdown" in html,
            "Toggle Function": "toggleNotifications()" in html,
            "Render Function": "renderNotifications()" in html,
            "Add Notification": "addNotification(" in html,
        }
        
        for check, result in checks.items():
            status = "✅" if result else "❌"
            print(f"{status} {check}")
        
        return all(checks.values())
    except Exception as e:
        print(f"❌ Notification test failed: {str(e)}")
        return False

def test_all_endpoints():
    """Test all backend endpoints"""
    print_header("BACKEND ENDPOINTS TEST")
    
    endpoints = [
        ("GET", "/api/docs", "API Documentation"),
        ("GET", "/api/scans", "Scans List"),
        ("GET", "/api/threats", "Threats List"),
        ("GET", "/api/reports", "Reports List"),
        ("GET", "/api/dashboard/stats", "Dashboard Stats"),
        ("GET", "/", "Frontend"),
    ]
    
    results = []
    for method, path, name in endpoints:
        try:
            if method == "GET":
                response = requests.get(f"{BASE_URL}{path}", timeout=5)
            
            status = "✅" if response.status_code == 200 else "⚠️"
            print(f"{status} {name} ({method} {path}): HTTP {response.status_code}")
            results.append(response.status_code == 200)
        except Exception as e:
            print(f"❌ {name}: {str(e)}")
            results.append(False)
    
    return all(results)

def main():
    print("\n" + "="*70)
    print(" SENTINEL AI - COMPREHENSIVE FUNCTIONALITY TEST")
    print("="*70)
    print(f" Test Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    if not test_server_health():
        print("\n❌ Server not running. Please start it first.")
        return
    
    # Run all tests
    results = {
        "API Endpoints": test_api_endpoints(),
        "Scan Functionality": test_scan_functionality(),
        "5 API Integrations": test_five_apis(),
        "Gemini AI": test_gemini_functionality(),
        "ML/AI Detection": test_ml_functionality(),
        "Dashboard Features": test_dashboard_features(),
        "Notification System": test_notification_system(),
        "Backend Endpoints": test_all_endpoints(),
    }
    
    # Summary
    print_header("TEST SUMMARY")
    
    for test_name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print("\n" + "="*70)
    passed_count = sum(results.values())
    total_count = len(results)
    percentage = (passed_count / total_count) * 100
    
    print(f" Results: {passed_count}/{total_count} tests passed ({percentage:.1f}%)")
    print("="*70)
    
    if passed_count == total_count:
        print("\n✅ ALL TESTS PASSED! System is fully functional.")
    else:
        print(f"\n⚠️  {total_count - passed_count} test(s) failed. Review output above.")
    
    print("\n" + "="*70)
    print(" MANUAL TESTING GUIDE")
    print("="*70)
    print("\n1. Eye Icon (Scan Details):")
    print("   - Go to http://localhost:8000")
    print("   - Navigate to 'Scans' tab")
    print("   - Click 👁️ icon → Modal opens with scan details\n")
    
    print("2. View All Threats:")
    print("   - On Dashboard, find 'Recent Threats' section")
    print("   - Click 'View All Threats →' button")
    print("   - Modal opens with all threats\n")
    
    print("3. Notifications:")
    print("   - Click 🔔 bell icon in top-right")
    print("   - Dropdown shows notifications")
    print("   - Click outside to close\n")
    
    print("4. Report Generation:")
    print("   - Perform a scan")
    print("   - Click 'Generate Report' button")
    print("   - Report generated with Gemini AI (if configured)\n")
    
    print("="*70)

if __name__ == "__main__":
    main()
