#!/usr/bin/env python
"""Quick test of API endpoints for demo verification"""
import requests
import json
import time

BASE_URL = "http://localhost:8000/api/v1"

def test_health():
    """Test /health endpoint"""
    print("\n=== Testing /health ===")
    try:
        resp = requests.get(f"{BASE_URL}/health", timeout=5)
        print(f"Status: {resp.status_code}")
        if resp.ok:
            print("✅ Health OK")
            print(json.dumps(resp.json(), indent=2))
        else:
            print(f"❌ Health failed: {resp.text}")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_dashboard_summary():
    """Test /dashboard/summary endpoint"""
    print("\n=== Testing /dashboard/summary ===")
    try:
        resp = requests.get(f"{BASE_URL}/dashboard/summary", timeout=5)
        print(f"Status: {resp.status_code}")
        if resp.ok:
            print("✅ Dashboard summary OK")
            data = resp.json()
            print(f"Total scans: {data.get('total_scans', 'N/A')}")
            print(f"Threats detected: {data.get('threats_detected', 'N/A')}")
        else:
            print(f"❌ Failed: {resp.text}")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_dashboard_threats():
    """Test /dashboard/threats endpoint"""
    print("\n=== Testing /dashboard/threats ===")
    try:
        resp = requests.get(f"{BASE_URL}/dashboard/threats", timeout=5)
        print(f"Status: {resp.status_code}")
        if resp.ok:
            print("✅ Dashboard threats OK")
            threats = resp.json()
            print(f"Threats count: {len(threats)}")
            if threats:
                print(f"Sample threat: {threats[0]}")
        else:
            print(f"❌ Failed: {resp.text}")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_reports():
    """Test /reports endpoint"""
    print("\n=== Testing /reports ===")
    try:
        resp = requests.get(f"{BASE_URL}/reports/", timeout=5)
        print(f"Status: {resp.status_code}")
        if resp.ok:
            print("✅ Reports list OK")
            data = resp.json()
            print(f"Reports count: {len(data.get('reports', []))}")
            if data.get('reports'):
                print(f"Sample report: {data['reports'][0]}")
        else:
            print(f"❌ Failed: {resp.text}")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_api_status():
    """Test /dashboard/api-status endpoint"""
    print("\n=== Testing /dashboard/api-status ===")
    try:
        resp = requests.get(f"{BASE_URL}/dashboard/api-status", timeout=5)
        print(f"Status: {resp.status_code}")
        if resp.ok:
            print("✅ API status OK")
            data = resp.json()
            print(f"APIs configured: {data.get('summary', {}).get('configured', 'N/A')}")
            print(f"APIs online: {data.get('summary', {}).get('online', 'N/A')}")
        else:
            print(f"❌ Failed: {resp.text}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    print("🧪 Starting API tests...")
    time.sleep(2)  # Give server time to respond
    test_health()
    test_dashboard_summary()
    test_dashboard_threats()
    test_api_status()
    test_reports()
    print("\n✅ Tests complete!")
