#!/usr/bin/env python
"""
Test script to verify CORS OPTIONS requests work properly.
"""
# Utility script (not a pytest test module)
__test__ = False

import json
import time
import urllib.request


def test_options(endpoint):
    """Test OPTIONS request to an endpoint."""
    url = f"http://127.0.0.1:8000{endpoint}"
    req = urllib.request.Request(url, method="OPTIONS")
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        print(f"✓ OPTIONS {endpoint}: {resp.status}")
        return True
    except urllib.error.HTTPError as e:
        print(f"✗ OPTIONS {endpoint}: {e.code} {e.reason}")
        return False
    except Exception as e:
        print(f"✗ OPTIONS {endpoint}: Error - {e}")
        return False


def test_endpoint(method, endpoint, data=None):
    """Test GET or POST request."""
    url = f"http://127.0.0.1:8000{endpoint}"
    try:
        if method == "GET":
            resp = urllib.request.urlopen(url, timeout=5)
        else:
            body = json.dumps(data).encode("utf-8") if data else None
            req = urllib.request.Request(url, data=body, method=method)
            req.add_header("Content-Type", "application/json")
            resp = urllib.request.urlopen(req, timeout=5)

        content = json.loads(resp.read())
        print(f"✓ {method} {endpoint}: {resp.status}")
        print(f"  Response keys: {list(content.keys())[:5]}")
        return True
    except Exception as e:
        print(f"✗ {method} {endpoint}: {e}")
        return False


if __name__ == "__main__":
    print("=" * 70)
    print("Testing CORS OPTIONS Requests")
    print("=" * 70)

    time.sleep(1)  # Wait for server to be ready

    # Test CORS preflight requests
    options_endpoints = [
        "/api/scan",
        "/api/scans",
        "/api/dashboard/stats",
        "/api/threats",
        "/api/reports",
    ]

    print("\n1. Testing CORS Preflight (OPTIONS) Requests:")
    print("-" * 70)
    options_passed = 0
    for endpoint in options_endpoints:
        if test_options(endpoint):
            options_passed += 1

    print(f"\nCORS Preflight: {options_passed}/{len(options_endpoints)} passed")

    # Test actual endpoints
    print("\n2. Testing API Endpoints:")
    print("-" * 70)

    test_endpoint("GET", "/api/v1/health")
    test_endpoint("GET", "/api/v1/dashboard/stats")
    test_endpoint("GET", "/api/v1/threats")
    test_endpoint("GET", "/api/scans")
    test_endpoint("POST", "/api/scan", {"type": "url", "target": "https://example.com"})

    print("\n" + "=" * 70)
    print("Test Complete!")
    print("=" * 70)
