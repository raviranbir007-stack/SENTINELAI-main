#!/usr/bin/env python3
"""
Test Client - Sends scan requests to verify monitoring works
Run this AFTER starting the server to see activity monitoring in action
"""

import requests
import time
import json
import os

SERVER_URL = os.getenv("SENTINEL_SERVER_URL", "http://localhost:8000")

print("=" * 80)
print("🧪 SENTINEL-AI Monitoring Test Client")
print("=" * 80)
print()
print(f"Server: {SERVER_URL}")
print("Sending test scans to verify monitoring...")
print()

# Test URLs to scan
test_targets = [
    {"type": "url", "target": "https://www.google.com"},
    {"type": "url", "target": "https://github.com"},
    {"type": "domain", "target": "example.com"},
    {"type": "ip", "target": "8.8.8.8"},
    {"type": "url", "target": "http://testphp.vulnweb.com"},
]

print(f"Sending {len(test_targets)} test scans...\n")

for i, scan_request in enumerate(test_targets, 1):
    try:
        print(f"[{i}/{len(test_targets)}] Scanning {scan_request['type']}: {scan_request['target']}...")
        
        response = requests.post(
            f"{SERVER_URL}/api/scan",
            json=scan_request,
            timeout=60
        )
        
        if response.status_code == 200:
            result = response.json()
            verdict = result.get('verdict', 'unknown')
            confidence = result.get('confidence', 0) * 100
            
            print(f"     ✓ Result: {verdict.upper()} (confidence: {confidence:.0f}%)")
            
            # Show threat indicators if any
            threats = result.get('threats_detected', 0)
            if threats > 0:
                print(f"     ⚠️ Threats detected: {threats}")
        else:
            print(f"     ✗ Error: HTTP {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print(f"     ✗ Cannot connect to server at {SERVER_URL}")
        print(f"     Make sure server is running: cd server && python3 run_server.py")
        break
    except Exception as e:
        print(f"     ✗ Error: {e}")
    
    # Small delay between scans
    time.sleep(2)

print()
print("=" * 80)
print("✅ Test complete!")
print()
print("Check your server terminal - you should see:")
print("  • Activity statistics updated")
print("  • Recent websites/domains listed")
print("  • Scan count increased")
print()
print("To see database records:")
print("  cd server")
print("  sqlite3 activity_monitoring.db \"SELECT COUNT(*) FROM threat_scans;\"")
print("=" * 80)
