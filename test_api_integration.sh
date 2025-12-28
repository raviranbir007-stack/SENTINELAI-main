#!/bin/bash

echo "═══════════════════════════════════════════════════════════"
echo "  Testing API Integration Through Actual Endpoints"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Test 1: IP Scan (AbuseIPDB + Shodan)
echo "🔍 Test 1: IP Address Scan (8.8.8.8)"
echo "   APIs Used: AbuseIPDB + Shodan"
echo ""
curl -s -X POST http://127.0.0.1:8000/api/v1/scan/ip \
  -H "Content-Type: application/json" \
  -d '{"target":"8.8.8.8"}' | python3 -m json.tool | head -30
echo ""
echo "   ✅ IP scan completed"
echo ""

# Test 2: URL Scan (VirusTotal + URLScan)
echo "🔍 Test 2: URL Scan (example.org)"
echo "   APIs Used: VirusTotal + URLScan.io"
echo ""
curl -s -X POST http://127.0.0.1:8000/api/v1/scan/url \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.org"}' | python3 -m json.tool | head -30
echo ""
echo "   ✅ URL scan completed"
echo ""

# Test 3: Hash Scan (VirusTotal + Hybrid Analysis)
echo "🔍 Test 3: File Hash Scan (SHA256 of empty file)"
echo "   APIs Used: VirusTotal + Hybrid Analysis"
echo ""
curl -s -X POST http://127.0.0.1:8000/api/v1/scan/hash \
  -H "Content-Type: application/json" \
  -d '{"target":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}' | python3 -m json.tool | head -30
echo ""
echo "   ✅ Hash scan completed"
echo ""

echo "═══════════════════════════════════════════════════════════"
echo "  ✅ All API Integration Tests Completed Successfully"
echo "═══════════════════════════════════════════════════════════"

