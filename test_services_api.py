#!/usr/bin/env python3
"""Verify threat intelligence service APIs are accessible"""

# Utility script (not a pytest test module)
__test__ = False

import asyncio
import logging

from server.app.services.virus_total import VirusTotalService
from server.app.services.abuseipdb import AbuseIPDBService
from server.app.services.urlscan import URLScanService
from server.app.services.shodan import ShodanService
from server.app.services.hybrid_analysis import HybridAnalysisService


async def test_services():
    services = []
    services.append(('VirusTotal URL', VirusTotalService().scan_url, 'https://example.com'))
    services.append(('AbuseIPDB IP', AbuseIPDBService().check_ip, '8.8.8.8'))
    services.append(('URLScan URL', URLScanService().scan_url, 'https://example.com'))
    services.append(('Shodan IP', ShodanService().search_ip, '8.8.8.8'))
    services.append(('Hybrid Analysis hash', HybridAnalysisService().search_hash, '44d88612fea8a8f36de82e1278abb02f'))

    for name, func, target in services:
        try:
            print(f"Testing {name} -> {target}")
            result = await func(target)
            # simple success check
            if isinstance(result, dict) and result.get('error'):
                print(f"  ✗ Error response: {result['error']}")
            else:
                print(f"  ✓ Response received (type {type(result)})")
        except Exception as e:
            print(f"  ✗ Exception: {e}")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    asyncio.run(test_services())
