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

# Quota / rate-limit error keywords that should NOT count as integration failures
_QUOTA_PHRASES = (
    "quota exceeded",
    "rate limit",
    "cooldown",
    "429",
)


def _is_quota_error(err: str) -> bool:
    return any(p in err.lower() for p in _QUOTA_PHRASES)


async def test_services():
    services = [
        # VirusTotal: prefer hash lookup (cheaper quota) over URL scan
        ("VirusTotal hash",   VirusTotalService().scan_file,  "44d88612fea8a8f36de82e1278abb02f"),
        ("VirusTotal URL",    VirusTotalService().scan_url,   "https://example.com"),
        ("AbuseIPDB IP",      AbuseIPDBService().check_ip,    "8.8.8.8"),
        ("URLScan URL",       URLScanService().scan_url,      "https://example.com"),
        ("Shodan IP",         ShodanService().search_ip,      "8.8.8.8"),
        ("Hybrid Analysis",   HybridAnalysisService().search_hash, "44d88612fea8a8f36de82e1278abb02f"),
    ]

    passed = 0
    quota_limited = 0
    failed = 0

    print("=" * 60)
    print("  SENTINEL-AI  API Service Status Check")
    print("=" * 60)

    for name, func, target in services:
        try:
            print(f"\nTesting {name} → {target}")
            result = await func(target)
            if isinstance(result, dict) and result.get("error"):
                err = result["error"]
                if _is_quota_error(err):
                    print(f"  ⚠  Quota/rate-limit (not a key issue): {err}")
                    quota_limited += 1
                else:
                    print(f"  ✗  Error: {err}")
                    failed += 1
            else:
                print(f"  ✓  OK  (type={type(result).__name__})")
                passed += 1
        except Exception as e:
            print(f"  ✗  Exception: {e}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"  Passed:        {passed}")
    print(f"  Quota-limited: {quota_limited}  (provider-side, not a code issue)")
    print(f"  Failed:        {failed}")
    overall = "✅ ALL GOOD" if failed == 0 else f"❌ {failed} INTEGRATION FAILURE(S)"
    print(f"  Overall:       {overall}")
    print("=" * 60)


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)   # suppress INFO noise in test output
    asyncio.run(test_services())

