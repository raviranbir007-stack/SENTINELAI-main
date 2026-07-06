#!/usr/bin/env python3
"""
Complete end-to-end test of SENTINEL-AI Threat Intelligence
Tests actual threat analysis with all providers
"""

import asyncio
import sys
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add server to path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "server"))

from app.config import settings
from app.core.threat_analyzer import ThreatAnalyzer


async def test_threat_analyzer():
    """Test threat analyzer with different input types"""
    
    print("\n" + "="*80)
    print("SENTINEL-AI THREAT ANALYZER END-TO-END TEST")
    print("="*80)
    
    print(f"\nConfiguration Check:")
    print(f"  EXTERNAL_APIS_ENABLED: {settings.EXTERNAL_APIS_ENABLED}")
    print(f"  VIRUSTOTAL_API_KEY: {bool(settings.VIRUSTOTAL_API_KEY)}")
    print(f"  ABUSEIPDB_API_KEY: {bool(settings.ABUSEIPDB_API_KEY)}")
    print(f"  SHODAN_API_KEY: {bool(settings.SHODAN_API_KEY)}")
    print(f"  URLSCAN_API_KEY: {bool(settings.URLSCAN_API_KEY)}")
    print(f"  HYBRIDANALYSIS_API_KEY: {bool(settings.HYBRIDANALYSIS_API_KEY)}")
    
    if not settings.EXTERNAL_APIS_ENABLED:
        print("\n⚠️  WARNING: EXTERNAL_APIS_ENABLED is False!")
        print("   System is running in local-only mode. Set to True to enable providers.")
        return
    
    # Initialize analyzer
    try:
        analyzer = ThreatAnalyzer()
        print("\n✅ ThreatAnalyzer initialized successfully")
    except Exception as e:
        print(f"\n❌ Failed to initialize ThreatAnalyzer: {e}")
        return
    
    # Test cases
    test_cases = [
        ("google.com", "domain", "Benign domain (known-good for testing)"),
        ("8.8.8.8", "ip", "Public DNS IP (known-good for testing)"),
    ]
    
    print("\n" + "="*80)
    print("RUNNING THREAT ANALYSIS TESTS")
    print("="*80)
    
    for test_value, input_type, description in test_cases:
        print(f"\n{'-'*80}")
        print(f"Test: {test_value}")
        print(f"Type: {input_type}")
        print(f"Description: {description}")
        print(f"{'-'*80}")
        
        try:
            result = await analyzer.analyze(test_value, use_external_apis=True)
            
            # Display results
            print(f"\nAnalysis Result:")
            print(f"  Input Type: {result.get('input_type')}")
            print(f"  Verdict: {result.get('verdict')}")
            print(f"  Confidence: {result.get('confidence'):.2%}")
            
            # Display API results summary
            api_results = result.get("api_results", {})
            api_status = api_results.get("api_status", {})
            
            if not api_status:
                print(f"  ⚠️  No API status information available")
            else:
                print(f"\n  Provider Status:")
                for provider_key, status_info in api_status.items():
                    if isinstance(status_info, dict):
                        name = status_info.get("name", provider_key)
                        status = status_info.get("status", "unknown")
                        configured = status_info.get("configured", False)
                        applicable = status_info.get("applicable", False)
                        
                        status_icon = "✅" if status == "success" else "⚠️" if status in ["pending", "limited"] else "❌"
                        config_icon = "✅" if configured else "⚠️"
                        applicable_icon = "✅" if applicable else "⛔"
                        
                        print(f"    {status_icon} {name}: {status} (Configured: {config_icon}, Applicable: {applicable_icon})")
            
            # Display threat indicators
            threats = result.get("threat_indicators", [])
            if threats:
                print(f"\n  Threats Detected: {len(threats)}")
                for threat in threats[:5]:
                    print(f"    - [{threat.get('severity', '?')}] {threat.get('source', '?')}: {threat.get('indicator', '?')}")
            else:
                print(f"\n  ✅ No threats detected")
            
        except Exception as e:
            print(f"\n❌ Analysis failed: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "="*80)
    print("RECOMMENDATIONS")
    print("="*80)
    print("""
1. If providers show status "success":
   - ✅ Your threat intelligence integration is working perfectly!
   - Reports should show "Provider data collected successfully"

2. If providers show status "error" or "not_configured":
   - Check your API keys in .env
   - Verify EXTERNAL_APIS_ENABLED=true
    - Run: python scripts/validation/validate_system.py

3. Next steps:
   - Run actual threat scans through the dashboard
   - Check reports for telemetry coverage table
   - Verify all 5 providers show proper status
""")


if __name__ == "__main__":
    asyncio.run(test_threat_analyzer())
