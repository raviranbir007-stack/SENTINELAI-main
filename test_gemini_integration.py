#!/usr/bin/env python3
"""
Test script to validate Gemini API integration and diagnose report generation issues.

Usage:
    python test_gemini_integration.py
    
This will:
1. Validate API keys
2. Test Gemini API connectivity
3. Check circuit breaker status
4. Display quota information
5. Generate a test report
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Add project to path BEFORE importing
sys.path.insert(0, str(Path(__file__).parent / "server"))

# Load environment variables early
load_dotenv()

# Import after path setup
try:
    from app.core.report_generator import report_generator
except ImportError as e:
    print(f"✗ Failed to import report generator: {e}")
    print("  Make sure you're running from the project root directory")
    sys.exit(1)

async def test_gemini():
    print("=" * 80)
    print("SENTINEL-AI GEMINI INTEGRATION TEST")
    print("=" * 80)
    print()
    
    # Configuration already loaded, just run tests
    print("1. GEMINI CONFIGURATION")
    print("-" * 80)
    print(f"   Gemini API Available: {report_generator.initialized and getattr(report_generator, 'GEMINI_AVAILABLE', False)}")
    print(f"   API Keys Configured: {len(report_generator.gemini_keys)}")
    if report_generator.gemini_keys:
        for idx, key in enumerate(report_generator.gemini_keys):
            key_preview = f"{key[:20]}...{key[-4:]}" if len(key) > 24 else key
            print(f"      Key {idx+1}: {key_preview}")
    print(f"   Model Candidates: {', '.join(report_generator.gemini_model_candidates)}")
    print(f"   Daily Limit: {report_generator.gemini_daily_report_limit}/day")
    print(f"   Hourly Limit: {report_generator.gemini_hourly_report_limit}/hour")
    print()
    
    print("2. GEMINI STATUS DIAGNOSTICS")
    print("-" * 80)
    try:
        diagnosis = await report_generator.diagnose_gemini_status()
        print(json.dumps(diagnosis, indent=2))
    except Exception as e:
        print(f"✗ Diagnostics failed: {e}")
        return False
    
    print()
    print("3. TEST REPORT GENERATION")
    print("-" * 80)
    
    # Create a test threat analysis
    test_threat_data = {
        "input": "8.8.8.8",
        "input_type": "ip",
        "verdict": "BENIGN",
        "confidence": 0.95,
        "threat_indicators": [
            {
                "source": "test",
                "severity": "low",
                "indicator": "Public DNS server"
            }
        ],
        "api_results": {
            "virustotal": {
                "detected_urls": 0,
                "detection_ratio": "0/88"
            }
        },
        "summary": "Test threat assessment",
        "threats_detected": 0,
        "analysis_data": {},
        "file_analysis": {},
        "forensic_metadata": {},
        "scan_id": "test_scan_001",
        "threat_level": "low",
        "status": "complete",
        "report_type": "executive_summary",
        "intervals": ["24h", "7d", "30d"],
        "timestamp": "2024-04-28T00:00:00Z"
    }
    
    try:
        print("   Generating AI analysis using Gemini...")
        analysis = await report_generator._generate_ai_analysis(test_threat_data)
        
        if analysis:
            word_count = len(analysis.split())
            if "false" in analysis.lower() or "fallback" in analysis.lower() or "local" in analysis.lower():
                print(f"   ⚠  Generated analysis appears to be fallback (local)")
                print(f"   Reason: {report_generator._last_gemini_failure_reason}")
            else:
                print(f"   ✓ Generated AI analysis ({word_count} words)")
            
            # Print first 500 chars
            print(f"\n   First 500 characters of analysis:")
            print(f"   {'-' * 76}")
            preview = analysis[:500]
            for line in preview.split('\n'):
                print(f"   {line}")
            print(f"   {'-' * 76}")
        else:
            print(f"   ✗ Analysis generation failed")
            print(f"   Reason: {report_generator._last_gemini_failure_reason}")
    except Exception as e:
        print(f"   ✗ Error during report generation: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print()
    print("4. RECOMMENDATIONS")
    print("-" * 80)
    
    if not report_generator.initialized:
        print("   ✗ Gemini not initialized. Check:")
        print("     - GEMINI_API_KEY environment variable is set")
        print("     - google-genai or google-generativeai package is installed")
        print("     - Run: pip install google-genai")
    
    if len(report_generator.gemini_keys) == 0:
        print("   ✗ No API keys configured. Set GEMINI_API_KEY in .env")
    
    if "api_keys_valid" in diagnosis and not diagnosis.get("api_keys_valid"):
        print("   ✗ API keys may be invalid or expired. Check:")
        print("     - Create new API key at: https://aistudio.google.com/app/apikey")
        print("     - Ensure you have billing enabled for Gemini API")
        print("     - Test with: curl -X GET 'https://generativelanguage.googleapis.com/v1beta/models'")
    
    if diagnosis.get("circuit_breaker_open"):
        print("   ⚠  Circuit breaker is open - Gemini is rate-limited")
        print(f"     Will reset at: {diagnosis.get('circuit_open_until')}")
    
    if diagnosis.get("quota_cooldown_active"):
        print("   ⚠  Quota cooldown active - API is paused after rate limit")
        print(f"     Will reset at: {diagnosis.get('quota_cooldown_until')}")
    
    if diagnosis.get("daily_reports_count", 0) >= (diagnosis.get("daily_reports_limit", 50) * 0.8):
        print(f"   ⚠  Daily report limit approaching: {diagnosis.get('daily_reports_count', 0)}/{diagnosis.get('daily_reports_limit', 50)}")
        print("     Increase GEMINI_DAILY_REPORT_LIMIT or add more API keys with GEMINI_API_KEYS")
    
    if "GEMINI_API_KEY" not in os.environ:
        print("   ℹ  Hint: Set GEMINI_API_KEY in .env to enable Gemini reports")
    
    print()
    print("=" * 80)
    print("TEST COMPLETE")
    print("=" * 80)
    
    return True


if __name__ == "__main__":
    success = asyncio.run(test_gemini())
    sys.exit(0 if success else 1)
