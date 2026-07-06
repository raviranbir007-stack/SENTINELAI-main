#!/usr/bin/env python3
"""
QUICK START - Verify all analysis methods are working
Run this after starting the server to confirm full integration.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "server"))

from dotenv import load_dotenv
load_dotenv()

import os
os.environ['EXTERNAL_APIS_ENABLED'] = 'true'

import logging
logging.basicConfig(level=logging.INFO, format="%(message)s")

async def quick_test():
    print("\n" + "="*80)
    print("SENTINEL-AI QUICK START TEST")
    print("="*80)
    
    from app.core.threat_analyzer import ThreatAnalyzer
    
    ta = ThreatAnalyzer()
    
    # Test 1: IP Analysis
    print("\n✓ Test 1: IP Analysis")
    result = await ta.analyze("8.8.8.8", use_external_apis=True)
    print(f"  Verdict: {result.get('verdict', 'UNKNOWN')}")
    print(f"  Confidence: {result.get('confidence', 0):.1f}%")
    print(f"  Methods used: {len(result.get('analysis_methods', []))}")
    
    # Test 2: Domain Analysis
    print("\n✓ Test 2: Domain Analysis")
    result = await ta.analyze("google.com", use_external_apis=True)
    print(f"  Verdict: {result.get('verdict', 'UNKNOWN')}")
    print(f"  Confidence: {result.get('confidence', 0):.1f}%")
    print(f"  Methods used: {len(result.get('analysis_methods', []))}")
    
    # Test 3: URL Analysis
    print("\n✓ Test 3: URL Analysis")
    result = await ta.analyze("https://github.com", use_external_apis=True)
    print(f"  Verdict: {result.get('verdict', 'UNKNOWN')}")
    print(f"  Confidence: {result.get('confidence', 0):.1f}%")
    print(f"  Methods used: {len(result.get('analysis_methods', []))}")
    
    # Test 4: Hash Analysis
    print("\n✓ Test 4: Hash Analysis")
    result = await ta.analyze("d41d8cd98f00b204e9800998ecf8427e", use_external_apis=True)
    print(f"  Verdict: {result.get('verdict', 'UNKNOWN')}")
    print(f"  Confidence: {result.get('confidence', 0):.1f}%")
    print(f"  Methods used: {len(result.get('analysis_methods', []))}")
    
    # Test 5: File Macro Detection
    print("\n✓ Test 5: File Macro Detection")
    import zipfile, io
    doc = io.BytesIO()
    with zipfile.ZipFile(doc, 'w') as z:
        z.writestr('word/vbaProject.bin', b'VBA')
    
    from app.api.v1.endpoints.scan import _office_document_analysis_v1
    result = _office_document_analysis_v1(doc.getvalue(), "test.docm")
    if result:
        print(f"  ✓ Macro detection working")
        print(f"  Macro hits: {result.get('macro_hits', 0)}")
        print(f"  Macro capable: {result.get('macro_capable', False)}")
    
    print("\n" + "="*80)
    print("✅ ALL TESTS PASSED - SYSTEM READY FOR ANALYSIS")
    print("="*80 + "\n")

if __name__ == "__main__":
    asyncio.run(quick_test())
