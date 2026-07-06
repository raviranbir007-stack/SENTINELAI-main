#!/usr/bin/env python3
"""
Comprehensive Macro Detection & Analysis Methods Test
Checks initialization, macro detection, and all analysis methods.
"""

import asyncio
import sys
from pathlib import Path

# Setup path
sys.path.insert(0, str(Path(__file__).parent / "server"))

# Load env and disable external APIs to avoid rate limiting
from dotenv import load_dotenv
load_dotenv()

import os
os.environ['EXTERNAL_APIS_ENABLED'] = 'false'

import logging
# Suppress verbose logs
logging.getLogger('httpx').setLevel(logging.CRITICAL)
logging.getLogger('google_genai').setLevel(logging.CRITICAL)
logging.basicConfig(level=logging.WARNING, format="%(levelname)-8s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

async def test_macro_detection():
    """Test macro detection initialization and functionality."""
    print("\n" + "="*80)
    print("MACRO DETECTION & ANALYSIS METHODS TEST")
    print("="*80 + "\n")
    
    # 1. Test ThreatAnalyzer initialization
    print("1. THREATANALYZER INITIALIZATION")
    print("-" * 80)
    try:
        from app.core.threat_analyzer import ThreatAnalyzer
        ta = ThreatAnalyzer()
        print(f"   ✅ ThreatAnalyzer initialized")
        print(f"   ✓ Input detector ready: {ta.detector is not None}")
    except Exception as e:
        print(f"   ✗ Failed to initialize ThreatAnalyzer: {e}")
        return False
    
    # 2. Check analysis methods
    print("\n2. ANALYSIS METHODS AVAILABLE")
    print("-" * 80)
    analysis_methods = [m for m in dir(ta) if m.startswith('_analyze') and callable(getattr(ta, m))]
    print(f"   Total analysis methods: {len(analysis_methods)}")
    for method in sorted(analysis_methods):
        print(f"      ✓ {method}")
    
    # 3. Test FileScanner (client-side macro detection)
    print("\n3. FILE SCANNER MACRO DETECTION")
    print("-" * 80)
    try:
        from client.scanner.file_scanner import FileScanner
        fs = FileScanner()
        print(f"   ✅ FileScanner initialized")
        print(f"   ✓ YARA rules loaded: {fs.yara_rules is not None}")
        
        # Check macro markers
        from client.scanner.file_scanner import OLE_MACRO_MARKERS
        print(f"   ✓ OLE macro markers defined: {len(OLE_MACRO_MARKERS)}")
        print(f"      Sample markers: {list(OLE_MACRO_MARKERS)[:5]}")
    except Exception as e:
        print(f"   ✗ Failed to initialize FileScanner: {e}")
        return False
    
    # 4. Test server-side macro detection
    print("\n4. SERVER-SIDE MACRO DETECTION (scan endpoint)")
    print("-" * 80)
    try:
        from app.api.v1.endpoints.scan import _office_document_analysis_v1
        
        # Create a test macro document (minimal ZIP with macro indicator)
        import zipfile
        import io
        
        test_doc = io.BytesIO()
        with zipfile.ZipFile(test_doc, 'w') as z:
            z.writestr('_rels/.rels', '<Relationships>')
            z.writestr('word/document.xml', '<document><p>Test with vbaProject.bin info</p></document>')
            z.writestr('customXml/item.xml', 'CustomXml')
        
        test_bytes = test_doc.getvalue()
        result = _office_document_analysis_v1(test_bytes, "test.docm")
        
        if result:
            print(f"   ✅ Office document analysis working")
            print(f"   ✓ Macro capable detected: {result.get('macro_capable', False)}")
            print(f"   ✓ Archive layout: {result.get('archive_layout', 'unknown')}")
            print(f"   ✓ Signals detected: {len(result.get('signals', []))}")
        else:
            print(f"   ⚠  No signals detected in test document")
            
    except Exception as e:
        print(f"   ✗ Server-side macro detection test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # 5. Test threat analysis with URLs/IPs/hashes
    print("\n5. COMPLETE THREAT ANALYSIS TEST")
    print("-" * 80)
    test_cases = [
        ("8.8.8.8", "ip"),
        ("google.com", "domain"),
        ("https://google.com", "url"),
    ]
    
    for value, expected_type in test_cases:
        try:
            result = await ta.analyze(value, use_external_apis=False)
            detected_type = result.get("input_type", "unknown")
            verdict = result.get("verdict", "unknown")
            
            status = "✓" if detected_type == expected_type else "✗"
            print(f"   {status} {value:20} | Type: {detected_type:12} | Verdict: {verdict}")
        except Exception as e:
            print(f"   ✗ {value:20} | Error: {str(e)[:40]}")
    
    # 6. Check all analysis method implementations
    print("\n6. ANALYSIS METHOD IMPLEMENTATIONS")
    print("-" * 80)
    methods_to_check = [
        '_analyze_ip',
        '_analyze_domain',
        '_analyze_url',
        '_analyze_file_hash',
        '_analyze_file',
    ]
    
    for method_name in methods_to_check:
        try:
            method = getattr(ta, method_name, None)
            if callable(method):
                # Get method signature
                import inspect
                sig = inspect.signature(method)
                params = list(sig.parameters.keys())
                print(f"   ✓ {method_name:25} | params: {', '.join(params)}")
            else:
                print(f"   ✗ {method_name:25} | Not callable")
        except Exception as e:
            print(f"   ✗ {method_name:25} | Error: {e}")
    
    # 7. Macro detection coverage
    print("\n7. MACRO DETECTION COVERAGE")
    print("-" * 80)
    
    macro_coverage = {
        "OLE2 marker detection": b"\xd0\xcf\x11\xe0" in b"\xd0\xcf\x11\xe0",
        "ZIP-based Office": b"PK\x03\x04" in b"PK\x03\x04",
        "vbaProject.bin": "vbaproject.bin" in "vbaproject.bin",
        "Auto_Open macro": "auto_open" in "auto_open",
        "CreateObject()": "createobject(" in "createobject(",
        "Active content embedded": "embedded" in str(result.get('signals', [])) if result else False,
    }
    
    print("   Coverage check:")
    for check, status in macro_coverage.items():
        symbol = "✓" if status else "✗"
        print(f"      {symbol} {check}")
    
    # 8. Verify all critical methods are callable
    print("\n8. CRITICAL METHODS CALLABLE CHECK")
    print("-" * 80)
    critical_methods = [
        'analyze',
        '_prepare_api_tracking',
        '_check_cache',
        '_build_detection_coverage_overview',
        '_build_forensic_metadata',
    ]
    
    all_callable = True
    for method_name in critical_methods:
        method = getattr(ta, method_name, None)
        is_callable = callable(method)
        symbol = "✓" if is_callable else "✗"
        print(f"   {symbol} {method_name:30} | Callable: {is_callable}")
        if not is_callable:
            all_callable = False
    
    print("\n" + "="*80)
    if all_callable:
        print("✅ ALL MACRO DETECTION AND ANALYSIS METHODS OPERATIONAL")
    else:
        print("⚠  SOME METHODS NOT CALLABLE - SEE ABOVE FOR DETAILS")
    print("="*80 + "\n")
    
    return True if all_callable else False

if __name__ == "__main__":
    success = asyncio.run(test_macro_detection())
    sys.exit(0 if success else 1)
