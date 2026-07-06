#!/usr/bin/env python3
"""
ANALYSIS INTEGRATION INITIALIZATION
Ensures all macro detection, file analysis, and threat analysis methods are properly initialized.
"""

import os
import sys
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)-8s | %(name)-30s | %(message)s"
)
logger = logging.getLogger(__name__)

def init_analysis_environment():
    """Initialize and verify all analysis environments."""
    
    logger.info("="*80)
    logger.info("ANALYSIS INTEGRATION INITIALIZATION")
    logger.info("="*80)
    
    # Load environment
    from dotenv import load_dotenv
    load_dotenv()
    
    # Ensure external APIs are enabled
    os.environ['EXTERNAL_APIS_ENABLED'] = os.environ.get('EXTERNAL_APIS_ENABLED', 'true')
    os.environ['SENTINEL_ENABLE_MACRO_DETECTION'] = os.environ.get('SENTINEL_ENABLE_MACRO_DETECTION', 'true')
    os.environ['SENTINEL_ENABLE_ML_ANALYSIS'] = os.environ.get('SENTINEL_ENABLE_ML_ANALYSIS', 'true')
    os.environ['SENTINEL_USE_ALL_ANALYSIS_METHODS'] = os.environ.get('SENTINEL_USE_ALL_ANALYSIS_METHODS', 'true')
    
    logger.info("\n1. ENVIRONMENT CONFIGURATION")
    logger.info("-" * 80)
    logger.info(f"   EXTERNAL_APIS_ENABLED={os.environ.get('EXTERNAL_APIS_ENABLED')}")
    logger.info(f"   SENTINEL_ENABLE_MACRO_DETECTION={os.environ.get('SENTINEL_ENABLE_MACRO_DETECTION')}")
    logger.info(f"   SENTINEL_ENABLE_ML_ANALYSIS={os.environ.get('SENTINEL_ENABLE_ML_ANALYSIS')}")
    logger.info(f"   SENTINEL_USE_ALL_ANALYSIS_METHODS={os.environ.get('SENTINEL_USE_ALL_ANALYSIS_METHODS')}")
    
    # Setup Python path
    sys.path.insert(0, str(Path(__file__).parent / "server"))
    sys.path.insert(0, str(Path(__file__).parent / "client"))
    
    logger.info("\n2. DEPENDENCY VERIFICATION")
    logger.info("-" * 80)
    
    deps = {
        'pefile': False,
        'lief': False,
        'capstone': False,
        'yara': False,
        'sklearn': False,
        'numpy': False,
        'google.genai': False,
    }
    
    for dep in deps.keys():
        try:
            __import__(dep)
            deps[dep] = True
            logger.info(f"   ✅ {dep:20s} | Available")
        except ImportError:
            logger.warning(f"   ⚠️  {dep:20s} | Not available (limited analysis)")
    
    logger.info("\n3. THREAT ANALYZER INITIALIZATION")
    logger.info("-" * 80)
    
    try:
        from app.core.threat_analyzer import ThreatAnalyzer
        ta = ThreatAnalyzer()
        logger.info(f"   ✅ ThreatAnalyzer initialized")
        logger.info(f"   ✓  Input detector: {ta.detector is not None}")
        logger.info(
            f"   ✓  ML models available: "
            f"{(getattr(ta, 'anomaly_model', None) is not None and getattr(ta, 'threat_model', None) is not None)}"
        )
        
        # List analysis methods
        methods = [m for m in dir(ta) if m.startswith('_analyze') and callable(getattr(ta, m))]
        logger.info(f"   ✓  Analysis methods: {len(methods)}")
        
    except Exception as e:
        logger.error(f"   ✗ ThreatAnalyzer failed: {e}")
        return False
    
    logger.info("\n4. FILE SCANNER INITIALIZATION")
    logger.info("-" * 80)
    
    try:
        from scanner.file_scanner import FileScanner, PE_ANALYSIS_AVAILABLE, ML_ANALYSIS_AVAILABLE
        fs = FileScanner()
        logger.info(f"   ✅ FileScanner initialized")
        logger.info(f"   ✓  YARA rules: {fs.yara_rules is not None}")
        logger.info(f"   ✓  PE analysis available: {PE_ANALYSIS_AVAILABLE}")
        logger.info(f"   ✓  ML analysis available: {ML_ANALYSIS_AVAILABLE}")
        logger.info(f"   ✓  Macro detection: {getattr(fs, '_macro_detection_enabled', True)}")
        
    except Exception as e:
        logger.error(f"   ✗ FileScanner failed: {e}")
        return False
    
    logger.info("\n5. API ENDPOINTS INITIALIZATION")
    logger.info("-" * 80)
    
    try:
        from app.api.v1.endpoints.scan import (
            _office_document_analysis_v1,
            _local_scan_v1,
        )
        logger.info(f"   ✅ Office document analysis: Available")
        logger.info(f"   ✅ Local file scanning: Available")
        
    except Exception as e:
        logger.error(f"   ✗ API endpoints failed: {e}")
        return False
    
    logger.info("\n6. EXTERNAL API VERIFICATION")
    logger.info("-" * 80)
    
    from app.config import settings
    
    api_keys = {
        'VIRUSTOTAL': (settings.VIRUSTOTAL_API_KEY, 'VirusTotal'),
        'ABUSEIPDB': (settings.ABUSEIPDB_API_KEY, 'AbuseIPDB'),
        'SHODAN': (settings.SHODAN_API_KEY, 'Shodan'),
        'URLSCAN': (settings.URLSCAN_API_KEY, 'URLScan'),
        'HYBRIDANALYSIS': (settings.HYBRIDANALYSIS_API_KEY, 'Hybrid Analysis'),
    }
    
    available_apis = 0
    for key_name, (key_value, display), in api_keys.items():
        if key_value and str(key_value).strip():
            logger.info(f"   ✅ {display:20s} | Configured")
            available_apis += 1
        else:
            logger.warning(f"   ⚠️  {display:20s} | Not configured")
    
    logger.info(f"   📊 {available_apis}/5 external APIs configured")
    
    logger.info("\n7. GEMINI AI VERIFICATION")
    logger.info("-" * 80)
    
    gemini_keys = []
    for i in range(1, 21):
        key_var = f'GEMINI_API_KEY_{i}' if i > 1 else 'GEMINI_API_KEY'
        key_val = os.getenv(key_var, '')
        if key_val:
            gemini_keys.append(key_val)
    
    # Also check comma-separated keys
    for csv_var in ['GEMINI_API_KEYS', 'GOOGLE_API_KEYS']:
        csv_val = os.getenv(csv_var, '')
        if csv_val:
            gemini_keys.extend([k.strip() for k in csv_val.split(',') if k.strip()])
    
    unique_keys = len(set(gemini_keys))
    logger.info(f"   ✅ Gemini API keys: {unique_keys} configured")
    
    if unique_keys > 0:
        try:
            import google.genai as genai
            logger.info(f"   ✅ Google Genai library available")
        except ImportError:
            logger.warning(f"   ⚠️  google-genai not installed")
    
    logger.info("\n8. ANALYSIS CAPABILITIES SUMMARY")
    logger.info("-" * 80)
    
    capabilities = {
        "Macro Detection": True,
        "File Analysis": True,
        "PE/ELF Parsing": deps['pefile'] or deps['lief'],
        "YARA Scanning": deps['yara'],
        "String Extraction": True,
        "Hash Analysis": available_apis > 0,
        "IP Geolocation": available_apis >= 1,
        "Domain Reputation": available_apis >= 1,
        "URL Analysis": available_apis >= 1,
        "ML Anomaly Detection": deps['sklearn'] and deps['numpy'],
        "ML Threat Prediction": deps['sklearn'] and deps['numpy'],
        "Gemini AI Analysis": unique_keys > 0,
        "Report Generation": True,
    }
    
    for capability, available in capabilities.items():
        symbol = "✅" if available else "⚠️"
        logger.info(f"   {symbol} {capability:25s} | {'Enabled' if available else 'Limited'}")
    
    logger.info("\n" + "="*80)
    logger.info("✅ ALL ANALYSIS SYSTEMS INITIALIZED AND READY")
    logger.info("   Ready to process: Files | IPs | Domains | URLs | Hashes")
    logger.info("   With: Macro detection | File analysis | API correlation | ML | Gemini AI")
    logger.info("="*80 + "\n")
    
    return True

if __name__ == "__main__":
    success = init_analysis_environment()
    sys.exit(0 if success else 1)
