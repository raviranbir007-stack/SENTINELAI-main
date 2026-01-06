#!/usr/bin/env python3
"""
SENTINEL-AI Comprehensive Test Suite
Tests all major improvements and features
"""

import sys
import json
from typing import Dict, Any

# Color codes for terminal output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def print_header(text: str):
    print(f"\n{BLUE}{'='*70}{RESET}")
    print(f"{BLUE}{text.center(70)}{RESET}")
    print(f"{BLUE}{'='*70}{RESET}\n")

def print_success(text: str):
    print(f"{GREEN}✅ {text}{RESET}")

def print_error(text: str):
    print(f"{RED}❌ {text}{RESET}")

def print_info(text: str):
    print(f"{YELLOW}ℹ️  {text}{RESET}")

def test_google_import():
    """Test 1: Google AI Package Import"""
    print_header("Test 1: Google AI Package Import")
    try:
        import google.genai
        print_success("Google AI package imported successfully")
        print_info(f"Module path: {google.genai.__file__}")
        return True
    except ImportError as e:
        print_error(f"Failed to import google.genai: {e}")
        return False

def test_anomaly_detector():
    """Test 2: Enhanced Anomaly Detector"""
    print_header("Test 2: Enhanced Anomaly Detector")
    try:
        from app.anomaly_detector import get_anomaly_detector
        
        detector = get_anomaly_detector()
        
        # Test with clean data
        clean_data = {
            'target': 'google.com',
            'verdict': 'safe'
        }
        
        clean_result = detector.detect(clean_data)
        print_info("Clean Data Test:")
        print(json.dumps(clean_result, indent=2))
        
        # Test with malicious data
        malicious_data = {
            'target': 'cmd.exe /c evil_payload',
            'port': 31337,
            'threat_indicators': [
                {'severity': 'critical', 'indicator': 'Shell command'},
                {'severity': 'high', 'indicator': 'Backdoor port'}
            ],
            'verdict': 'malicious'
        }
        
        malicious_result = detector.detect(malicious_data)
        print_info("\nMalicious Data Test:")
        print(json.dumps(malicious_result, indent=2))
        
        # Verify results
        if not clean_result['is_anomalous'] and malicious_result['is_anomalous']:
            print_success("Anomaly detector working correctly")
            return True
        else:
            print_error("Anomaly detector not working as expected")
            return False
            
    except Exception as e:
        print_error(f"Anomaly detector test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_threat_prediction():
    """Test 3: Enhanced Threat Prediction Model"""
    print_header("Test 3: Enhanced Threat Prediction Model")
    try:
        from app.ml_models import get_threat_model
        
        model = get_threat_model()
        
        # Test with safe data
        safe_features = {
            'threat_indicators': [],
            'verdict': 'safe',
            'malicious_score': 0.0,
            'detection_ratio': '0/70'
        }
        
        safe_result = model.predict(safe_features)
        print_info("Safe Data Test:")
        print(json.dumps(safe_result, indent=2))
        
        # Test with threat data
        threat_features = {
            'threat_indicators': [
                {'severity': 'critical'},
                {'severity': 'high'},
                {'severity': 'medium'}
            ],
            'verdict': 'malicious',
            'malicious_score': 0.9,
            'detection_ratio': '45/70'
        }
        
        threat_result = model.predict(threat_features)
        print_info("\nThreat Data Test:")
        print(json.dumps(threat_result, indent=2))
        
        # Verify results
        if not safe_result['is_threat'] and threat_result['is_threat']:
            print_success("Threat prediction model working correctly")
            print_info(f"Threat level: {threat_result['threat_level']}")
            print_info(f"Factors: {', '.join(threat_result['factors'])}")
            return True
        else:
            print_error("Threat prediction model not working as expected")
            return False
            
    except Exception as e:
        print_error(f"Threat prediction test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_anomaly_model():
    """Test 4: Enhanced Anomaly Detection Model"""
    print_header("Test 4: Enhanced Anomaly Detection Model")
    try:
        from app.ml_models import get_anomaly_model
        
        model = get_anomaly_model()
        
        # Test with normal data
        normal_features = {
            'threat_indicators': [],
            'verdict': 'safe',
            'scan_type': 'url',
            'api_results': {}
        }
        
        normal_result = model.predict(normal_features)
        print_info("Normal Data Test:")
        print(json.dumps(normal_result, indent=2))
        
        # Test with anomalous data
        anomalous_features = {
            'threat_indicators': [
                {'severity': 'critical'},
                {'severity': 'high'}
            ],
            'verdict': 'malicious',
            'scan_type': 'file',
            'file_size': 15 * 1024 * 1024,  # 15MB
            'api_results': {
                'virustotal': {'malicious': True},
                'hybrid': {'malicious': True}
            }
        }
        
        anomalous_result = model.predict(anomalous_features)
        print_info("\nAnomalous Data Test:")
        print(json.dumps(anomalous_result, indent=2))
        
        # Verify results
        if not normal_result['is_anomaly'] and anomalous_result['is_anomaly']:
            print_success("Anomaly detection model working correctly")
            return True
        else:
            print_error("Anomaly detection model not working as expected")
            return False
            
    except Exception as e:
        print_error(f"Anomaly detection model test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_gemini_integration():
    """Test 5: Gemini Integration"""
    print_header("Test 5: Gemini Integration")
    try:
        from app.gemini_integration import GeminiIntegration
        
        gemini = GeminiIntegration()
        
        if gemini.is_available():
            print_success("Gemini AI initialized successfully")
            
            availability = gemini.check_availability()
            print_info(f"Status: {availability['status']}")
            print_info(f"Model: {availability.get('model', 'N/A')}")
            print_info(f"Available: {availability['available']}")
            return True
        else:
            print_info("Gemini AI not available (API key not configured)")
            print_info("This is expected if GEMINI_API_KEY is not set")
            return True  # Not a failure if API key isn't configured
            
    except Exception as e:
        print_error(f"Gemini integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_all_tests():
    """Run all tests and report results"""
    print(f"\n{BLUE}{'='*70}{RESET}")
    print(f"{BLUE}{'SENTINEL-AI Comprehensive Test Suite'.center(70)}{RESET}")
    print(f"{BLUE}{'='*70}{RESET}")
    
    tests = [
        ("Google AI Import", test_google_import),
        ("Anomaly Detector", test_anomaly_detector),
        ("Threat Prediction", test_threat_prediction),
        ("Anomaly Model", test_anomaly_model),
        ("Gemini Integration", test_gemini_integration),
    ]
    
    results = {}
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print_error(f"Test '{test_name}' crashed: {e}")
            results[test_name] = False
    
    # Print summary
    print_header("Test Summary")
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    for test_name, result in results.items():
        if result:
            print_success(f"{test_name}: PASSED")
        else:
            print_error(f"{test_name}: FAILED")
    
    print(f"\n{BLUE}{'='*70}{RESET}")
    if passed == total:
        print(f"{GREEN}All tests passed! ({passed}/{total}){RESET}")
        print(f"{GREEN}✅ SENTINEL-AI is fully operational{RESET}")
    else:
        print(f"{YELLOW}Some tests failed ({passed}/{total} passed){RESET}")
        print(f"{YELLOW}⚠️  Review failed tests above{RESET}")
    print(f"{BLUE}{'='*70}{RESET}\n")
    
    return passed == total

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
