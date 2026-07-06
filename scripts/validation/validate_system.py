#!/usr/bin/env python3
"""
SENTINEL-AI System Configuration Validator & Fixer
Ensures all threat intelligence providers are properly configured and working
"""

import os
import sys
import re
from pathlib import Path
from typing import Dict, List, Tuple


def check_env_file() -> Tuple[bool, Dict[str, str]]:
    """Check if .env file exists and contains required API keys"""
    
    env_path = Path(__file__).resolve().parents[2] / ".env"
    
    print("\n" + "="*80)
    print("1. ENVIRONMENT FILE CHECK")
    print("="*80)
    
    if not env_path.exists():
        print(f"❌ .env file not found at: {env_path}")
        print(f"   Create it by copying .env.example and filling in your API keys")
        return False, {}
    
    print(f"✅ .env file found at: {env_path}")
    
    # Parse .env file
    config = {}
    with open(env_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                key, value = line.split('=', 1)
                config[key.strip()] = value.strip()
    
    return True, config


def validate_api_keys(config: Dict[str, str]) -> List[Tuple[str, bool, str]]:
    """Validate API keys are properly configured"""
    
    print("\n" + "="*80)
    print("2. API KEY VALIDATION")
    print("="*80)
    
    api_keys_to_check = [
        ("VIRUSTOTAL_API_KEY", "VirusTotal", 64, "hexadecimal string"),
        ("ABUSEIPDB_API_KEY", "AbuseIPDB", 80, "long alphanumeric string"),
        ("SHODAN_API_KEY", "Shodan", 20, "alphanumeric string"),
        ("HYBRIDANALYSIS_API_KEY", "Hybrid Analysis", 32, "alphanumeric string"),
        ("URLSCAN_API_KEY", "URLScan.io", 36, "UUID format"),
    ]
    
    results = []
    
    for env_key, display_name, min_length, format_desc in api_keys_to_check:
        api_key = config.get(env_key, "").strip().strip('"').strip("'")
        
        is_valid = bool(api_key and len(api_key) >= min_length and not api_key.startswith("your_"))
        status_icon = "✅" if is_valid else "❌"
        
        if not api_key:
            status = f"{status_icon} {display_name}: NOT CONFIGURED (empty)"
        elif api_key.startswith("your_") or api_key == "":
            status = f"{status_icon} {display_name}: NOT CONFIGURED (placeholder value)"
        elif len(api_key) < min_length:
            status = f"{status_icon} {display_name}: INVALID (too short - {len(api_key)} chars, need {min_length})"
        else:
            status = f"{status_icon} {display_name}: Configured ({len(api_key)} chars, {format_desc})"
        
        print(f"   {status}")
        results.append((env_key, is_valid, api_key))
    
    return results


def validate_external_apis_enabled(config: Dict[str, str]) -> bool:
    """Check if external APIs are enabled"""
    
    print("\n" + "="*80)
    print("3. EXTERNAL API SETTINGS")
    print("="*80)
    
    external_apis_enabled = config.get("EXTERNAL_APIS_ENABLED", "True").lower() in ("true", "1", "yes", "on")
    
    if external_apis_enabled:
        print("   ✅ EXTERNAL_APIS_ENABLED: True (external APIs will be used)")
    else:
        print("   ⚠️  EXTERNAL_APIS_ENABLED: False (system running in local-only mode)")
        print("      FIX: Set EXTERNAL_APIS_ENABLED=True in .env to enable providers")
    
    return external_apis_enabled


def check_gemini_configuration(config: Dict[str, str]) -> Tuple[bool, List[str]]:
    """Check Gemini API configuration for report generation"""
    
    print("\n" + "="*80)
    print("4. GEMINI API (FOR REPORT GENERATION)")
    print("="*80)
    
    gemini_keys = []
    
    # Check single key
    key = config.get("GEMINI_API_KEY", "").strip().strip('"').strip("'")
    if key and not key.startswith("your_"):
        gemini_keys.append(key)
    
    # Check CSV keys
    csv_keys = config.get("GEMINI_API_KEYS", "").strip().strip('"').strip("'")
    if csv_keys:
        for k in csv_keys.split(","):
            k = k.strip()
            if k and not k.startswith("your_"):
                gemini_keys.append(k)
    
    # Check numbered keys
    for i in range(1, 6):
        key = config.get(f"GEMINI_API_KEY_{i}", "").strip().strip('"').strip("'")
        if key and not key.startswith("your_"):
            gemini_keys.append(key)
    
    if gemini_keys:
        print(f"   ✅ Gemini API: Configured ({len(gemini_keys)} key(s) available)")
        return True, gemini_keys
    else:
        print("   ⚠️  Gemini API: Not configured (reports will fall back to text-only)")
        return False, []


def suggest_fixes() -> str:
    """Generate fix recommendations"""
    
    fixes = """
================================================================================
FIXING YOUR SENTINEL-AI THREAT INTELLIGENCE SETUP
================================================================================

STEP 1: Verify Your API Keys
────────────────────────────
1. Go to each provider's website:
   - VirusTotal: https://www.virustotal.com/gui/my-apikey
   - AbuseIPDB: https://www.abuseipdb.com/api  
   - Shodan: https://account.shodan.io/
   - URLScan: https://urlscan.io/user/profile/
   - Hybrid Analysis: https://www.hybrid-analysis.com/manage-api

2. Copy your API keys

3. Update your .env file:
   VIRUSTOTAL_API_KEY=your_actual_key_here
   ABUSEIPDB_API_KEY=your_actual_key_here
   SHODAN_API_KEY=your_actual_key_here
   URLSCAN_API_KEY=your_actual_key_here
   HYBRIDANALYSIS_API_KEY=your_actual_key_here

STEP 2: Enable External APIs
──────────────────────────────
   EXTERNAL_APIS_ENABLED=true

STEP 3: Test Provider Connectivity
───────────────────────────────────
    python tests/manual/manual_threat_intel_provider_check.py

STEP 4: Verify System Configuration
────────────────────────────────────
    python scripts/validation/validate_system.py

COMMON ISSUES & SOLUTIONS
═════════════════════════

Issue: "Provider unavailable" in reports
Solution:
  1. Check API keys are valid and not expired
  2. Verify EXTERNAL_APIS_ENABLED=true
  3. Check network connectivity to provider APIs
  4. Verify no firewall blocking outbound HTTPS

Issue: "Rate limited" messages
Solution:
  1. Check your provider's usage dashboard
  2. Free tiers often have daily limits
  3. Wait for rate limit window to reset
  4. Upgrade to paid account for higher limits

Issue: "Not configured" status
Solution:
  1. Ensure .env file has proper API keys
  2. No extra spaces or quotes around values
  3. Restart the server after updating .env
  4. Check database may still have cached old status

NEXT STEPS
══════════
1. Update your .env file with valid API keys
2. Run the test script to verify connectivity
3. Restart the SENTINEL-AI server
4. Run a scan and check the telemetry coverage report
5. All providers should now show "Provider data collected successfully"
"""
    
    return fixes


def generate_env_template(current_config: Dict[str, str]) -> str:
    """Generate a template with current settings"""
    
    template = """# SENTINEL-AI Configuration Template
# Paste your actual API keys here

# Application Settings
DEBUG=True
PROJECT_NAME=SENTINEL-AI
VERSION=1.0.0
API_V1_PREFIX=/api/v1
API_PORT=8000

# API Keys for Threat Intelligence Services
VIRUSTOTAL_API_KEY={vt_key}
ABUSEIPDB_API_KEY={abuse_key}
SHODAN_API_KEY={shodan_key}
HYBRIDANALYSIS_API_KEY={ha_key}
URLSCAN_API_KEY={urlscan_key}

# Enable/Disable External APIs
EXTERNAL_APIS_ENABLED=true

# Gemini API for AI-powered analysis (optional but recommended)
GEMINI_API_KEY={gemini_key}

# Database Configuration
DATABASE_URL=sqlite:///./sentinel.db
REDIS_URL=redis://localhost:6379

# Security Settings
SECRET_KEY={secret_key}
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# CORS and Host Settings
ALLOWED_HOSTS=localhost,127.0.0.1
CORS_ORIGINS=http://localhost:3000,http://localhost:8080,http://localhost:5000,http://127.0.0.1:3000,http://127.0.0.1:8080,http://127.0.0.1:5000

# Email Settings
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
FROM_EMAIL=alerts@sentinel-ai.com
ALERT_EMAIL=your-email@gmail.com

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60
API_CACHE_TTL=300

# Admin Configuration
ADMIN_INFRA_HOSTNAMES=kali,kali-linux-vbox
ADMIN_INFRA_IPS=127.0.0.1
"""
    
    return template.format(
        vt_key=current_config.get("VIRUSTOTAL_API_KEY", "your_key_here"),
        abuse_key=current_config.get("ABUSEIPDB_API_KEY", "your_key_here"),
        shodan_key=current_config.get("SHODAN_API_KEY", "your_key_here"),
        ha_key=current_config.get("HYBRIDANALYSIS_API_KEY", "your_key_here"),
        urlscan_key=current_config.get("URLSCAN_API_KEY", "your_key_here"),
        gemini_key=current_config.get("GEMINI_API_KEY", "your_key_here"),
        secret_key=current_config.get("SECRET_KEY", "Ranbir@96469"),
    )


def main():
    """Main validation function"""
    
    print("\n\n")
    print("█" * 80)
    print("       SENTINEL-AI THREAT INTELLIGENCE PROVIDER CONFIGURATION")
    print("█" * 80)
    
    # Check .env file
    env_exists, config = check_env_file()
    if not env_exists:
        print("\n❌ Cannot proceed without .env file")
        sys.exit(1)
    
    # Validate API keys
    api_results = validate_api_keys(config)
    all_apis_working = sum(1 for _, is_valid, _ in api_results if is_valid)
    
    # Check external APIs enabled
    external_enabled = validate_external_apis_enabled(config)
    
    # Check Gemini
    gemini_ok, gemini_keys = check_gemini_configuration(config)
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Threat Intelligence Providers Configured: {all_apis_working}/5")
    print(f"External APIs Enabled: {'✅ Yes' if external_enabled else '❌ No'}")
    print(f"Gemini API for Reports: {'✅ Yes' if gemini_ok else '⚠️  Optional'}")
    
    if all_apis_working < 1:
        print("\n❌ NO THREAT INTELLIGENCE PROVIDERS CONFIGURED!")
    elif all_apis_working < 3:
        print("\n⚠️  LIMITED THREAT INTELLIGENCE COVERAGE")
        print("   Configure more providers for better threat detection.")
    else:
        print("\n✅ GOOD THREAT INTELLIGENCE COVERAGE")
        print("   Your system has access to multiple threat intelligence sources.")
    
    # Print fixes
    print(suggest_fixes())
    
    # Generate template
    print("\n" + "="*80)
    print("RECOMMENDED .env CONFIGURATION")
    print("="*80)
    print(generate_env_template(config))


if __name__ == "__main__":
    main()
