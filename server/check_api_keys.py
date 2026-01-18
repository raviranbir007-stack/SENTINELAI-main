#!/usr/bin/env python3
"""
Check API Key Configuration Status
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file
env_file = Path(__file__).parent / ".env"
load_dotenv(env_file)

print("="*80)
print("🔑 API KEY CONFIGURATION STATUS")
print("="*80)

# Check for .env file
env_file = Path(__file__).parent / ".env"
if env_file.exists():
    print(f"✅ .env file found: {env_file}")
else:
    print(f"❌ .env file NOT found: {env_file}")
    print(f"   Creating template .env file...")
    
    template = """# SENTINEL-AI API Keys Configuration

# VirusTotal API Key
# Get your key from: https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY=

# AbuseIPDB API Key  
# Get your key from: https://www.abuseipdb.com/api
ABUSEIPDB_API_KEY=

# URLScan.io API Key
# Get your key from: https://urlscan.io/user/profile/
URLSCAN_API_KEY=

# Shodan API Key
# Get your key from: https://account.shodan.io/
SHODAN_API_KEY=

# Hybrid Analysis API Key
# Get your key from: https://www.hybrid-analysis.com/apikeys/info
HYBRIDANALYSIS_API_KEY=

# Gemini AI API Key (Required for AI analysis)
# Get your key from: https://makersuite.google.com/app/apikey
GEMINI_API_KEY=

# Database
DATABASE_URL=sqlite:///./test.db

# Security
SECRET_KEY=your-secret-key-here-change-in-production
"""
    
    env_file.write_text(template)
    print(f"✅ Created template .env file")
    print(f"   Edit {env_file} to add your API keys")

print("\n" + "="*80)
print("📊 CURRENT API KEY STATUS")
print("="*80)

api_keys = {
    'VirusTotal': os.getenv('VIRUSTOTAL_API_KEY', ''),
    'AbuseIPDB': os.getenv('ABUSEIPDB_API_KEY', ''),
    'URLScan.io': os.getenv('URLSCAN_API_KEY', ''),
    'Shodan': os.getenv('SHODAN_API_KEY', ''),
    'Hybrid Analysis': os.getenv('HYBRIDANALYSIS_API_KEY', ''),
    'Gemini AI': os.getenv('GEMINI_API_KEY', ''),
}

configured_count = 0
for service, key in api_keys.items():
    if key and len(key) > 10:
        print(f"✅ {service:20s} - Configured ({len(key)} chars)")
        configured_count += 1
    elif key:
        print(f"⚠️  {service:20s} - Configured but seems short ({len(key)} chars)")
        configured_count += 1
    else:
        print(f"❌ {service:20s} - NOT configured")

print("="*80)
print(f"📈 Summary: {configured_count}/{len(api_keys)} API keys configured")
print("="*80)

if configured_count == 0:
    print("\n⚠️  WARNING: No API keys configured!")
    print("   The system will work but with limited threat intelligence.")
    print("   ")
    print("   To configure API keys:")
    print(f"   1. Edit: {env_file}")
    print("   2. Add your API keys to the file")
    print("   3. Restart the server")
    print("")
    print("   Note: Gemini AI key is highly recommended for AI-powered analysis!")
elif configured_count < len(api_keys):
    print("\n💡 TIP: Configure more API keys for better threat detection!")
    print("   Each API provides different threat intelligence data.")
else:
    print("\n✅ All API keys configured! Maximum threat detection enabled.")

print("\n" + "="*80)
