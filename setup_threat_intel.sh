#!/bin/bash
# SENTINEL-AI Threat Intelligence Provider Setup & Fix Script
# Quick script to get threat intelligence providers working perfectly

set -e

echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo "           SENTINEL-AI THREAT INTELLIGENCE PROVIDER SETUP WIZARD"
echo "════════════════════════════════════════════════════════════════════════════════"

PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$PROJECT_ROOT"

echo ""
echo "1️⃣  CHECKING SYSTEM STATE..."
echo "────────────────────────────────────────────────────────────────────────────────"

if [ ! -f ".env" ]; then
    echo "❌ ERROR: .env file not found"
    echo ""
    echo "Please copy .env.example to .env:"
    echo "  cp .env.example .env"
    echo ""
    echo "Then edit .env and add your API keys:"
    echo "  - VIRUSTOTAL_API_KEY"
    echo "  - ABUSEIPDB_API_KEY" 
    echo "  - SHODAN_API_KEY"
    echo "  - HYBRIDANALYSIS_API_KEY"
    echo "  - URLSCAN_API_KEY"
    exit 1
fi

echo "✅ .env file found"

# Check if Python test scripts exist
if [ ! -f "validate_system.py" ]; then
    echo "⚠️ validate_system.py not found - creating it..."
fi

echo ""
echo "2️⃣  VALIDATING CONFIGURATION..."
echo "────────────────────────────────────────────────────────────────────────────────"

# Check for required settings
EXTERNAL_APIS=$(grep "^EXTERNAL_APIS_ENABLED" .env | cut -d'=' -f2 | tr '[:upper:]' '[:lower:]' | tr -d ' ')

if [ -z "$EXTERNAL_APIS" ] || [ "$EXTERNAL_APIS" != "true" ]; then
    echo "⚠️  EXTERNAL_APIS_ENABLED is not set to true"
    echo "   Fixing: Setting EXTERNAL_APIS_ENABLED=true"
    
    # Backup original .env
    cp .env .env.backup
    
    # Update or add EXTERNAL_APIS_ENABLED
    if grep -q "^EXTERNAL_APIS_ENABLED" .env; then
        sed -i 's/^EXTERNAL_APIS_ENABLED=.*/EXTERNAL_APIS_ENABLED=true/' .env
    else
        echo "EXTERNAL_APIS_ENABLED=true" >> .env
    fi
    
    echo "✅ Updated .env"
else
    echo "✅ EXTERNAL_APIS_ENABLED=true"
fi

echo ""
echo "3️⃣  CHECKING API KEY CONFIGURATION..."
echo "────────────────────────────────────────────────────────────────────────────────"

check_api_key() {
    local key_name=$1
    local min_length=$2
    if grep -q "^$key_name" .env; then
        local value=$(grep "^$key_name" .env | cut -d'=' -f2- | tr -d ' ' | tr -d '"' | tr -d "'")
        if [ -z "$value" ] || [ "$value" = "your_key" ] || [[ "$value" == your_* ]]; then
            echo "❌ $key_name: Not configured (empty or placeholder)"
            return 1
        elif [ ${#value} -lt $min_length ]; then
            echo "⚠️  $key_name: Short key (${#value} chars)"
            return 2
        else
            echo "✅ $key_name: Configured"
            return 0
        fi
    else
        echo "❌ $key_name: Missing from .env"
        return 1
    fi
}

check_api_key "VIRUSTOTAL_API_KEY" 60
check_api_key "ABUSEIPDB_API_KEY" 80
check_api_key "SHODAN_API_KEY" 15
check_api_key "HYBRIDANALYSIS_API_KEY" 30
check_api_key "URLSCAN_API_KEY" 30

echo ""
echo "4️⃣  AVAILABLE DIAGNOSTIC TOOLS..."
echo "────────────────────────────────────────────────────────────────────────────────"
echo ""
echo "To fully test and fix your setup, run these tools in order:"
echo ""
echo "  1️⃣  System Validation:"
echo "      python validate_system.py"
echo ""
echo "  2️⃣  Provider Connectivity Test:"
echo "      python test_threat_intel_providers.py"
echo ""
echo "  3️⃣  End-to-End Analysis Test:"
echo "      python test_end_to_end.py"
echo ""

echo "────────────────────────────────────────────────────────────────────────────────"
echo ""
echo "✅ SETUP COMPLETE!"
echo ""
echo "Next steps:"
echo "  1. Run: python validate_system.py"
echo "  2. Fix any missing API keys shown above"
echo "  3. Restart SENTINEL-AI server"
echo "  4. Run a threat scan and check the telemetry coverage report"
echo ""
echo "For detailed instructions, see: THREAT_INTEL_FIX_README.md"
echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""
