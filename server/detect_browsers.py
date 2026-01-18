#!/usr/bin/env python3
"""
Comprehensive browser detection - find ALL installed browsers
"""
import os
from pathlib import Path
import subprocess

print("="*80)
print("🔍 COMPREHENSIVE BROWSER DETECTION")
print("="*80)

# Standard paths
browser_configs = {
    'Firefox': [
        Path.home() / ".mozilla" / "firefox",
        Path.home() / "snap" / "firefox" / "common" / ".mozilla" / "firefox",
        Path("/usr/bin/firefox"),
        Path("/usr/bin/firefox-esr"),
    ],
    'Chrome': [
        Path.home() / ".config" / "google-chrome",
        Path("/usr/bin/google-chrome"),
        Path("/usr/bin/google-chrome-stable"),
    ],
    'Chromium': [
        Path.home() / ".config" / "chromium",
        Path("/usr/bin/chromium"),
        Path("/usr/bin/chromium-browser"),
        Path.home() / "snap" / "chromium" / "common" / "chromium",
    ],
    'Brave': [
        Path.home() / ".config" / "BraveSoftware" / "Brave-Browser",
        Path("/usr/bin/brave-browser"),
        Path("/usr/bin/brave"),
    ],
    'Edge': [
        Path.home() / ".config" / "microsoft-edge",
        Path("/usr/bin/microsoft-edge"),
    ],
    'Opera': [
        Path.home() / ".config" / "opera",
        Path("/usr/bin/opera"),
    ],
    'Vivaldi': [
        Path.home() / ".config" / "vivaldi",
        Path("/usr/bin/vivaldi"),
    ],
}

print("\n📂 Checking filesystem paths:")
for browser, paths in browser_configs.items():
    found = []
    for path in paths:
        if path.exists():
            found.append(str(path))
    
    if found:
        print(f"✅ {browser}: {', '.join(found)}")
    else:
        print(f"❌ {browser}: Not found")

# Check running processes
print("\n🔄 Checking running browser processes:")
try:
    result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
    processes = result.stdout.lower()
    
    browser_processes = {
        'Firefox': ['firefox', 'firefox-esr'],
        'Chrome': ['chrome', 'google-chrome'],
        'Chromium': ['chromium', 'chromium-browser'],
        'Brave': ['brave', 'brave-browser'],
        'Edge': ['microsoft-edge', 'msedge'],
        'Opera': ['opera'],
        'Vivaldi': ['vivaldi'],
    }
    
    for browser, keywords in browser_processes.items():
        running = any(keyword in processes for keyword in keywords)
        if running:
            print(f"✅ {browser}: RUNNING")
        else:
            print(f"❌ {browser}: Not running")
except Exception as e:
    print(f"❌ Error checking processes: {e}")

# Check which command
print("\n🔍 Checking 'which' command:")
commands = ['firefox', 'firefox-esr', 'google-chrome', 'chromium', 'chromium-browser', 
            'brave-browser', 'brave', 'microsoft-edge', 'opera', 'vivaldi']

for cmd in commands:
    try:
        result = subprocess.run(['which', cmd], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ {cmd}: {result.stdout.strip()}")
    except:
        pass

# Check history databases
print("\n📊 Checking browser history databases:")

firefox_profiles = Path.home() / ".mozilla" / "firefox"
if firefox_profiles.exists():
    for profile in firefox_profiles.glob("*.default*"):
        db = profile / "places.sqlite"
        if db.exists():
            size = db.stat().st_size / 1024 / 1024
            print(f"✅ Firefox history: {db} ({size:.2f} MB)")

chrome_paths = [
    Path.home() / ".config" / "google-chrome" / "Default" / "History",
    Path.home() / ".config" / "chromium" / "Default" / "History",
    Path.home() / ".config" / "BraveSoftware" / "Brave-Browser" / "Default" / "History",
]

for path in chrome_paths:
    if path.exists():
        size = path.stat().st_size / 1024 / 1024
        print(f"✅ {path.parent.parent.parent.name} history: {path} ({size:.2f} MB)")

print("\n" + "="*80)
print("✅ Detection complete!")
print("="*80)
