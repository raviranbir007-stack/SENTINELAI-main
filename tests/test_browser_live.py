#!/usr/bin/env python3
"""
Test browser detection in real-time
"""
import sqlite3
import shutil
import os
from pathlib import Path
from datetime import datetime

# Browser paths
firefox_paths = [
    Path.home() / ".mozilla" / "firefox",
]

chrome_based = {
    'Chrome': Path.home() / ".config" / "google-chrome" / "Default" / "History",
    'Chromium': Path.home() / ".config" / "chromium" / "Default" / "History",
    'Brave': Path.home() / ".config" / "BraveSoftware" / "Brave-Browser" / "Default" / "History",
}

print("="*80)
print("🔍 BROWSER DETECTION TEST")
print("="*80)

# Test Firefox
for firefox_path in firefox_paths:
    if not firefox_path.exists():
        print(f"❌ Firefox not found: {firefox_path}")
        continue
    
    print(f"\n✅ Firefox found: {firefox_path}")
    
    for profile_dir in firefox_path.glob("*.default*"):
        history_db = profile_dir / "places.sqlite"
        if not history_db.exists():
            continue
        
        print(f"   📂 Profile: {profile_dir.name}")
        print(f"   📁 Database: {history_db}")
        
        temp_db = Path(f"/tmp/test_firefox_{os.getpid()}.db")
        try:
            shutil.copy2(history_db, temp_db)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Get last 10 visits
            cursor.execute('''
                SELECT url, title, datetime(last_visit_date/1000000, 'unixepoch', 'localtime')
                FROM moz_places
                WHERE last_visit_date > (strftime('%s', 'now', '-300 seconds') * 1000000)
                AND url NOT LIKE 'about:%'
                AND url NOT LIKE 'moz-extension:%'
                AND (url LIKE 'http://%' OR url LIKE 'https://%')
                ORDER BY last_visit_date DESC
                LIMIT 10
            ''')
            
            results = cursor.fetchall()
            if results:
                print(f"\n   🌐 Last {len(results)} visits (last 5 minutes):")
                for url, title, visit_time in results:
                    print(f"      • {visit_time} - {url[:60]}")
            else:
                print("   ⚠️  No visits in last 5 minutes")
            
            conn.close()
            temp_db.unlink()
        except Exception as e:
            print(f"   ❌ Error: {e}")
            if temp_db.exists():
                temp_db.unlink()

# Test Chrome-based browsers
for browser_name, chrome_db in chrome_based.items():
    if not chrome_db.exists():
        print(f"\n❌ {browser_name} not found: {chrome_db}")
        continue
    
    print(f"\n✅ {browser_name} found: {chrome_db}")
    
    temp_db = Path(f"/tmp/test_{browser_name.lower()}_{os.getpid()}.db")
    try:
        shutil.copy2(chrome_db, temp_db)
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        # Get last 10 visits
        cursor.execute('''
            SELECT url, title, datetime((last_visit_time/1000000)-11644473600, 'unixepoch', 'localtime')
            FROM urls
            WHERE last_visit_time > ((strftime('%s', 'now', '-300 seconds') + 11644473600) * 1000000)
            AND url NOT LIKE 'chrome:%'
            AND url NOT LIKE 'chrome-extension:%'
            AND (url LIKE 'http://%' OR url LIKE 'https://%')
            ORDER BY last_visit_time DESC
            LIMIT 10
        ''')
        
        results = cursor.fetchall()
        if results:
            print(f"   🌐 Last {len(results)} visits (last 5 minutes):")
            for url, title, visit_time in results:
                print(f"      • {visit_time} - {url[:60]}")
        else:
            print("   ⚠️  No visits in last 5 minutes")
        
        conn.close()
        temp_db.unlink()
    except Exception as e:
        print(f"   ❌ Error: {e}")
        if temp_db.exists():
            temp_db.unlink()

print("\n" + "="*80)
print("✅ Test complete!")
print("="*80)
