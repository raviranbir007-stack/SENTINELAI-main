#!/usr/bin/env python3
"""
Debug script to test browser activity monitoring
"""
import sqlite3
import shutil
import os
from pathlib import Path
from datetime import datetime

print("="*80)
print("🔍 BROWSER MONITORING DEBUG TEST")
print("="*80)

# Firefox paths
firefox_paths = [
    Path.home() / ".mozilla" / "firefox",
    Path.home() / "snap" / "firefox" / "common" / ".mozilla" / "firefox"
]

print("\n📂 Checking Firefox...")
for firefox_path in firefox_paths:
    if not firefox_path.exists():
        print(f"   ❌ Not found: {firefox_path}")
        continue
    
    print(f"   ✅ Found: {firefox_path}")
    
    for profile_dir in firefox_path.glob("*.default*"):
        history_db = profile_dir / "places.sqlite"
        if not history_db.exists():
            print(f"      ❌ No history DB in: {profile_dir.name}")
            continue
        
        print(f"      📁 Profile: {profile_dir.name}")
        print(f"      📊 Database: {history_db}")
        
        temp_db = Path(f"/tmp/test_firefox_debug_{os.getpid()}.db")
        try:
            shutil.copy2(history_db, temp_db)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Test: Get ALL visits (no time filter)
            cursor.execute('''
                SELECT COUNT(*) FROM moz_places
                WHERE url LIKE 'http://%' OR url LIKE 'https://%'
            ''')
            total_count = cursor.fetchone()[0]
            print(f"      📈 Total HTTP/HTTPS URLs in database: {total_count}")
            
            # Test: Last 10 visits
            cursor.execute('''
                SELECT url, title, datetime(last_visit_date/1000000, 'unixepoch', 'localtime'),
                       last_visit_date
                FROM moz_places
                WHERE (url LIKE 'http://%' OR url LIKE 'https://%')
                AND last_visit_date IS NOT NULL
                ORDER BY last_visit_date DESC
                LIMIT 10
            ''')
            
            print(f"\n      🌐 Last 10 visited URLs:")
            results = cursor.fetchall()
            if results:
                for i, (url, title, visit_time, timestamp) in enumerate(results, 1):
                    print(f"         {i}. {visit_time} - {url[:60]}")
            else:
                print(f"         ⚠️  No visits found!")
            
            # Test: Last 5 minutes
            cursor.execute('''
                SELECT COUNT(*) FROM moz_places
                WHERE last_visit_date > (strftime('%s', 'now', '-300 seconds') * 1000000)
                AND (url LIKE 'http://%' OR url LIKE 'https://%')
            ''')
            recent_count = cursor.fetchone()[0]
            print(f"\n      ⏰ Visits in last 5 minutes: {recent_count}")
            
            if recent_count > 0:
                cursor.execute('''
                    SELECT url, title, datetime(last_visit_date/1000000, 'unixepoch', 'localtime')
                    FROM moz_places
                    WHERE last_visit_date > (strftime('%s', 'now', '-300 seconds') * 1000000)
                    AND url NOT LIKE 'about:%'
                    AND url NOT LIKE 'moz-extension:%'
                    AND url NOT LIKE 'file:%'
                    AND (url LIKE 'http://%' OR url LIKE 'https://%')
                    ORDER BY last_visit_date DESC
                ''')
                
                print(f"\n      🎯 Recent visits (last 5 min):")
                for url, title, visit_time in cursor.fetchall():
                    print(f"         • {visit_time} - {url[:60]}")
            
            conn.close()
            temp_db.unlink()
            
        except Exception as e:
            print(f"      ❌ Error: {e}")
            if temp_db.exists():
                try:
                    temp_db.unlink()
                except:
                    pass

print("\n" + "="*80)
print("✅ Debug test complete!")
print("\nℹ️  If 'Visits in last 5 minutes' is 0, try:")
print("   1. Visit some websites in Firefox")
print("   2. Wait 5-10 seconds")
print("   3. Run this script again")
print("="*80)
