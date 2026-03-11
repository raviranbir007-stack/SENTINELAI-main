#!/usr/bin/env python3
"""Test browser history detection"""

import sqlite3
from pathlib import Path
from datetime import datetime

print("🔍 Testing Browser History Detection\n")

# Check Firefox
firefox_paths = [
    Path.home() / ".mozilla" / "firefox",
    Path.home() / "snap" / "firefox" / "common" / ".mozilla" / "firefox"
]

print("📂 Firefox:")
for firefox_path in firefox_paths:
    if firefox_path.exists():
        print(f"   ✅ Found: {firefox_path}")
        for profile_dir in firefox_path.glob("*.default*"):
            history_db = profile_dir / "places.sqlite"
            if history_db.exists():
                print(f"   ✅ History DB: {history_db}")
                try:
                    conn = sqlite3.connect(history_db)
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT url, title, datetime(last_visit_date/1000000, 'unixepoch', 'localtime')
                        FROM moz_places
                        WHERE last_visit_date > (strftime('%s', 'now', '-300 seconds') * 1000000)
                        AND url NOT LIKE 'about:%'
                        ORDER BY last_visit_date DESC
                        LIMIT 5
                    ''')
                    rows = cursor.fetchall()
                    print(f"   📊 Recent visits (last 5 mins): {len(rows)}")
                    for url, title, time in rows:
                        print(f"      • {url[:50]}... at {time}")
                    conn.close()
                except Exception as e:
                    print(f"   ❌ Error: {e}")
    else:
        print(f"   ❌ Not found: {firefox_path}")

print("\n📂 Chrome/Chromium:")
chrome_paths = [
    Path.home() / ".config" / "google-chrome" / "Default" / "History",
    Path.home() / ".config" / "chromium" / "Default" / "History",
]

for chrome_db in chrome_paths:
    if chrome_db.exists():
        print(f"   ✅ Found: {chrome_db}")
        try:
            import shutil
            temp_db = "/tmp/test_chrome_history.db"
            shutil.copy2(chrome_db, temp_db)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT url, title, datetime((last_visit_time/1000000)-11644473600, 'unixepoch', 'localtime')
                FROM urls
                WHERE last_visit_time > ((strftime('%s', 'now', '-300 seconds') + 11644473600) * 1000000)
                AND url NOT LIKE 'chrome:%'
                ORDER BY last_visit_time DESC
                LIMIT 5
            ''')
            rows = cursor.fetchall()
            print(f"   📊 Recent visits (last 5 mins): {len(rows)}")
            for url, title, time in rows:
                print(f"      • {url[:50]}... at {time}")
            conn.close()
            Path(temp_db).unlink()
        except Exception as e:
            print(f"   ❌ Error: {e}")
    else:
        print(f"   ❌ Not found: {chrome_db}")

print("\n✅ Test complete!")
