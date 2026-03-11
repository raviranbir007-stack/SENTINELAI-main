#!/usr/bin/env python3
"""Test Firefox database reading"""
import sqlite3
import shutil
from pathlib import Path
from datetime import datetime

# Find Firefox profile
firefox_path = Path.home() / ".mozilla" / "firefox"
profiles = list(firefox_path.glob("*.default*"))

print(f"Found {len(profiles)} Firefox profiles")

for profile in profiles:
    print(f"\nProfile: {profile.name}")
    history_db = profile / "places.sqlite"
    
    if not history_db.exists():
        print("  No places.sqlite found")
        continue
    
    # Copy to temp
    temp_db = Path("/tmp/test_firefox.db")
    shutil.copy2(history_db, temp_db)
    
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    
    # Get current time
    now = datetime.now().timestamp()
    ten_min_ago = (now - 600) * 1000000
    
    print(f"  Current time: {now}")
    print(f"  Checking for visits after: {ten_min_ago}")
    
    # Query
    cursor.execute('''
        SELECT url, title, last_visit_date, 
               datetime(last_visit_date/1000000, 'unixepoch', 'localtime')
        FROM moz_places
        WHERE last_visit_date > ?
        AND (url LIKE 'http://%' OR url LIKE 'https://%')
        ORDER BY last_visit_date DESC
        LIMIT 10
    ''', (ten_min_ago,))
    
    results = cursor.fetchall()
    print(f"  Found {len(results)} recent URLs")
    
    for url, title, timestamp, visit_time in results:
        print(f"    - {url[:60]}")
        print(f"      Title: {title}")
        print(f"      Time: {visit_time}")
    
    conn.close()
    temp_db.unlink()

print("\nTest complete!")
