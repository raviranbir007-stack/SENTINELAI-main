#!/usr/bin/env python3
"""Inspect scan_history DB to understand scan sources."""
import sqlite3
import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent

# Resolve database path without importing server modules.
# Priority:
# 1) SENTINEL_DB_PATH env var
# 2) common project DB locations (root/test.db, server/sentinel_ai.db)
env_db = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else None
if env_db:
    db_url = str(env_db)
else:
    candidates = [
        PROJECT_ROOT / "test.db",
        PROJECT_ROOT / "server" / "sentinel_ai.db",
        PROJECT_ROOT / "server" / "test.db",
    ]
    found = next((p for p in candidates if p.exists()), candidates[0])
    db_url = str(found)

print(f'DB path: {db_url}')
if not pathlib.Path(db_url).exists():
    print('DB does not exist yet.')
    sys.exit(0)

conn = sqlite3.connect(db_url)
cur = conn.cursor()

cur.execute('SELECT COUNT(*) FROM scan_history')
total = cur.fetchone()[0]
print(f'\nTotal records in scan_history: {total}')

cur.execute('SELECT scan_source, COUNT(*) FROM scan_history GROUP BY scan_source ORDER BY 2 DESC')
print('\nBy scan_source:')
for row in cur.fetchall():
    print(f'  {repr(row[0])}: {row[1]}')

cur.execute("SELECT SUBSTR(scan_id,1,6), COUNT(*) FROM scan_history GROUP BY SUBSTR(scan_id,1,6) ORDER BY 2 DESC")
print('\nBy scan_id prefix (first 6 chars):')
for row in cur.fetchall():
    print(f'  {repr(row[0])}: {row[1]}')

cur.execute('SELECT scan_id, target_type, target, scan_source, scan_timestamp FROM scan_history ORDER BY scan_timestamp DESC LIMIT 15')
print('\nLast 15 scans:')
for row in cur.fetchall():
    print(f'  src={row[3]}  type={row[1]}  target={str(row[2])[:40]}  ts={row[4]}')

cur.execute("SELECT DATE(scan_timestamp), COUNT(*) FROM scan_history GROUP BY DATE(scan_timestamp) ORDER BY 1 DESC LIMIT 14")
print('\nBy date (last 14 days):')
for row in cur.fetchall():
    print(f'  {row[0]}: {row[1]} scans')

cur.execute("SELECT target_type, COUNT(*) FROM scan_history GROUP BY target_type ORDER BY 2 DESC")
print('\nBy target_type:')
for row in cur.fetchall():
    print(f'  {repr(row[0])}: {row[1]}')

conn.close()
print('\nDone.')
