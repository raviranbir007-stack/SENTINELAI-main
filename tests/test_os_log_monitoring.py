#!/usr/bin/env python3
"""Simple test for OS log monitoring in ActivityLogger"""
import tempfile
import time
import os
from client.scanner.activity_logger import ActivityLogger


def main():
    # create a temporary log file with initial content
    tmp = tempfile.NamedTemporaryFile(delete=False, mode='w+')
    log_path = tmp.name
    tmp.write("startup entry\n")
    tmp.flush()
    tmp.close()

    events = []
    def callback(evt):
        events.append(evt)

    # use a temporary file-based database to persist tables across connections
    db_tmp = tempfile.NamedTemporaryFile(delete=False)
    db_path = db_tmp.name
    db_tmp.close()
    logger = ActivityLogger(db_path=db_path, callback=callback, os_log_file=log_path)
    logger.start()

    # give thread time to initialize
    time.sleep(1)

    # append new log entries
    with open(log_path, 'a') as f:
        f.write("new event 1\n")
        f.flush()

    # wait for monitor loop to execute (uses 10 second interval)
    time.sleep(12)

    logger.stop()

    print("Captured events:")
    for e in events:
        print(e)

    # cleanup
    try:
        os.unlink(log_path)
    except Exception:
        pass


if __name__ == "__main__":
    main()
