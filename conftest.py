# Root pytest configuration: ignore large standalone test scripts
collect_ignore = [
    "server/test_api_all.py",
    "server/test_cors.py",
    "server/test_threat_detection.py",
]
