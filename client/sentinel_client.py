# DEPRECATED: Use sentinel_client_v3.py as the main client entry point.
# This file is retained for legacy reference only.

"""
SENTINEL-AI Client
Standalone Python client for threat detection and reporting
"""

class SentinelClient:
    def __init__(self, server_url: str = "http://localhost:8000"):
        self.server_url = server_url
        self.api_base = f"{server_url}/api/v1"
    
    async def scan_file(self, filepath: str):
        """Scan a file for threats"""
        pass
    
    async def scan_url(self, url: str):
        """Scan a URL for threats"""
        pass
    
    async def get_threats(self):
        """Get all detected threats"""
        pass

if __name__ == "__main__":
    client = SentinelClient()
    print("SENTINEL-AI Client initialized")
