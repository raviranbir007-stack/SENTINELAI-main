"""Network Scanner Module"""
import socket
from typing import List, Dict

class NetworkScanner:
    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    @staticmethod
    async def scan_network(target: str) -> Dict:
        """Scan network"""
        return {
            "target": target,
            "local_ip": NetworkScanner.get_local_ip()
        }
