"""System Information Module"""
import platform
import psutil
from typing import Dict

class SystemInfo:
    @staticmethod
    def get_system_info() -> Dict:
        """Get system information"""
        return {
            "os": platform.system(),
            "os_version": platform.release(),
            "processor": platform.processor(),
            "cpu_count": psutil.cpu_count(),
            "memory_total": psutil.virtual_memory().total,
            "memory_available": psutil.virtual_memory().available
        }
