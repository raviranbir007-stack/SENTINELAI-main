"""Process Scanner Module"""
import psutil
from typing import List, Dict

class ProcessScanner:
    @staticmethod
    def get_running_processes() -> List[Dict]:
        """Get list of running processes"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
            try:
                processes.append({
                    "pid": proc.info['pid'],
                    "name": proc.info['name'],
                    "memory": proc.info['memory_percent']
                })
            except:
                pass
        return processes
