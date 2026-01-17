"""File Scanner Module"""
import os
import hashlib
from typing import Dict

class FileScanner:
    @staticmethod
    def calculate_hash(filepath: str) -> str:
        """Calculate file hash"""
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    @staticmethod
    def scan_file(filepath: str) -> Dict:
        """Scan file for threats"""
        return {
            "filepath": filepath,
            "hash": FileScanner.calculate_hash(filepath),
            "size": os.path.getsize(filepath)
        }
