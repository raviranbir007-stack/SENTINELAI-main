"""Helper Functions"""
import os
import json
from typing import Any

class Helpers:
    @staticmethod
    def save_json(data: Any, filepath: str):
        """Save data as JSON"""
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    @staticmethod
    def load_json(filepath: str) -> Any:
        """Load JSON file"""
        with open(filepath, 'r') as f:
            return json.load(f)
