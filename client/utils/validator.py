"""Input Validation Module"""
import re

class Validator:
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Validate IP address"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return re.match(pattern, ip) is not None
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Validate URL"""
        pattern = r'^https?://[\w\.-]+(\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&\'\(\)\*\+,;=.]+$'
        return re.match(pattern, url) is not None
