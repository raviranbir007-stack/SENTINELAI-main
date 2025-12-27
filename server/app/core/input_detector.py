"""
Input Type Detection Module
Identifies whether input is IP, URL, domain, file, or hash
"""

import ipaddress
import re
from enum import Enum
from typing import Tuple
from urllib.parse import urlparse


class InputType(str, Enum):
    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    FILE_HASH = "file_hash"
    FILE = "file"
    UNKNOWN = "unknown"


class InputDetector:
    """Detects and validates input type"""

    # Regex patterns
    IPV4_PATTERN = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )

    IPV6_PATTERN = re.compile(
        r"^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
        r"([0-9a-fA-F]{1,4}:){1,7}:|"
        r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
        r"([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
        r"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
        r"([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
        r"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
        r"[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
        r":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
        r"fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
        r"::(ffff(:0{1,4}){0,1}:){0,1}"
        r"((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
        r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|"
        r"([0-9a-fA-F]{1,4}:){1,4}:"
        r"((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
        r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"
    )

    # Hash patterns
    MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
    SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
    SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

    # URL pattern
    URL_PATTERN = re.compile(
        r"^https?://"
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"
        r"localhost|"
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        r"(?::\d+)?"
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE,
    )

    # Domain pattern (without protocol)
    DOMAIN_PATTERN = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
        r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
        r"\.(?:[a-zA-Z]{2,})$"
    )

    @staticmethod
    def is_ipv4(value: str) -> bool:
        """Check if value is valid IPv4 address"""
        return bool(InputDetector.IPV4_PATTERN.match(value))

    @staticmethod
    def is_ipv6(value: str) -> bool:
        """Check if value is valid IPv6 address"""
        return bool(InputDetector.IPV6_PATTERN.match(value))

    @staticmethod
    def is_ip(value: str) -> bool:
        """Check if value is valid IP address"""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_hash(value: str) -> bool:
        """Check if value is a valid file hash"""
        value = value.strip().lower()
        return bool(
            InputDetector.MD5_PATTERN.match(value)
            or InputDetector.SHA1_PATTERN.match(value)
            or InputDetector.SHA256_PATTERN.match(value)
        )

    @staticmethod
    def get_hash_type(value: str) -> str:
        """Determine the type of hash"""
        value = value.strip().lower()
        if InputDetector.MD5_PATTERN.match(value):
            return "md5"
        elif InputDetector.SHA1_PATTERN.match(value):
            return "sha1"
        elif InputDetector.SHA256_PATTERN.match(value):
            return "sha256"
        return "unknown"

    @staticmethod
    def is_url(value: str) -> bool:
        """Check if value is a valid URL"""
        return bool(InputDetector.URL_PATTERN.match(value))

    @staticmethod
    def is_domain(value: str) -> bool:
        """Check if value is a valid domain"""
        value = value.strip().lower()
        if value.startswith("http://") or value.startswith("https://"):
            return False
        return bool(InputDetector.DOMAIN_PATTERN.match(value))

    @staticmethod
    def detect(value: str) -> Tuple[InputType, dict]:
        """
        Detect input type and return metadata

        Returns:
            Tuple of (InputType, metadata_dict)
        """
        value = value.strip()

        # Check IP (IPv4 or IPv6)
        if InputDetector.is_ip(value):
            ip_version = "IPv6" if InputDetector.is_ipv6(value) else "IPv4"
            return InputType.IP, {"ip_version": ip_version, "value": value}

        # Check URL
        if InputDetector.is_url(value):
            parsed = urlparse(value)
            return InputType.URL, {
                "scheme": parsed.scheme,
                "netloc": parsed.netloc,
                "path": parsed.path,
                "value": value,
            }

        # Check file hash
        if InputDetector.is_hash(value):
            hash_type = InputDetector.get_hash_type(value)
            return InputType.FILE_HASH, {"hash_type": hash_type, "value": value}

        # Check domain
        if InputDetector.is_domain(value):
            return InputType.DOMAIN, {"value": value}

        # Unknown type
        return InputType.UNKNOWN, {"value": value}

    @staticmethod
    def extract_domain_from_url(url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc or url
        except Exception:
            return url

    @staticmethod
    def extract_ip_from_url(url: str) -> str:
        """Extract IP from URL if present"""
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.split(":")[0]  # Remove port
            if InputDetector.is_ip(netloc):
                return netloc
            return ""
        except Exception:
            return ""
