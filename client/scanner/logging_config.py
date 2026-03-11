"""
Unified Logging Configuration for SENTINEL-AI Client
Ensures consistent, clean logging across all modules
"""

import logging
import sys
from pathlib import Path

# Log file paths
CLIENT_LOG = Path("sentinel_client.log")
ACTIVITY_LOG = Path("activity.log")


def configure_module_logger(name: str, log_file: Path = CLIENT_LOG, 
                           console_level: int = logging.ERROR,
                           file_level: int = logging.WARNING) -> logging.Logger:
    """
    Configure a logger for a module with minimal console output
    
    Args:
        name: Logger name (usually __name__)
        log_file: File to write logs to
        console_level: Minimum level for console output (ERROR or CRITICAL only)
        file_level: Minimum level for file output (WARNING+)
    
    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)  # Capture everything internally
    
    # Remove existing handlers to avoid duplicates
    logger.handlers = []
    
    # File handler - captures all warnings and above
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(file_level)
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Console handler - ONLY errors and critical
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(console_level)
    console_formatter = logging.Formatter("%(message)s")
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    return logger


def configure_root_logger():
    """Configure the root logger"""
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.WARNING)
    
    # Remove console handler from root to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    return root_logger
