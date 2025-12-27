#!/usr/bin/env python
"""
SENTINEL-AI Server Entry Point - Optimized for Kali Linux
Handles multi-platform execution for Linux/Unix environments
"""
import logging
import os
import sys

import uvicorn

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

from app.config import settings


def run_kali_optimized():
    """
    Run server optimized for Kali Linux
    - Enables full threat detection APIs
    - Uses 0.0.0.0 for network accessibility
    - Enables debug mode for detailed logging
    - Optimized for Kali's network scanning capabilities
    """
    logger.info("=" * 60)
    logger.info("SENTINEL-AI Server - Kali Linux Optimized Mode")
    logger.info("=" * 60)
    logger.info(f"Platform: {sys.platform}")
    logger.info(f"Python Version: {sys.version}")
    logger.info(f"Debug Mode: {settings.DEBUG}")
    logger.info(f"API URL: http://0.0.0.0:{settings.API_PORT}{settings.API_V1_PREFIX}")
    logger.info("=" * 60)
    logger.info("Features Enabled:")
    logger.info("  ✓ Threat Detection with Multi-API Integration")
    logger.info("  ✓ Network Vulnerability Scanning (Shodan)")
    logger.info("  ✓ IP Reputation Analysis (AbuseIPDB)")
    logger.info("  ✓ File Hash Analysis (VirusTotal)")
    logger.info("  ✓ URL Scanning (URLScan)")
    logger.info("  ✓ Behavioral Analysis (Hybrid Analysis)")
    logger.info("  ✓ AI-Powered Report Generation (Gemini)")
    logger.info("  ✓ PDF Report Download")
    logger.info("  ✓ Time-Range Based Threat Filtering (24h, 7d, 30d)")
    logger.info("=" * 60)
    logger.info("Available Endpoints:")
    logger.info("  POST   /api/v1/scan/ip")
    logger.info("  POST   /api/v1/scan/url")
    logger.info("  POST   /api/v1/scan/file")
    logger.info("  GET    /api/v1/threats?time_range=24h")
    logger.info("  GET    /api/v1/threats/{threat_id}")
    logger.info("  POST   /api/v1/reports/generate?threat_id=THR001")
    logger.info("  GET    /api/v1/reports/download/{report_id}")
    logger.info("  GET    /api/v1/dashboard/summary?time_range=24h")
    logger.info("  GET    /api/v1/dashboard/threats?time_range=7d")
    logger.info("=" * 60)

    # Run uvicorn server
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="info" if not settings.DEBUG else "debug",
        access_log=True,
        loop="uvloop" if sys.platform != "win32" else "asyncio",
    )


def run_development():
    """Run in development mode with auto-reload"""
    logger.info("Starting in DEVELOPMENT mode with auto-reload...")
    uvicorn.run(
        "app.main:app", host="127.0.0.1", port=8000, reload=True, log_level="debug"
    )


def run_production():
    """Run in production mode with optimized settings"""
    logger.info("Starting in PRODUCTION mode...")
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="warning",
        access_log=False,
        workers=4,
    )


if __name__ == "__main__":
    try:
        # Check environment to determine run mode
        if os.getenv("ENVIRONMENT") == "production":
            run_production()
        elif os.getenv("ENVIRONMENT") == "development":
            run_development()
        else:
            # Default to Kali-optimized mode for Unix/Linux systems
            if sys.platform in ["linux", "linux2", "darwin"]:
                run_kali_optimized()
            else:
                # Windows fallback
                logger.warning("Windows detected. Consider using run_app.py instead.")
                logger.info("Running in basic mode...")
                uvicorn.run(
                    "app.main:app", host="127.0.0.1", port=8000, reload=settings.DEBUG
                )
    except Exception as e:
        logger.error(f"[FATAL] Server failed to start: {e}", exc_info=True)
        sys.exit(1)
