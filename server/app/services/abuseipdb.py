import logging

import httpx

from ..config import settings
from .cache import get_cached, rate_limit_allow, set_cached

logger = logging.getLogger(__name__)


class AbuseIPDBService:
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    @staticmethod
    async def check_ip(ip_address: str):
        """
        Check IP address on AbuseIPDB for abuse reports

        Args:
            ip_address: IP address to check

        Returns:
            Dict with AbuseIPDB results
        """
        logger.debug(f"AbuseIPDB.check_ip called for {ip_address}")
        if not settings.ABUSEIPDB_API_KEY:
            logger.warning("AbuseIPDB API key not configured")
            return {"error": "AbuseIPDB API key not configured"}

        cache_key = f"abuseipdb:ip:{ip_address}"
        cached = get_cached(cache_key)
        if cached:
            return cached

        if not rate_limit_allow("abuseipdb"):
            return {"error": "AbuseIPDB rate limit reached"}

        try:
            headers = {"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}
            params = {"ipAddress": ip_address, "maxAgeInDays": 90}

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{AbuseIPDBService.BASE_URL}/check",
                    headers=headers,
                    params=params,
                    follow_redirects=True,
                )

                if response.status_code == 200:
                    logger.debug(f"AbuseIPDB result received for {ip_address}")
                    data = response.json()
                    set_cached(cache_key, data)
                    return data
                else:
                    logger.warning(f"AbuseIPDB API error {response.status_code} for {ip_address}")
                    return {"error": f"AbuseIPDB API error: {response.status_code}"}

        except httpx.TimeoutException:
            logger.warning(f"AbuseIPDB timeout for {ip_address}")
            return {"error": "AbuseIPDB API timeout"}
        except Exception as e:
            logger.error(f"AbuseIPDB error for {ip_address}: {str(e)}")
            return {"error": str(e)}
