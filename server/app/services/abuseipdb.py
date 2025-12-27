import logging

import httpx

from ..config import settings

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
        if not settings.ABUSEIPDB_API_KEY:
            logger.warning("AbuseIPDB API key not configured")
            return {"error": "AbuseIPDB API key not configured"}

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
                    return response.json()
                else:
                    return {"error": f"AbuseIPDB API error: {response.status_code}"}

        except httpx.TimeoutException:
            logger.warning(f"AbuseIPDB timeout for {ip_address}")
            return {"error": "AbuseIPDB API timeout"}
        except Exception as e:
            logger.error(f"AbuseIPDB error for {ip_address}: {str(e)}")
            return {"error": str(e)}
