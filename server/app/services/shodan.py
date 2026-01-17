import logging

import httpx

from ..config import settings

logger = logging.getLogger(__name__)


class ShodanService:
    BASE_URL = "https://api.shodan.io"

    @staticmethod
    async def search_ip(ip_address: str):
        """
        Search IP on Shodan for exposed services and vulnerabilities

        Args:
            ip_address: IP address to search

        Returns:
            Dict with Shodan results or error
        """
        if not settings.SHODAN_API_KEY:
            logger.warning("Shodan API key not configured")
            return {"error": "Shodan API key not configured"}

        try:
            params = {"key": settings.SHODAN_API_KEY}
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{ShodanService.BASE_URL}/shodan/host/{ip_address}",
                    params=params,
                    follow_redirects=True,
                )

                result = response.json() if response.status_code == 200 else {}

                # Ensure we always return a dict with consistent format
                if isinstance(result, dict):
                    return result
                return {"error": "Invalid response format from Shodan"}

        except httpx.TimeoutException:
            logger.warning(f"Shodan timeout for {ip_address}")
            return {"error": "Shodan API timeout"}
        except Exception as e:
            logger.error(f"Shodan error for {ip_address}: {str(e)}")
            return {"error": str(e)}
