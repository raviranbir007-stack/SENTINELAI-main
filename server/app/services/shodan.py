import logging

import httpx

from ..config import settings
from .cache import get_cached, rate_limit_allow, set_cached

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
        logger.debug(f"Shodan.search_ip called for {ip_address}")
        if not settings.SHODAN_API_KEY:
            logger.warning("Shodan API key not configured")
            return {"error": "Shodan API key not configured"}

        cache_key = f"shodan:ip:{ip_address}"
        cached = get_cached(cache_key)
        if cached:
            return cached

        if not rate_limit_allow("shodan"):
            return {"error": "Shodan rate limit reached"}

        try:
            params = {"key": settings.SHODAN_API_KEY}
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{ShodanService.BASE_URL}/shodan/host/{ip_address}",
                    params=params,
                    follow_redirects=True,
                )

                if response.status_code == 200:
                    logger.debug(f"Shodan search successful for {ip_address}")
                    result = response.json()
                    set_cached(cache_key, result, service="shodan")
                    # Ensure we always return a dict with consistent format
                    if isinstance(result, dict):
                        return result
                    return {"error": "Invalid response format from Shodan"}

                if response.status_code in (401, 403):
                    logger.warning(f"Shodan authorization failed ({response.status_code}) for {ip_address}")
                    return {"error": f"Shodan authorization failed ({response.status_code})"}

                if response.status_code == 429:
                    logger.warning(f"Shodan rate limit reached for {ip_address}")
                    return {"error": "Shodan rate limit reached"}

                logger.warning(f"Shodan API error {response.status_code} for {ip_address}")
                return {"error": f"Shodan API error: {response.status_code}"}

        except httpx.TimeoutException:
            logger.warning(f"Shodan timeout for {ip_address}")
            return {"error": "Shodan API timeout"}
        except Exception as e:
            logger.error(f"Shodan error for {ip_address}: {str(e)}")
            return {"error": str(e)}
