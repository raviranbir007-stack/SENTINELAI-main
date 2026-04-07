import logging

import httpx

from ..config import settings
from .cache import get_cached, rate_limit_allow, set_cached

logger = logging.getLogger(__name__)


class ShodanService:
    BASE_URL = "https://api.shodan.io"

    @staticmethod
    def _clean_api_key(raw_key: str) -> str:
        """Normalize API key values copied from env/UI with quotes or bearer prefix."""
        key = str(raw_key or "").strip().strip('"').strip("'")
        if key.lower().startswith("bearer "):
            key = key.split(" ", 1)[1].strip()
        return key

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
        api_key = ShodanService._clean_api_key(settings.SHODAN_API_KEY)
        if not api_key or api_key.startswith("your_") or len(api_key.strip()) < 10:
            logger.error("Shodan API key is missing, empty, or not set properly.")
            return {"error": "Shodan API key is missing, empty, or not set properly."}

        cache_key = f"shodan:ip:{ip_address}"
        cached = get_cached(cache_key)
        if cached:
            return cached

        if not rate_limit_allow("shodan"):
            return {"error": "Shodan rate limit reached"}

        try:
            params = {"key": api_key}
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
                    provider_message = ""
                    try:
                        body = response.json()
                        if isinstance(body, dict):
                            provider_message = str(body.get("error") or "").strip()
                    except Exception:
                        provider_message = (response.text or "").strip()

                    error_text = (
                        f"Shodan authorization failed ({response.status_code}): {provider_message}"
                        if provider_message
                        else f"Shodan authorization failed ({response.status_code})"
                    )
                    logger.warning(f"{error_text} for {ip_address}")
                    return {"error": error_text}

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
