import logging

import httpx

from ..config import settings
from .cache import get_cached, rate_limit_allow, set_cached

logger = logging.getLogger(__name__)


class AbuseIPDBService:
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    @staticmethod
    def _clean_api_key(raw_key: str) -> str:
        """Normalize API key values copied from env/UI with quotes or bearer prefix."""
        key = str(raw_key or "").strip().strip('"').strip("'")
        if key.lower().startswith("bearer "):
            key = key.split(" ", 1)[1].strip()
        return key

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
        api_key = AbuseIPDBService._clean_api_key(settings.ABUSEIPDB_API_KEY)
        if not api_key or api_key.startswith("your_") or len(api_key.strip()) < 10:
            logger.error("AbuseIPDB API key is missing, empty, or not set properly.")
            return {"error": "AbuseIPDB API key is missing, empty, or not set properly."}

        cache_key = f"abuseipdb:ip:{ip_address}"
        cached = get_cached(cache_key)
        if cached:
            return cached

        if not rate_limit_allow("abuseipdb"):
            return {"error": "AbuseIPDB rate limit reached"}

        try:
            headers = {"Key": api_key, "Accept": "application/json"}
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
                    set_cached(cache_key, data, service="abuseipdb")
                    return data
                elif response.status_code in (401, 403):
                    detail = ""
                    try:
                        body = response.json()
                        if isinstance(body, dict):
                            detail = str(body.get("errors", [{}])[0].get("detail") if isinstance(body.get("errors"), list) and body.get("errors") else body.get("detail") or "").strip()
                    except Exception:
                        detail = (response.text or "").strip()
                    return {
                        "error": f"AbuseIPDB authorization failed ({response.status_code})"
                        + (f": {detail}" if detail else "")
                    }
                elif response.status_code == 429:
                    logger.warning(f"AbuseIPDB rate limit hit for {ip_address}")
                    return {"error": "AbuseIPDB rate limit reached (429)"}
                else:
                    logger.warning(f"AbuseIPDB API error {response.status_code} for {ip_address}")
                    return {"error": f"AbuseIPDB API error: {response.status_code}"}

        except httpx.TimeoutException:
            logger.warning(f"AbuseIPDB timeout for {ip_address}")
            return {"error": "AbuseIPDB API timeout"}
        except Exception as e:
            err_text = str(e).strip() or f"{type(e).__name__}: {e!r}"
            logger.error(f"AbuseIPDB error for {ip_address}: {err_text}")
            return {"error": err_text}
