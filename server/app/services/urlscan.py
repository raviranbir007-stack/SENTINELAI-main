import logging

import httpx

from ..config import settings
from .cache import get_cached, rate_limit_allow, set_cached

logger = logging.getLogger(__name__)


class URLScanService:
    BASE_URL = "https://urlscan.io/api/v1"

    @staticmethod
    def _clean_api_key(raw_key: str) -> str:
        """Normalize API key values copied from env/UI with quotes or bearer prefix."""
        key = str(raw_key or "").strip().strip('"').strip("'")
        if key.lower().startswith("bearer "):
            key = key.split(" ", 1)[1].strip()
        return key

    @staticmethod
    async def search_domain(domain: str):
        """
        Query URLScan historical intelligence for a domain.

        Args:
            domain: Domain to search (e.g. example.com)

        Returns:
            Dict with URLScan search results
        """
        logger.debug(f"URLScan.search_domain called for {domain}")
        api_key = URLScanService._clean_api_key(settings.URLSCAN_API_KEY)
        if not api_key or api_key.startswith("your_") or len(api_key.strip()) < 10:
            logger.error("URLScan API key is missing, empty, or not set properly.")
            return {"error": "URLScan API key is missing, empty, or not set properly."}

        cache_key = f"urlscan:domain:{domain}"
        cached = get_cached(cache_key)
        if cached:
            return cached

        if not rate_limit_allow("urlscan"):
            return {"error": "URLScan rate limit reached"}

        try:
            headers = {"API-Key": api_key}

            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.get(
                    f"{URLScanService.BASE_URL}/search/",
                    headers=headers,
                    params={"q": f"domain:{domain}", "size": 10},
                    follow_redirects=True,
                )

                if response.status_code == 200:
                    data = response.json()
                    set_cached(cache_key, data, service="urlscan")
                    return data
                elif response.status_code in (401, 403):
                    detail = ""
                    try:
                        body = response.json()
                        if isinstance(body, dict):
                            detail = str(body.get("message") or body.get("description") or "").strip()
                    except Exception:
                        detail = (response.text or "").strip()
                    return {
                        "error": f"URLScan authorization failed ({response.status_code})"
                        + (f": {detail}" if detail else "")
                    }
                elif response.status_code == 400:
                    return {"error": "URLScan invalid domain input"}
                elif response.status_code == 429:
                    return {"error": "URLScan rate limit reached (429)"}
                else:
                    return {"error": f"URLScan API error: {response.status_code}"}

        except httpx.TimeoutException:
            logger.warning(f"URLScan timeout for domain {domain}")
            return {"error": "URLScan API timeout"}
        except Exception as e:
            logger.error(f"URLScan error for domain {domain}: {str(e)}")
            return {"error": str(e)}

    @staticmethod
    async def scan_url(url: str):
        """
        Scan URL on URLScan for security threats

        Args:
            url: URL to scan

        Returns:
            Dict with URLScan results
        """
        logger.debug(f"URLScan.scan_url called for {url}")
        api_key = URLScanService._clean_api_key(settings.URLSCAN_API_KEY)
        if not api_key or api_key.startswith("your_") or len(api_key.strip()) < 10:
            logger.error("URLScan API key is missing, empty, or not set properly.")
            return {"error": "URLScan API key is missing, empty, or not set properly."}

        cache_key = f"urlscan:url:{url}"
        cached = get_cached(cache_key)
        if cached:
            return cached

        if not rate_limit_allow("urlscan"):
            return {"error": "URLScan rate limit reached"}

        try:
            headers = {
                "API-Key": api_key,
                "Content-Type": "application/json",
            }
            data = {"url": url, "visibility": "public"}

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{URLScanService.BASE_URL}/scan/",
                    headers=headers,
                    json=data,
                    follow_redirects=True,
                )

                if response.status_code in [200, 201]:
                    logger.debug(f"URLScan scan submitted for {url}")
                    data = response.json()
                    set_cached(cache_key, data, service="urlscan")
                    return data
                elif response.status_code in (401, 403):
                    detail = ""
                    try:
                        body = response.json()
                        if isinstance(body, dict):
                            detail = str(body.get("message") or body.get("description") or "").strip()
                    except Exception:
                        detail = (response.text or "").strip()
                    return {
                        "error": f"URLScan authorization failed ({response.status_code})"
                        + (f": {detail}" if detail else "")
                    }
                elif response.status_code == 400:
                    # Handle scan prevention (rate limit, blocked domain, etc.)
                    error_data = response.json()
                    error_msg = error_data.get("description", "Scan prevented")
                    logger.warning(f"URLScan blocked scan for {url}: {error_msg}")
                    return {
                        "error": f"URLScan blocked: {error_msg}",
                        "status": "blocked",
                        "details": error_data
                    }
                elif response.status_code == 429:
                    logger.warning(f"URLScan rate limit hit for {url}")
                    return {"error": "URLScan rate limit reached (429)"}
                else:
                    return {"error": f"URLScan API error: {response.status_code}"}

        except httpx.TimeoutException:
            logger.warning(f"URLScan timeout for {url}")
            return {"error": "URLScan API timeout"}
        except Exception as e:
            logger.error(f"URLScan error for {url}: {str(e)}")
            return {"error": str(e)}

    @staticmethod
    async def get_results(uuid: str):
        """
        Get results from a previously submitted URLScan

        Args:
            uuid: Scan UUID from scan_url response

        Returns:
            Dict with scan results
        """
        cleaned_key = URLScanService._clean_api_key(settings.URLSCAN_API_KEY)
        if not cleaned_key:
            logger.warning("URLScan API key not configured")
            return {"error": "URLScan API key not configured"}

        cache_key = f"urlscan:uuid:{uuid}"
        cached = get_cached(cache_key)
        if cached:
            return cached

        if not rate_limit_allow("urlscan"):
            return {"error": "URLScan rate limit reached"}

        try:
            headers = {"API-Key": cleaned_key}

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{URLScanService.BASE_URL}/result/{uuid}/",
                    headers=headers,
                    follow_redirects=True,
                )

                if response.status_code == 200:
                    data = response.json()
                    set_cached(cache_key, data, service="urlscan")
                    return data
                elif response.status_code in (401, 403):
                    detail = ""
                    try:
                        body = response.json()
                        if isinstance(body, dict):
                            detail = str(body.get("message") or body.get("description") or "").strip()
                    except Exception:
                        detail = (response.text or "").strip()
                    return {
                        "error": f"URLScan authorization failed ({response.status_code})"
                        + (f": {detail}" if detail else "")
                    }
                elif response.status_code == 404:
                    return {"error": "Scan not found or not yet complete"}
                elif response.status_code == 429:
                    logger.warning(f"URLScan rate limit hit for UUID {uuid}")
                    return {"error": "URLScan rate limit reached (429)"}
                else:
                    return {"error": f"URLScan API error: {response.status_code}"}

        except httpx.TimeoutException:
            logger.warning(f"URLScan timeout for UUID {uuid}")
            return {"error": "URLScan API timeout"}
        except Exception as e:
            logger.error(f"URLScan error for UUID {uuid}: {str(e)}")
            return {"error": str(e)}
