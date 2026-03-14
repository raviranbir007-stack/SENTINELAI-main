import asyncio
import logging

import httpx

from ..config import settings
from .cache import get_cached, rate_limit_allow, set_cached

logger = logging.getLogger(__name__)


class HybridAnalysisService:
    BASE_URL = "https://www.hybrid-analysis.com/api/v2"

    @staticmethod
    async def search_hash(file_hash: str):
        """
        Search file hash on Hybrid Analysis

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            Dict with Hybrid Analysis results
        """
        logger.debug(f"HybridAnalysis.search_hash called for {file_hash}")
        if not settings.HYBRIDANALYSIS_API_KEY:
            logger.warning("Hybrid Analysis API key not configured")
            return {"error": "Hybrid Analysis API key not configured"}

        cache_key = f"hybrid:hash:{file_hash}"
        cached = get_cached(cache_key)
        if cached:
            return cached

        if not rate_limit_allow("hybrid_analysis"):
            return {"error": "Hybrid Analysis rate limit reached"}

        headers = {
            "api-key": settings.HYBRIDANALYSIS_API_KEY,
            "user-agent": "Hybrid Analysis",
            "Accept": "application/json",
        }
        params = {"hash": file_hash}

        for attempt in range(2):
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.get(
                        f"{HybridAnalysisService.BASE_URL}/search/hash",
                        headers=headers,
                        params=params,
                        follow_redirects=True,
                    )

                    if response.status_code == 200:
                        logger.debug(f"HybridAnalysis result returned for {file_hash}")
                        data = response.json()
                        # Hybrid Analysis returns a raw JSON array for hash searches;
                        # normalise to a dict so all callers can safely use .get().
                        if isinstance(data, list):
                            data = {"results": data}
                        set_cached(cache_key, data, service="hybrid_analysis")
                        return data
                    elif response.status_code == 404:
                        # Hash not present in Hybrid Analysis corpus is a valid
                        # lookup outcome, not an integration failure.
                        data = {
                            "results": [],
                            "count": 0,
                            "status": "not_found",
                            "message": "No Hybrid Analysis record for this hash",
                        }
                        set_cached(cache_key, data, service="hybrid_analysis")
                        return data
                    elif response.status_code == 429:
                        logger.warning(f"Hybrid Analysis rate limit hit for {file_hash}")
                        return {"error": "Hybrid Analysis rate limit reached (429)"}
                    else:
                        logger.warning(
                            f"Hybrid Analysis API error: {response.status_code} for {file_hash}"
                        )
                        return {
                            "error": f"Hybrid Analysis API error: {response.status_code}"
                        }

            except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError) as e:
                if attempt == 0:
                    await asyncio.sleep(1.0)
                    continue
                err_text = str(e).strip() or f"{type(e).__name__}: {e!r}"
                logger.warning(f"Hybrid Analysis transient failure for hash {file_hash}: {err_text}")
                return {"error": f"Hybrid Analysis API transient failure: {err_text}"}
            except Exception as e:
                err_text = str(e).strip() or f"{type(e).__name__}: {e!r}"
                logger.error(f"Hybrid Analysis error for hash {file_hash}: {err_text}")
                return {"error": err_text}

        return {"error": "Hybrid Analysis lookup failed"}
