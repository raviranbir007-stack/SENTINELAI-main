import logging

import httpx

from ..config import settings

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
        if not settings.HYBRIDANALYSIS_API_KEY:
            logger.warning("Hybrid Analysis API key not configured")
            return {"error": "Hybrid Analysis API key not configured"}

        try:
            headers = {
                "api-key": settings.HYBRIDANALYSIS_API_KEY,
                "user-agent": "Hybrid Analysis",
                "Accept": "application/json",
            }
            params = {"hash": file_hash}

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{HybridAnalysisService.BASE_URL}/search/hash",
                    headers=headers,
                    params=params,
                    follow_redirects=True,
                )

                if response.status_code == 200:
                    return response.json()
                else:
                    return {
                        "error": f"Hybrid Analysis API error: {response.status_code}"
                    }

        except httpx.TimeoutException:
            logger.warning(f"Hybrid Analysis timeout for hash {file_hash}")
            return {"error": "Hybrid Analysis API timeout"}
        except Exception as e:
            logger.error(f"Hybrid Analysis error for hash {file_hash}: {str(e)}")
            return {"error": str(e)}
