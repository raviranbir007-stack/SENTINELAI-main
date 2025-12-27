import logging

import httpx

from ..config import settings

logger = logging.getLogger(__name__)


class URLScanService:
    BASE_URL = "https://urlscan.io/api/v1"

    @staticmethod
    async def scan_url(url: str):
        """
        Scan URL on URLScan for security threats

        Args:
            url: URL to scan

        Returns:
            Dict with URLScan results
        """
        if not settings.URLSCAN_API_KEY:
            logger.warning("URLScan API key not configured")
            return {"error": "URLScan API key not configured"}

        try:
            headers = {
                "API-Key": settings.URLSCAN_API_KEY,
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
                    return response.json()
                else:
                    return {"error": f"URLScan API error: {response.status_code}"}

        except httpx.TimeoutException:
            logger.warning(f"URLScan timeout for {url}")
            return {"error": "URLScan API timeout"}
        except Exception as e:
            logger.error(f"URLScan error for {url}: {str(e)}")
            return {"error": str(e)}
