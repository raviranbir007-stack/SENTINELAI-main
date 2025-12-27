import logging

import httpx

from ..config import settings

logger = logging.getLogger(__name__)


class VirusTotalService:
    BASE_URL = "https://www.virustotal.com/api/v3"

    @staticmethod
    async def scan_file(file_hash: str):
        """
        Get file analysis from VirusTotal by hash
        Supports MD5, SHA1, SHA256

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            Dict with VirusTotal results
        """
        if not settings.VIRUSTOTAL_API_KEY:
            logger.warning("VirusTotal API key not configured")
            return {"error": "VirusTotal API key not configured"}

        try:
            headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{VirusTotalService.BASE_URL}/files/{file_hash}",
                    headers=headers,
                    follow_redirects=True,
                )

                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 404:
                    return {
                        "data": {
                            "attributes": {
                                "last_analysis_stats": {
                                    "malicious": 0,
                                    "suspicious": 0,
                                    "undetected": 1,
                                }
                            }
                        }
                    }
                else:
                    return {"error": f"VirusTotal API error: {response.status_code}"}

        except httpx.TimeoutException:
            logger.warning(f"VirusTotal timeout for hash {file_hash}")
            return {"error": "VirusTotal API timeout"}
        except Exception as e:
            logger.error(f"VirusTotal error for hash {file_hash}: {str(e)}")
            return {"error": str(e)}

    @staticmethod
    async def scan_url(url: str):
        """
        Scan URL on VirusTotal

        Args:
            url: URL to scan

        Returns:
            Dict with VirusTotal results
        """
        if not settings.VIRUSTOTAL_API_KEY:
            logger.warning("VirusTotal API key not configured")
            return {"error": "VirusTotal API key not configured"}

        try:
            headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
            data = {"url": url}

            async with httpx.AsyncClient(timeout=30.0) as client:
                # First, try to get existing analysis
                response = await client.post(
                    f"{VirusTotalService.BASE_URL}/urls",
                    headers=headers,
                    data=data,
                    follow_redirects=True,
                )

                if response.status_code == 200:
                    return response.json()
                else:
                    return {"error": f"VirusTotal scan error: {response.status_code}"}

        except httpx.TimeoutException:
            logger.warning(f"VirusTotal timeout for URL {url}")
            return {"error": "VirusTotal API timeout"}
        except Exception as e:
            logger.error(f"VirusTotal error for URL {url}: {str(e)}")
            return {"error": str(e)}
