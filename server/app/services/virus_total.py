import logging

import httpx

from ..config import settings
from .cache import get_cached, rate_limit_allow, set_cached

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
        logger.debug(f"VirusTotal.scan_file called for {file_hash}")
        if not settings.VIRUSTOTAL_API_KEY:
            logger.warning("VirusTotal API key not configured")
            return {"error": "VirusTotal API key not configured"}

        cache_key = f"virustotal:file:{file_hash}"
        cached = get_cached(cache_key)
        if cached:
            return cached

        if not rate_limit_allow("virustotal"):
            return {"error": "VirusTotal rate limit reached"}

        try:
            headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{VirusTotalService.BASE_URL}/files/{file_hash}",
                    headers=headers,
                    follow_redirects=True,
                )

                if response.status_code == 200:
                    data = response.json()
                    logger.debug(f"VirusTotal.scan_file success for {file_hash}")
                    set_cached(cache_key, data)
                    return data
                elif response.status_code == 404:
                    data = {
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
                    set_cached(cache_key, data)
                    return data
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
        Scan URL on VirusTotal and retrieve analysis results

        Args:
            url: URL to scan

        Returns:
            Dict with VirusTotal results
        """
        logger.debug(f"VirusTotal.scan_url called for {url}")
        if not settings.VIRUSTOTAL_API_KEY:
            logger.warning("VirusTotal API key not configured")
            return {"error": "VirusTotal API key not configured"}

        cache_key = f"virustotal:url:{url}"
        cached = get_cached(cache_key)
        if cached:
            return cached

        if not rate_limit_allow("virustotal"):
            return {"error": "VirusTotal rate limit reached"}

        try:
            headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
            
            # Keep URL scans responsive for live monitoring workflows.
            async with httpx.AsyncClient(timeout=20.0) as client:
                # First, submit the URL for scanning
                data = {"url": url}
                response = await client.post(
                    f"{VirusTotalService.BASE_URL}/urls",
                    headers=headers,
                    data=data,
                    follow_redirects=True,
                )

                if response.status_code == 200:
                    result = response.json()
                    logger.debug(f"VirusTotal.scan_url submitted {url}")
                    
                    # Get the analysis ID to retrieve results
                    analysis_id = result.get("data", {}).get("id")
                    
                    if analysis_id:
                        # Minimal delay to let backend register the submission.
                        import asyncio
                        await asyncio.sleep(0.5)
                        
                        # Retrieve the analysis results
                        analysis_response = await client.get(
                            f"{VirusTotalService.BASE_URL}/analyses/{analysis_id}",
                            headers=headers,
                            follow_redirects=True,
                        )
                        
                        if analysis_response.status_code == 200:
                            analysis_data = analysis_response.json()
                            
                            # Check if analysis is complete
                            status = analysis_data.get("data", {}).get("attributes", {}).get("status")
                            
                            if status == "completed":
                                logger.info(f"VirusTotal.analysis completed for {url}")
                                set_cached(cache_key, analysis_data)
                                return analysis_data
                            else:
                                # If not complete, try to get URL object directly
                                logger.debug(f"Analysis status: {status}, fetching URL object")
                        
                        # Try to get URL object for immediate results
                        import base64
                        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                        
                        url_response = await client.get(
                            f"{VirusTotalService.BASE_URL}/urls/{url_id}",
                            headers=headers,
                            follow_redirects=True,
                        )
                        
                        if url_response.status_code == 200:
                            logger.info(f"VirusTotal.url object retrieved for {url}")
                            data = url_response.json()
                            set_cached(cache_key, data)
                            return data
                    
                    set_cached(cache_key, result)
                    return result
                else:
                    logger.warning(f"VirusTotal scan error: {response.status_code} - {response.text}")
                    return {"error": f"VirusTotal scan error: {response.status_code}"}

        except httpx.TimeoutException:
            logger.warning(f"VirusTotal timeout for URL {url}")
            return {"error": "VirusTotal API timeout"}
        except Exception as e:
            logger.error(f"VirusTotal error for URL {url}: {str(e)}")
            return {"error": str(e)}
