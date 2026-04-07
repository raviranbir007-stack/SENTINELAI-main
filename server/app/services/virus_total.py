import logging
import time

import httpx

from ..config import settings
from .cache import get_cached, rate_limit_allow, set_cached

logger = logging.getLogger(__name__)

# Temporary cool-down state when provider returns quota errors.
_VT_QUOTA_COOLDOWN_UNTIL = 0.0
_VT_QUOTA_COOLDOWN_SECONDS = 15 * 60


def _vt_in_quota_cooldown() -> bool:
    return time.time() < _VT_QUOTA_COOLDOWN_UNTIL


def _vt_start_quota_cooldown(seconds: int = _VT_QUOTA_COOLDOWN_SECONDS) -> None:
    global _VT_QUOTA_COOLDOWN_UNTIL
    _VT_QUOTA_COOLDOWN_UNTIL = max(_VT_QUOTA_COOLDOWN_UNTIL, time.time() + max(60, seconds))


class VirusTotalService:
    BASE_URL = "https://www.virustotal.com/api/v3"

    @staticmethod
    def _clean_api_key(raw_key: str) -> str:
        """Normalize API key values copied from env/UI with quotes or bearer prefix."""
        key = str(raw_key or "").strip().strip('"').strip("'")
        if key.lower().startswith("bearer "):
            key = key.split(" ", 1)[1].strip()
        return key

    @staticmethod
    async def scan_domain(domain: str):
        """
        Get domain reputation/analysis from VirusTotal.

        Args:
            domain: Domain to lookup (e.g. example.com)

        Returns:
            Dict with VirusTotal domain results
        """
        logger.debug(f"VirusTotal.scan_domain called for {domain}")
        api_key = VirusTotalService._clean_api_key(settings.VIRUSTOTAL_API_KEY)
        if not api_key or api_key.startswith("your_") or len(api_key.strip()) < 10:
            logger.error("VirusTotal API key is missing, empty, or not set properly.")
            return {"error": "VirusTotal API key is missing, empty, or not set properly."}

        cache_key = f"virustotal:domain:{domain}"
        cached = get_cached(cache_key)
        if cached:
            return cached

        if _vt_in_quota_cooldown():
            return {"error": "VirusTotal quota cooldown active; retry later"}

        if not rate_limit_allow("virustotal"):
            return {"error": "VirusTotal rate limit reached"}

        try:
            headers = {"x-apikey": api_key}
            async with httpx.AsyncClient(timeout=25.0) as client:
                response = await client.get(
                    f"{VirusTotalService.BASE_URL}/domains/{domain}",
                    headers=headers,
                    follow_redirects=True,
                )

                if response.status_code == 200:
                    data = response.json()
                    set_cached(cache_key, data, service="virustotal")
                    return data
                elif response.status_code in (401, 403):
                    detail = ""
                    try:
                        body = response.json()
                        if isinstance(body, dict):
                            detail = str(body.get("error") or body.get("message") or "").strip()
                    except Exception:
                        detail = (response.text or "").strip()
                    return {
                        "error": f"VirusTotal authorization failed ({response.status_code})"
                        + (f": {detail}" if detail else "")
                    }
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
                    set_cached(cache_key, data, service="virustotal")
                    return data
                elif response.status_code == 429:
                    _vt_start_quota_cooldown()
                    logger.warning("VirusTotal quota exceeded for domain lookup; entering cooldown")
                    return {"error": "VirusTotal quota exceeded"}
                elif response.status_code == 400:
                    return {"error": "VirusTotal invalid domain input"}
                else:
                    return {"error": f"VirusTotal API error: {response.status_code}"}
        except httpx.TimeoutException:
            logger.warning(f"VirusTotal timeout for domain {domain}")
            return {"error": "VirusTotal API timeout"}
        except Exception as e:
            logger.error(f"VirusTotal error for domain {domain}: {str(e)}")
            return {"error": str(e)}

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
        api_key = VirusTotalService._clean_api_key(settings.VIRUSTOTAL_API_KEY)
        if not api_key:
            logger.warning("VirusTotal API key not configured")
            return {"error": "VirusTotal API key not configured"}

        cache_key = f"virustotal:file:{file_hash}"
        cached = get_cached(cache_key)
        if cached:
            return cached

        if _vt_in_quota_cooldown():
            return {"error": "VirusTotal quota cooldown active; retry later"}

        if not rate_limit_allow("virustotal"):
            return {"error": "VirusTotal rate limit reached"}

        try:
            headers = {"x-apikey": api_key}
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{VirusTotalService.BASE_URL}/files/{file_hash}",
                    headers=headers,
                    follow_redirects=True,
                )

                if response.status_code == 200:
                    data = response.json()
                    logger.debug(f"VirusTotal.scan_file success for {file_hash}")
                    set_cached(cache_key, data, service="virustotal")
                    return data
                elif response.status_code in (401, 403):
                    detail = ""
                    try:
                        body = response.json()
                        if isinstance(body, dict):
                            detail = str(body.get("error") or body.get("message") or "").strip()
                    except Exception:
                        detail = (response.text or "").strip()
                    return {
                        "error": f"VirusTotal authorization failed ({response.status_code})"
                        + (f": {detail}" if detail else "")
                    }
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
                elif response.status_code == 429:
                    _vt_start_quota_cooldown()
                    logger.warning("VirusTotal quota exceeded for hash lookup; entering cooldown")
                    return {"error": "VirusTotal quota exceeded"}
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
        api_key = VirusTotalService._clean_api_key(settings.VIRUSTOTAL_API_KEY)
        if not api_key:
            logger.warning("VirusTotal API key not configured")
            return {"error": "VirusTotal API key not configured"}

        cache_key = f"virustotal:url:{url}"
        cached = get_cached(cache_key)
        if cached:
            return cached

        if _vt_in_quota_cooldown():
            return {"error": "VirusTotal quota cooldown active; retry later"}

        if not rate_limit_allow("virustotal"):
            return {"error": "VirusTotal rate limit reached"}

        try:
            headers = {"x-apikey": api_key}
            
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
                            set_cached(cache_key, data, service="virustotal")
                            return data
                    elif response.status_code in (401, 403):
                        detail = ""
                        try:
                            body = response.json()
                            if isinstance(body, dict):
                                detail = str(body.get("error") or body.get("message") or "").strip()
                        except Exception:
                            detail = (response.text or "").strip()
                        return {
                            "error": f"VirusTotal authorization failed ({response.status_code})"
                            + (f": {detail}" if detail else "")
                        }
                    
                    set_cached(cache_key, result, service="virustotal")
                    return result
                else:
                    if response.status_code == 429:
                        _vt_start_quota_cooldown()
                        logger.warning("VirusTotal quota exceeded for URL scan; entering cooldown")
                        return {"error": "VirusTotal quota exceeded"}
                    logger.warning(f"VirusTotal scan error: {response.status_code} - {response.text}")
                    return {"error": f"VirusTotal scan error: {response.status_code}"}

        except httpx.TimeoutException:
            logger.warning(f"VirusTotal timeout for URL {url}")
            return {"error": "VirusTotal API timeout"}
        except Exception as e:
            logger.error(f"VirusTotal error for URL {url}: {str(e)}")
            return {"error": str(e)}
