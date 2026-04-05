"""Client-side threat intelligence enrichment helpers for forensic records."""

import ipaddress
import json
import socket
import time
import urllib.request
from typing import Dict, Tuple

_INTEL_CACHE: Dict[str, Tuple[float, Dict[str, object]]] = {}
_DEFAULT_TTL_SECONDS = 3600
_DEFAULT_TIMEOUT_SECONDS = 1.5


def enrich_ip_threat_intel(
    ip_value: str,
    event_context: str = "endpoint",
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> Dict[str, object]:
    """Return ASN/org/country/context with a confidence score for an IP-like value."""
    ip = str(ip_value or "").strip()
    if not ip:
        return {}

    now = time.time()
    cached = _INTEL_CACHE.get(ip)
    if cached and now < cached[0]:
        return cached[1]

    intel: Dict[str, object] = {
        "ip": ip,
        "event_context": event_context,
        "confidence": 0.25,
        "lookup_source": "none",
    }

    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_loopback:
            intel.update(
                {
                    "country": "LOCAL",
                    "asn": "LOCALHOST",
                    "organization": socket.gethostname() or "loopback",
                    "is_private": True,
                    "is_hosting": False,
                    "is_proxy": False,
                    "confidence": 1.0,
                    "lookup_source": "local-classification",
                }
            )
            _INTEL_CACHE[ip] = (now + ttl_seconds, intel)
            return intel
        if ip_obj.is_private:
            intel.update(
                {
                    "country": "PRIVATE",
                    "asn": "RFC1918",
                    "organization": "private-network",
                    "is_private": True,
                    "is_hosting": False,
                    "is_proxy": False,
                    "confidence": 0.98,
                    "lookup_source": "local-classification",
                }
            )
            _INTEL_CACHE[ip] = (now + ttl_seconds, intel)
            return intel
    except Exception:
        _INTEL_CACHE[ip] = (now + min(300, ttl_seconds), intel)
        return intel

    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,as,org,isp,proxy,hosting,mobile,query",
            headers={"User-Agent": "SENTINEL-AI/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))

        if payload.get("status") == "success":
            asn = str(payload.get("as") or "").strip() or "UNKNOWN"
            org = str(payload.get("org") or payload.get("isp") or "UNKNOWN").strip()
            country = str(payload.get("country") or payload.get("countryCode") or "UNKNOWN").strip()
            is_proxy = bool(payload.get("proxy"))
            is_hosting = bool(payload.get("hosting"))
            score = 0.55
            if country and country != "UNKNOWN":
                score += 0.15
            if asn and asn != "UNKNOWN":
                score += 0.15
            if org and org != "UNKNOWN":
                score += 0.1
            if is_proxy or is_hosting:
                score += 0.1

            intel.update(
                {
                    "country": country,
                    "asn": asn,
                    "organization": org,
                    "is_private": False,
                    "is_hosting": is_hosting,
                    "is_proxy": is_proxy,
                    "confidence": round(min(score, 0.99), 2),
                    "lookup_source": "ip-api",
                }
            )
        else:
            intel.update(
                {
                    "country": "UNKNOWN",
                    "asn": "UNKNOWN",
                    "organization": "UNKNOWN",
                    "is_private": False,
                    "is_hosting": False,
                    "is_proxy": False,
                    "confidence": 0.35,
                    "lookup_source": "lookup-failed",
                }
            )
    except Exception:
        intel.update(
            {
                "country": "UNKNOWN",
                "asn": "UNKNOWN",
                "organization": "UNKNOWN",
                "is_private": False,
                "is_hosting": False,
                "is_proxy": False,
                "confidence": 0.35,
                "lookup_source": "lookup-failed",
            }
        )

    _INTEL_CACHE[ip] = (now + ttl_seconds, intel)
    return intel
