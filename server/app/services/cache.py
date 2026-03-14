from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any, Dict, Optional, Tuple

import json

try:
    import redis
except Exception:  # pragma: no cover - optional dependency
    redis = None

from ..config import settings

_cache_store: Dict[str, Tuple[float, Any]] = {}
_rate_limits: Dict[str, deque] = defaultdict(deque)
_redis_client = None

# -----------------------------------------------------------------------
# Per-service rate limits (requests per 60-second window)
# These reflect real free-tier provider limits so we don't burn quota.
#   VirusTotal  : 4 req/min, 500/day  (free tier)
#   Shodan      : 1 req/sec but monitor daily cap – be conservative
#   AbuseIPDB   : 1000 req/day  (~16/min burst ok, keep modest)
#   URLScan     : 3000 scans/day  (~50/min – keep modest)
#   HybridAnalysis: 200 req/month (~0.005/min – very conservative)
# -----------------------------------------------------------------------
_PER_SERVICE_LIMITS: Dict[str, int] = {
    "virustotal":      4,
    "shodan":          10,
    "abuseipdb":       20,
    "urlscan":         15,
    "hybrid_analysis": 3,
}

# Per-service cache TTLs (seconds).  Longer TTLs reduce repeat API calls.
_PER_SERVICE_TTL: Dict[str, int] = {
    "virustotal":      1800,   # 30 min – VT results rarely change quickly
    "shodan":          3600,   # 60 min
    "abuseipdb":       600,    # 10 min
    "urlscan":         900,    # 15 min
    "hybrid_analysis": 3600,   # 60 min
}


def _get_redis_client():
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    if not redis:
        return None
    try:
        _redis_client = redis.Redis.from_url(settings.REDIS_URL, socket_timeout=2)
        # Ping once to validate connectivity
        _redis_client.ping()
        return _redis_client
    except Exception:
        _redis_client = None
        return None


def get_cached(key: str) -> Optional[Any]:
    """Return cached value if not expired."""
    client = _get_redis_client()
    if client:
        try:
            cached = client.get(key)
            if cached is None:
                return None
            return json.loads(cached)
        except Exception:
            pass

    entry = _cache_store.get(key)
    if not entry:
        return None
    expires_at, value = entry
    if time.time() > expires_at:
        _cache_store.pop(key, None)
        return None
    return value


def set_cached(key: str, value: Any, ttl: Optional[int] = None, service: Optional[str] = None) -> None:
    """Store value with TTL (seconds). Uses per-service TTL when available."""
    if ttl is None:
        ttl = _PER_SERVICE_TTL.get(service or "", settings.API_CACHE_TTL)
    client = _get_redis_client()
    if client:
        try:
            client.setex(key, ttl, json.dumps(value))
            return
        except Exception:
            pass
    _cache_store[key] = (time.time() + ttl, value)


def rate_limit_allow(service: str, limit_per_minute: Optional[int] = None) -> bool:
    """Per-service rate limiter (sliding 60-second window).

    Uses explicit ``limit_per_minute`` when provided, then the per-service
    table, then the global setting as a fallback.
    """
    if limit_per_minute is None:
        limit_per_minute = _PER_SERVICE_LIMITS.get(service, settings.RATE_LIMIT_PER_MINUTE)
    window = 60
    now = time.time()
    q = _rate_limits[service]

    while q and now - q[0] > window:
        q.popleft()

    if len(q) >= limit_per_minute:
        return False

    q.append(now)
    return True
