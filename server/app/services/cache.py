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


def set_cached(key: str, value: Any, ttl: Optional[int] = None) -> None:
    """Store value with TTL (seconds)."""
    ttl = ttl if ttl is not None else settings.API_CACHE_TTL
    client = _get_redis_client()
    if client:
        try:
            client.setex(key, ttl, json.dumps(value))
            return
        except Exception:
            pass
    _cache_store[key] = (time.time() + ttl, value)


def rate_limit_allow(service: str, limit_per_minute: Optional[int] = None) -> bool:
    """Basic per-service rate limiter (token bucket with 60s window)."""
    limit = limit_per_minute if limit_per_minute is not None else settings.RATE_LIMIT_PER_MINUTE
    window = 60
    now = time.time()
    q = _rate_limits[service]

    while q and now - q[0] > window:
        q.popleft()

    if len(q) >= limit:
        return False

    q.append(now)
    return True
