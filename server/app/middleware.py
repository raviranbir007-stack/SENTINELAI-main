"""
Custom middleware implementations for SENTINEL-AI server
"""
import asyncio
import ipaddress
import json
import logging
import os
import re
import time
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Callable, Dict, Tuple

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple in-memory rate limiting middleware.
    
    Limits requests per client IP to prevent abuse.
    Configuration can be set via environment or passed at initialization.
    """

    def __init__(
        self,
        app: Callable,
        requests_per_minute: int = 4800,  # Default 80 req/sec - much higher for dashboard
        cleanup_interval: int = 300,  # Clean old IPs every 5 min
        exempt_paths: list[str] = None,
    ):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.cleanup_interval = cleanup_interval
        self.exempt_paths = exempt_paths or [
            # Dashboard core endpoints - never rate-limited
            "/api/v1/dashboard/",
            # Reports endpoint - has server-side caching (5 seconds)
            "/api/v1/reports/",
            # Advanced report generation - resource intensive, needs unlimited access
            "/api/v1/advanced-reports/",
            # Monitoring live feeds - core dashboard telemetry
            "/api/v1/monitoring/",
            # Network client communication
            "/api/v1/network/",
            # Health and diagnostics
            "/api/v1/health",
            # API docs
            "/docs",
            "/redoc",
            "/openapi.json",
            # Static files
            "/static/",
            # Single page app
            "/favicon.ico",
            "/index.html",
        ]
        
        # Rate limit tracking: {ip: [(timestamp, count), ...]}
        self.request_times = defaultdict(list)
        self.last_cleanup = time.time()
        # Per-IP log throttling state for repeated rate-limit hits.
        self._rate_limit_log_state: Dict[str, Dict[str, float]] = defaultdict(
            lambda: {"last_log_at": 0.0, "suppressed": 0.0}
        )
        self._rate_limit_log_interval = 3600.0
        # Active scanner/abuse controls.
        self._suspicious_window_seconds = int(os.getenv("SENTINEL_SUSPICIOUS_WINDOW_SECONDS", "120") or 120)
        self._suspicious_score_threshold = int(os.getenv("SENTINEL_SUSPICIOUS_SCORE_THRESHOLD", "12") or 12)
        self._temporary_block_seconds = int(os.getenv("SENTINEL_TEMP_BLOCK_SECONDS", "900") or 900)
        self._ip_suspicion_events: Dict[str, list[tuple[float, int, str, str]]] = defaultdict(list)
        self._temporarily_blocked_ips: Dict[str, float] = {}
        self._blocked_log_state: Dict[str, Dict[str, float]] = defaultdict(
            lambda: {"last_log_at": 0.0, "suppressed": 0.0}
        )
        self._blocked_log_interval = 3600.0
        self._suspicious_path_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in (
                r"/\.env($|[./])",
                r"/wp-admin",
                r"/wp-login",
                r"/xmlrpc",
                r"/phpmyadmin",
                r"/\.git",
                r"/\.svn",
                r"/cgi-bin",
                r"/shell",
                r"/actuator",
                r"/jmx-console",
                r"/manager/html",
                r"/HNAP1",
                r"/vendor/phpunit",
            )
        ]
        self._suspicious_user_agents = (
            "sqlmap", "nikto", "nmap", "masscan", "zgrab", "acunetix",
            "nessus", "openvas", "dirbuster", "gobuster", "whatweb", "wpscan",
        )
        security_log_path = os.getenv("SENTINEL_SECURITY_EVENT_LOG", "logs/security_events.log")
        self._security_event_log_path = Path(security_log_path)
        self._security_event_log_path.parent.mkdir(parents=True, exist_ok=True)
        self._threat_intel_ttl_seconds = int(os.getenv("SENTINEL_THREAT_INTEL_TTL_SECONDS", "3600") or 3600)
        self._threat_intel_timeout_seconds = float(os.getenv("SENTINEL_THREAT_INTEL_TIMEOUT_SECONDS", "1.5") or 1.5)
        self._threat_intel_cache: Dict[str, tuple[float, Dict[str, object]]] = {}
        self._security_summary_state = {
            "hour_bucket": int(time.time() // 3600),
            "counts": defaultdict(int),
            "top_paths": defaultdict(int),
            "unique_ips": set(),
            "last_flushed_bucket": None,
        }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with rate limiting."""
        
        # Root path and favicon should never be rate-limited
        if request.url.path in ("/", "/favicon.ico"):
            return await call_next(request)
        
        # Check if path is exempt
        if any(request.url.path.startswith(path) for path in self.exempt_paths):
            return await call_next(request)

        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        current_time = time.time()

        # Enforce temporary deny list for aggressive scanners.
        if self._is_temporarily_blocked(client_ip, current_time):
            self._log_temporary_block_hit(client_ip, request.url.path, current_time)
            return Response(
                content='{"detail":"Access temporarily blocked due to suspicious activity"}',
                status_code=403,
                media_type="application/json",
                headers={"Retry-After": str(self._temporary_block_seconds)},
            )

        # Register suspicious traffic signals before regular rate limiting.
        score, reason = self._calculate_suspicion_score(request)
        if score > 0:
            self._register_suspicion(client_ip, score, reason, request.url.path, current_time)
            if self._should_temporary_block(client_ip, current_time):
                block_until = current_time + self._temporary_block_seconds
                self._temporarily_blocked_ips[client_ip] = block_until
                total_score = self._current_suspicion_score(client_ip, current_time)
                logger.debug(
                    "Temporary security block applied to %s for %ss (score=%s, latest_reason=%s)",
                    client_ip,
                    self._temporary_block_seconds,
                    total_score,
                    reason,
                )
                self._note_security_summary(
                    event_type="temporary_block",
                    client_ip=client_ip,
                    path=request.url.path,
                    method=request.method,
                    details={
                        "score": total_score,
                        "reason": reason,
                        "block_seconds": self._temporary_block_seconds,
                    },
                    now=current_time,
                )
                return Response(
                    content='{"detail":"Access temporarily blocked due to suspicious activity"}',
                    status_code=403,
                    media_type="application/json",
                    headers={"Retry-After": str(self._temporary_block_seconds)},
                )

        # Cleanup old entries periodically
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries(current_time)
            self.last_cleanup = current_time

        # Check rate limit
        request_times = self.request_times[client_ip]
        
        # Remove timestamps older than 1 minute
        minute_ago = current_time - 60
        request_times[:] = [ts for ts in request_times if ts > minute_ago]

        # Check if limit exceeded
        if len(request_times) >= self.requests_per_minute:
            self._log_rate_limit_exceeded(client_ip, len(request_times), current_time)
            self._note_security_summary(
                event_type="rate_limit_exceeded",
                client_ip=client_ip,
                path=request.url.path,
                method=request.method,
                details={
                    "requests_last_minute": len(request_times),
                    "limit": self.requests_per_minute,
                },
                now=current_time,
            )
            return Response(
                content='{"detail":"Rate limit exceeded: Too many requests"}',
                status_code=429,
                media_type="application/json",
            )

        # Record this request
        request_times.append(current_time)

        # Process request
        return await call_next(request)

    def _cleanup_old_entries(self, current_time: float) -> None:
        """Remove old IP entries to prevent memory leak."""
        minute_ago = current_time - 60
        ips_to_remove = []
        
        for ip, times in self.request_times.items():
            # Keep only recent timestamps
            times[:] = [ts for ts in times if ts > minute_ago]
            # Remove IP if no recent requests
            if not times:
                ips_to_remove.append(ip)
        
        for ip in ips_to_remove:
            del self.request_times[ip]
        
        if ips_to_remove:
            logger.debug(f"Cleaned up rate limit tracking for {len(ips_to_remove)} IPs")

        # Cleanup suspicion windows and expired temporary blocks.
        for ip, events in list(self._ip_suspicion_events.items()):
            events[:] = [e for e in events if (current_time - e[0]) <= self._suspicious_window_seconds]
            if not events:
                del self._ip_suspicion_events[ip]

        for ip, unblock_at in list(self._temporarily_blocked_ips.items()):
            if current_time >= unblock_at:
                del self._temporarily_blocked_ips[ip]

    def _calculate_suspicion_score(self, request: Request) -> tuple[int, str]:
        """Calculate a lightweight suspicion score for IDS/IPS-like request filtering."""
        path = request.url.path or ""
        method = (request.method or "GET").upper()
        user_agent = (request.headers.get("user-agent") or "").strip().lower()
        query = request.url.query or ""

        score = 0
        reasons: list[str] = []

        if not user_agent:
            score += 2
            reasons.append("empty_user_agent")

        if any(marker in user_agent for marker in self._suspicious_user_agents):
            score += 4
            reasons.append("scanner_user_agent")

        if any(pattern.search(path) for pattern in self._suspicious_path_patterns):
            score += 5
            reasons.append("sensitive_probe_path")

        lower_query = query.lower()
        if any(token in lower_query for token in ("../", "..%2f", "union+select", "<script", "cmd=", "exec(")):
            score += 4
            reasons.append("injection_or_traversal_pattern")

        if method in {"PUT", "DELETE", "TRACE", "CONNECT"} and path.startswith("/api/"):
            score += 2
            reasons.append("high_risk_method")

        return score, ",".join(reasons) if reasons else "none"

    def _register_suspicion(self, client_ip: str, score: int, reason: str, path: str, now: float) -> None:
        self._ip_suspicion_events[client_ip].append((now, score, reason, path))

    def _current_suspicion_score(self, client_ip: str, now: float) -> int:
        events = self._ip_suspicion_events.get(client_ip, [])
        return sum(e[1] for e in events if (now - e[0]) <= self._suspicious_window_seconds)

    def _should_temporary_block(self, client_ip: str, now: float) -> bool:
        return self._current_suspicion_score(client_ip, now) >= self._suspicious_score_threshold

    def _is_temporarily_blocked(self, client_ip: str, now: float) -> bool:
        unblock_at = self._temporarily_blocked_ips.get(client_ip)
        if not unblock_at:
            return False
        if now >= unblock_at:
            del self._temporarily_blocked_ips[client_ip]
            return False
        return True

    def _log_temporary_block_hit(self, client_ip: str, path: str, now: float) -> None:
        """Log temporary-block hits with duplicate suppression to avoid floods."""
        state = self._blocked_log_state[client_ip]
        last_log_at = float(state.get("last_log_at", 0.0) or 0.0)
        suppressed = int(state.get("suppressed", 0) or 0)
        if (now - last_log_at) >= self._blocked_log_interval:
            state["last_log_at"] = now
            state["suppressed"] = 0
            return
        state["suppressed"] = suppressed + 1

    def _record_security_event(
        self,
        event_type: str,
        client_ip: str,
        path: str,
        method: str,
        details: Dict[str, object],
    ) -> None:
        """Persist structured forensic security events for investigations."""
        enriched_details = dict(details or {})
        threat_intel = self._enrich_ip_threat_intel(client_ip, event_type)
        if threat_intel:
            enriched_details["threat_intel"] = threat_intel

        event = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event_type": event_type,
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "details": enriched_details,
        }
        try:
            with self._security_event_log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, ensure_ascii=True) + "\n")
        except Exception:
            logger.debug("Failed to persist security event", exc_info=True)

    def _enrich_ip_threat_intel(self, client_ip: str, event_type: str) -> Dict[str, object]:
        """Return structured IP threat-intel context with confidence score."""
        if not client_ip or client_ip == "unknown":
            return {}

        now = time.time()
        cached = self._threat_intel_cache.get(client_ip)
        if cached and now < cached[0]:
            return cached[1]

        intel: Dict[str, object] = {
            "ip": client_ip,
            "event_context": event_type,
            "confidence": 0.25,
            "lookup_source": "none",
        }

        try:
            ip_obj = ipaddress.ip_address(client_ip)
            if ip_obj.is_loopback:
                intel.update({
                    "country": "LOCAL",
                    "asn": "LOCALHOST",
                    "organization": "loopback",
                    "confidence": 1.0,
                    "lookup_source": "local-classification",
                    "is_private": True,
                    "is_hosting": False,
                    "is_proxy": False,
                })
                self._threat_intel_cache[client_ip] = (now + self._threat_intel_ttl_seconds, intel)
                return intel

            if ip_obj.is_private:
                intel.update({
                    "country": "PRIVATE",
                    "asn": "RFC1918",
                    "organization": "private-network",
                    "confidence": 0.98,
                    "lookup_source": "local-classification",
                    "is_private": True,
                    "is_hosting": False,
                    "is_proxy": False,
                })
                self._threat_intel_cache[client_ip] = (now + self._threat_intel_ttl_seconds, intel)
                return intel
        except Exception:
            # Non-IP values keep fallback intel payload.
            self._threat_intel_cache[client_ip] = (now + min(300, self._threat_intel_ttl_seconds), intel)
            return intel

        try:
            req = urllib.request.Request(
                f"http://ip-api.com/json/{client_ip}?fields=status,country,countryCode,as,org,isp,proxy,hosting,mobile,query",
                headers={"User-Agent": "SENTINEL-AI/1.0"},
            )
            with urllib.request.urlopen(req, timeout=self._threat_intel_timeout_seconds) as resp:
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

                intel.update({
                    "country": country,
                    "asn": asn,
                    "organization": org,
                    "is_private": False,
                    "is_hosting": is_hosting,
                    "is_proxy": is_proxy,
                    "confidence": round(min(score, 0.99), 2),
                    "lookup_source": "ip-api",
                })
        except Exception:
            intel.update({
                "country": "UNKNOWN",
                "asn": "UNKNOWN",
                "organization": "UNKNOWN",
                "is_private": False,
                "is_hosting": False,
                "is_proxy": False,
                "confidence": 0.35,
                "lookup_source": "lookup-failed",
            })

        self._threat_intel_cache[client_ip] = (now + self._threat_intel_ttl_seconds, intel)
        return intel

    def _log_rate_limit_exceeded(self, client_ip: str, request_count: int, now: float) -> None:
        """Emit compact rate-limit warning and suppress high-frequency duplicates."""
        state = self._rate_limit_log_state[client_ip]
        last_log_at = float(state.get("last_log_at", 0.0) or 0.0)
        suppressed = int(state.get("suppressed", 0) or 0)

        if (now - last_log_at) >= self._rate_limit_log_interval:
            state["last_log_at"] = now
            state["suppressed"] = 0
            return

        state["suppressed"] = suppressed + 1

    def _note_security_summary(
        self,
        event_type: str,
        client_ip: str,
        path: str,
        method: str,
        details: Dict[str, object],
        now: float,
    ) -> None:
        """Accumulate noisy security events and flush them as a single hourly summary."""
        bucket = int(now // 3600)
        state = self._security_summary_state
        if state["hour_bucket"] != bucket:
            self._flush_security_summary(now, force=True)
            state["hour_bucket"] = bucket

        counts = state["counts"]
        counts[event_type] += 1
        state["top_paths"][path] += 1
        if client_ip and client_ip != "unknown":
            state["unique_ips"].add(client_ip)

    def _flush_security_summary(self, now: float, force: bool = False) -> None:
        state = self._security_summary_state
        counts = state["counts"]
        if not counts:
            return

        hour_bucket = int(state["hour_bucket"])
        last_flushed_bucket = state.get("last_flushed_bucket")
        if not force and last_flushed_bucket == hour_bucket:
            return

        top_paths = state["top_paths"]
        summary = {
            "hour_bucket": hour_bucket,
            "window_start": time.strftime("%Y-%m-%dT%H:00:00Z", time.gmtime(hour_bucket * 3600)),
            "window_end": time.strftime("%Y-%m-%dT%H:59:59Z", time.gmtime(hour_bucket * 3600)),
            "counts": dict(counts),
            "unique_ip_count": len(state["unique_ips"]),
            "top_paths": [
                {"path": path, "count": count}
                for path, count in sorted(top_paths.items(), key=lambda item: item[1], reverse=True)[:5]
            ],
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        }

        self._record_security_event(
            event_type="security_summary",
            client_ip="summary",
            path="/summary",
            method="SUMMARY",
            details=summary,
        )

        counts.clear()
        top_paths.clear()
        state["unique_ips"].clear()
        state["last_flushed_bucket"] = hour_bucket


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for structured request/response logging
    """

    _quiet_prefixes = (
        "/api/v1/dashboard/",
        "/api/v1/monitoring/",
        "/api/v1/threats",
        "/api/v1/network/clients",
        "/api/v1/network/client/heartbeat",
        "/static/",
    )
    _quiet_exact = {"/", "/favicon.ico", "/index.html"}

    def __init__(self, app: Callable):
        super().__init__(app)
        # Suppress repeated high-volume 4xx/5xx logs while retaining periodic visibility.
        self._error_log_state: Dict[Tuple[str, int], Dict[str, object]] = defaultdict(
            lambda: {"last_log_at": 0.0, "suppressed": 0, "last_path": ""}
        )
        self._error_log_interval = 5.0

    @classmethod
    def _is_noisy_success_path(cls, path: str) -> bool:
        if path in cls._quiet_exact:
            return True
        return any(path.startswith(prefix) for prefix in cls._quiet_prefixes)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Log request and response with timing."""
        
        start_time = time.time()
        
        try:
            response = await call_next(request)
            process_time = time.time() - start_time

            log_msg = (
                f"{request.method} {request.url.path} - "
                f"Status: {response.status_code} - "
                f"Duration: {process_time:.3f}s"
            )

            # High-frequency dashboard polling can flood terminal output.
            if response.status_code >= 400:
                self._log_error_response(request, response.status_code, log_msg)
            else:
                # Successful polling requests are intentionally quiet in terminal output.
                logger.debug(log_msg)
            
            return response
            
        except Exception as e:
            process_time = time.time() - start_time
            logger.error(
                f"{request.method} {request.url.path} - "
                f"Error: {str(e)[:100]} - "
                f"Duration: {process_time:.3f}s",
                exc_info=True,
            )
            raise

    def _log_error_response(self, request: Request, status_code: int, log_msg: str) -> None:
        """Log one detailed warning per short interval and aggregate duplicates."""
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        key = (client_ip, int(status_code))
        state = self._error_log_state[key]
        last_log_at = float(state.get("last_log_at", 0.0) or 0.0)
        suppressed = int(state.get("suppressed", 0) or 0)

        if (now - last_log_at) >= self._error_log_interval:
            if suppressed > 0:
                logger.warning(
                    "Suppressed %d repeated HTTP %d responses from %s (last path: %s)",
                    suppressed,
                    status_code,
                    client_ip,
                    state.get("last_path") or "n/a",
                )
            if status_code == 429:
                logger.debug(log_msg)
                state["last_log_at"] = now
                state["suppressed"] = 0
                state["last_path"] = request.url.path
                return

            logger.warning(log_msg)
            logger.warning(f"HTTP {status_code}: {request.method} {request.url.path}")
            state["last_log_at"] = now
            state["suppressed"] = 0
            state["last_path"] = request.url.path
            return

        state["suppressed"] = suppressed + 1
        state["last_path"] = request.url.path
