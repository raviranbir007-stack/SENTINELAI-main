"""
Custom middleware implementations for SENTINEL-AI server
"""
import asyncio
import logging
import time
from collections import defaultdict
from typing import Callable

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
            logger.warning(
                f"Rate limit exceeded for {client_ip}: "
                f"{len(request_times)} requests in last minute"
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
                logger.warning(log_msg)
            else:
                # Successful polling requests are intentionally quiet in terminal output.
                logger.debug(log_msg)
            
            if response.status_code >= 400:
                logger.warning(
                    f"HTTP {response.status_code}: {request.method} {request.url.path}"
                )
            
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
