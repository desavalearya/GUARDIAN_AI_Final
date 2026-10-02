"""Operational middleware used by the deployment-ready API."""

from __future__ import annotations

import hashlib
import time

import redis.asyncio as redis
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from backend.config import settings


class RedisRateLimitMiddleware(BaseHTTPMiddleware):
    """Small fail-open fixed-window limiter for exposed API endpoints."""

    def __init__(self, app):
        super().__init__(app)
        self.redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith(("/health", "/docs", "/openapi.json")):
            return await call_next(request)
        ip = request.client.host if request.client else "unknown"
        path_group = request.url.path
        limit = settings.rate_limit_requests
        if path_group == "/api/v1/auth/login":
            limit = min(limit, 10)
        elif path_group.startswith("/api/v1/ingest"):
            limit = min(limit, 60)
        window = max(1, settings.rate_limit_window_seconds)
        slot = int(time.time()) // window
        identity = hashlib.sha256(f"{ip}:{path_group}".encode()).hexdigest()[:24]
        key = f"rate:{slot}:{identity}"
        try:
            count = await self.redis.incr(key)
            if count == 1:
                await self.redis.expire(key, window + 2)
            if count > limit:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded"},
                    headers={"Retry-After": str(window)},
                )
        except Exception:
            # Availability wins if Redis is temporarily unavailable; alerting should catch it.
            pass
        return await call_next(request)
