"""Token-bucket rate limiting (Redis-backed, in-memory fallback)."""
from __future__ import annotations

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from core.utils.config import settings
from core.utils.logger import get_logger

logger = get_logger("api.rate_limit")

try:
    import redis  # type: ignore

    _redis = redis.from_url(settings.REDIS_URL, socket_connect_timeout=1)
    _redis.ping()
except Exception:  # noqa: BLE001
    _redis = None

_local: dict[str, deque] = defaultdict(deque)
_EXEMPT_PREFIXES = ("/api/health", "/docs", "/openapi.json", "/redoc")


def _client_key(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth:
        return f"rl:{hash(auth) & 0xFFFFFFFF}"
    fwd = request.headers.get("x-forwarded-for", "")
    ip = fwd.split(",")[0].strip() or (request.client.host if request.client else "anon")
    return f"rl:{ip}"


def _allow(key: str, limit: int, window: int = 60) -> tuple[bool, int]:
    now = time.time()
    if _redis is not None:
        pipe = _redis.pipeline()
        pipe.incr(key)
        pipe.expire(key, window)
        count, _ = pipe.execute()
        return count <= limit, max(0, limit - int(count))
    bucket = _local[key]
    while bucket and bucket[0] < now - window:
        bucket.popleft()
    bucket.append(now)
    return len(bucket) <= limit, max(0, limit - len(bucket))


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limit_per_minute: int | None = None):
        super().__init__(app)
        self.limit = limit_per_minute or settings.RATE_LIMIT_PER_MINUTE

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith(_EXEMPT_PREFIXES):
            return await call_next(request)
        key = _client_key(request)
        allowed, remaining = _allow(key, self.limit)
        if not allowed:
            logger.warning("rate limit exceeded for %s on %s", key, request.url.path)
            return JSONResponse(
                status_code=429,
                content={"error": "rate_limited", "message": "too many requests"},
                headers={"retry-after": "60", "x-ratelimit-remaining": "0"},
            )
        response = await call_next(request)
        response.headers["x-ratelimit-limit"] = str(self.limit)
        response.headers["x-ratelimit-remaining"] = str(remaining)
        return response
