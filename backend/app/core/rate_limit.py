import time
from typing import Dict, List, Optional
from fastapi import Request
import redis.asyncio as aioredis

from app.core.config import settings
from app.core.exceptions import RateLimitException

# Local memory sliding window store: ip -> list of timestamps
_MEMORY_RATE_LIMIT_STORE: Dict[str, List[float]] = {}


async def check_rate_limit(
    request: Request,
    key_prefix: str = "auth",
    max_requests: int = 5,
    window_seconds: int = 60,
) -> None:
    """
    Sliding-window IP rate limiter.
    Attempts Redis first; seamlessly falls back to local memory if Redis is offline.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    rate_key = f"ratelimit:{key_prefix}:{client_ip}"
    now = time.time()

    # 1. Try Redis sliding window
    try:
        r = aioredis.from_url(
            settings.REDIS_URL,
            socket_timeout=1.0,
            decode_responses=True,
        )
        async with r:
            pipe = r.pipeline()
            # Remove timestamps older than window
            pipe.zremrangebyscore(rate_key, 0, now - window_seconds)
            # Count remaining timestamps
            pipe.zcard(rate_key)
            # Add current timestamp
            pipe.zadd(rate_key, {str(now): now})
            # Set TTL on key
            pipe.expire(rate_key, window_seconds)
            results = await pipe.execute()
            count = results[1]

            if count >= max_requests:
                raise RateLimitException(
                    f"Too many requests. Please wait {window_seconds} seconds before retrying."
                )
            return
    except RateLimitException:
        raise
    except Exception:
        # 2. Redis offline / error -> Fallback to in-memory sliding window
        pass

    # In-memory sliding window fallback
    timestamps = _MEMORY_RATE_LIMIT_STORE.get(rate_key, [])
    # Prune old timestamps
    cutoff = now - window_seconds
    valid_timestamps = [ts for ts in timestamps if ts > cutoff]

    if len(valid_timestamps) >= max_requests:
        _MEMORY_RATE_LIMIT_STORE[rate_key] = valid_timestamps
        raise RateLimitException(
            f"Too many requests. Please wait {window_seconds} seconds before retrying."
        )

    valid_timestamps.append(now)
    _MEMORY_RATE_LIMIT_STORE[rate_key] = valid_timestamps
