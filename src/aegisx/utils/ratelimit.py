"""Rate limiter for HTTP requests during scanning.

Prevents DoS on target by limiting request rate.
"""

from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Token bucket rate limiter for async HTTP requests.

    Usage:
        limiter = RateLimiter(requests_per_second=10.0)
        async with limiter:
            response = await client.get(url)
    """

    def __init__(self, requests_per_second: float = 10.0) -> None:
        self._rate = requests_per_second
        self._interval = 1.0 / requests_per_second if requests_per_second > 0 else 1.0
        self._tokens = requests_per_second
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
        self._total_requests = 0

    async def acquire(self) -> None:
        """Acquire a token, waiting if necessary."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._rate, self._tokens + elapsed / self._interval)
            self._last_refill = now

            if self._tokens < 1:
                wait_time = (1 - self._tokens) * self._interval
                await asyncio.sleep(wait_time)
                self._tokens = 0
            else:
                self._tokens -= 1

            self._total_requests += 1

    async def __aenter__(self) -> RateLimiter:
        await self.acquire()
        return self

    async def __aexit__(self, *args: object) -> None:
        pass

    @property
    def total_requests(self) -> int:
        return self._total_requests
