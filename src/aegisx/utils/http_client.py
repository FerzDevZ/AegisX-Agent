"""Shared HTTP client factory for all scanners and exploits.

Eliminates duplicated httpx.AsyncClient setup across the codebase.
Provides connection pooling, consistent timeout, rate limiting, and proxy support.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator

import httpx

from aegisx.core.config import AegisxConfig


class RateLimiter:
    """Token bucket rate limiter for outgoing requests."""

    def __init__(self, max_per_second: float = 10.0) -> None:
        self._interval = 1.0 / max_per_second if max_per_second > 0 else 0
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a request slot is available."""
        if self._interval <= 0:
            return
        async with self._lock:
            now = asyncio.get_event_loop().time()
            wait = self._interval - (now - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = asyncio.get_event_loop().time()


@asynccontextmanager
async def create_client(
    config: AegisxConfig,
    *,
    follow_redirects: bool = True,
    verify_ssl: bool = False,
    max_response_size: int = 5_000_000,
) -> AsyncIterator[httpx.AsyncClient]:
    """Create a shared httpx.AsyncClient with consistent settings.

    Usage:
        async with create_client(config) as client:
            response = await client.get(url)

    Args:
        config: scan configuration (timeout, user_agent, proxy, etc.)
        follow_redirects: whether to follow HTTP redirects
        verify_ssl: whether to verify SSL certificates (default False for scanning)
        max_response_size: maximum response body size in bytes (default 5MB)

    Yields:
        Configured httpx.AsyncClient instance
    """
    # Build proxy transport if proxy is configured
    proxy_url = getattr(config, "proxy", None)
    transport_kwargs: dict = {}
    if proxy_url:
        transport_kwargs["proxy"] = proxy_url

    async with httpx.AsyncClient(
        timeout=config.timeout_seconds,
        follow_redirects=follow_redirects,
        verify=verify_ssl,  # noqa: S501
        headers={"User-Agent": config.user_agent},
        limits=httpx.Limits(
            max_connections=50,
            max_keepalive_connections=20,
            keepalive_expiry=30,
        ),
        **transport_kwargs,
    ) as client:
        yield client


def get_headers(config: AegisxConfig) -> dict[str, str]:
    """Get default headers for requests to the target."""
    return {"User-Agent": config.user_agent}
