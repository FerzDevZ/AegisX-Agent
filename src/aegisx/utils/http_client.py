"""Shared HTTP client factory for all scanners and exploits.

Eliminates duplicated httpx.AsyncClient setup across the codebase.
Provides connection pooling, consistent timeout, and optional rate limiting.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

import httpx

from aegisx.core.config import AegisxConfig


@asynccontextmanager
async def create_client(
    config: AegisxConfig,
    *,
    follow_redirects: bool = True,
    verify_ssl: bool = False,
) -> AsyncIterator[httpx.AsyncClient]:
    """Create a shared httpx.AsyncClient with consistent settings.

    Usage:
        async with create_client(config) as client:
            response = await client.get(url)

    Args:
        config: scan configuration (timeout, user_agent, etc.)
        follow_redirects: whether to follow HTTP redirects
        verify_ssl: whether to verify SSL certificates (default False for scanning)

    Yields:
        Configured httpx.AsyncClient instance
    """
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
    ) as client:
        yield client


def get_headers(config: AegisxConfig) -> dict[str, str]:
    """Get default headers for requests to the target."""
    return {"User-Agent": config.user_agent}
