"""Async parallel page crawler with scope enforcement.

Discovers pages by fetching the root URL, extracting links, and probing
common paths — all with configurable concurrency via asyncio.Semaphore.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

import httpx

from aegisx.core.config import AegisxConfig
from aegisx.utils.http_client import create_client
from aegisx.utils.logger import get_logger

logger = get_logger("crawler")

# Common paths probed during discovery
COMMON_PATHS: list[str] = [
    "/login", "/register", "/signup", "/signin",
    "/admin", "/dashboard", "/panel", "/settings",
    "/services", "/search", "/profile", "/account",
    "/api", "/api/v1", "/graphql",
    "/wp-admin", "/wp-login.php",
    "/swagger", "/docs", "/api-docs",
    "/.env", "/config", "/debug",
]

# HTML link extraction pattern
_LINK_RE = re.compile(r'href=["\']([^"\'#]+)["\']', re.IGNORECASE)


def _is_in_scope(url: str, config: AegisxConfig) -> bool:
    """Check if a URL is within the configured scan scope."""
    if not config.is_in_scope(url):
        return False
    parsed = urlparse(url)
    # Skip non-HTTP schemes and fragments
    if parsed.scheme not in ("http", "https"):
        return False
    return True


async def _fetch_one(
    client: httpx.AsyncClient,
    url: str,
    config: AegisxConfig,
    semaphore: asyncio.Semaphore,
) -> str | None:
    """Fetch a single URL inside the semaphore, return body or None."""
    async with semaphore:
        try:
            resp = await client.get(
                url,
                headers={"User-Agent": config.user_agent},
                follow_redirects=True,
            )
            if resp.status_code < 400:
                return resp.text
        except (httpx.RequestError, httpx.TimeoutException) as exc:
            logger.debug("Fetch %s failed: %s", url, exc)
    return None


async def crawl_pages(
    config: AegisxConfig,
    *,
    concurrency: int = 10,
) -> list[str]:
    """Crawl the target to discover pages and endpoints.

    Args:
        config: scan configuration (target_url, scope, user_agent, etc.)
        concurrency: max parallel HTTP requests.

    Returns:
        Deduplicated list of in-scope URLs discovered.
    """
    discovered: set[str] = {config.target_url}
    parsed = urlparse(config.target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    semaphore = asyncio.Semaphore(concurrency)

    async with create_client(config) as client:
        # 1. Fetch root page and extract links
        root_body = await _fetch_one(client, config.target_url, config, semaphore)
        if root_body is not None:
            for link in _LINK_RE.findall(root_body):
                if link.startswith("/"):
                    full = base_url + link
                elif link.startswith("http") and parsed.netloc in link:
                    full = link
                else:
                    continue
                if _is_in_scope(full, config):
                    discovered.add(full)

        # 2. Probe common paths in parallel
        probe_urls = [
            f"{base_url}{path}"
            for path in COMMON_PATHS
            if _is_in_scope(f"{base_url}{path}", config)
            and f"{base_url}{path}" not in discovered
        ]

        if probe_urls:
            tasks = [
                _probe_path(client, url, config, semaphore)
                for url in probe_urls
            ]
            results = await asyncio.gather(*tasks)
            for url, ok in zip(probe_urls, results):
                if ok:
                    discovered.add(url)

    logger.info("Discovered %d pages to scan", len(discovered))
    return list(discovered)


async def _probe_path(
    client: httpx.AsyncClient,
    url: str,
    config: AegisxConfig,
    semaphore: asyncio.Semaphore,
) -> bool:
    """Probe a single path; return True if it responds with 2xx/3xx."""
    body = await _fetch_one(client, url, config, semaphore)
    return body is not None
