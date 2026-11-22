"""Async HTTP with per-source rate limiting.

Passive collection is entirely bound by third-party rate limits, so the token
bucket here — not concurrency, not parsing — determines your total runtime.
Each source gets its own bucket; buckets run independently so a slow source
never blocks a fast one.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from .config import CACHE_TTL, RATE_LIMITS, Config
from .store import Store

log = logging.getLogger("bastion.net")


class TokenBucket:
    def __init__(self, per_second: float, burst: int = 1):
        self.rate = max(per_second, 0.001)
        self.capacity = max(burst, 1)
        self._tokens = float(self.capacity)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def take(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._last) * self.rate
                )
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                await asyncio.sleep((1.0 - self._tokens) / self.rate)


class HttpClient:
    """Shared client. One instance per run, passed to every collector."""

    def __init__(self, cfg: Config, store: Store):
        self.cfg = cfg
        self.store = store
        self._buckets = {
            name: TokenBucket(rl.per_second, rl.burst)
            for name, rl in RATE_LIMITS.items()
        }
        self._sem = asyncio.Semaphore(cfg.concurrency)
        self._client: httpx.AsyncClient | None = None
        self.stats: dict[str, dict[str, int]] = {}

    async def __aenter__(self) -> "HttpClient":
        self._client = httpx.AsyncClient(
            timeout=self.cfg.http_timeout,
            follow_redirects=True,
            headers={"User-Agent": self.cfg.user_agent},
            limits=httpx.Limits(max_connections=self.cfg.concurrency),
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._client:
            await self._client.aclose()

    def _bump(self, source: str, kind: str) -> None:
        self.stats.setdefault(source, {"hit": 0, "miss": 0, "error": 0})[kind] += 1

    async def get_json(
        self,
        source: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        auth: tuple[str, str] | None = None,
        cache_key: str | None = None,
        ttl: int | None = None,
        expect_json: bool = True,
    ) -> Any | None:
        """Rate-limited, cached GET. Returns parsed JSON or None on failure."""
        key = cache_key or f"{url}?{sorted((params or {}).items())}"
        ttl = CACHE_TTL.get(source, 3600) if ttl is None else ttl

        cached = self.store.cache_get(source, key, ttl)
        if cached is not None:
            self._bump(source, "hit")
            return cached

        bucket = self._buckets.get(source)
        if bucket:
            await bucket.take()

        async with self._sem:
            assert self._client is not None
            try:
                resp = await self._client.get(
                    url, params=params, headers=headers, auth=auth
                )
            except httpx.HTTPError as exc:
                log.warning("%s: request failed: %s", source, exc)
                self._bump(source, "error")
                return None

        if resp.status_code == 429:
            log.warning("%s: rate limited by server; backing off 30s", source)
            await asyncio.sleep(30)
            self._bump(source, "error")
            return None
        if resp.status_code == 404:
            self.store.cache_put(source, key, [])   # negative caching
            self._bump(source, "miss")
            return []
        if resp.status_code >= 400:
            log.warning("%s: HTTP %s for %s", source, resp.status_code, url)
            self._bump(source, "error")
            return None

        try:
            data = resp.json() if expect_json else resp.text
        except ValueError:
            log.warning("%s: non-JSON response from %s", source, url)
            self._bump(source, "error")
            return None

        self.store.cache_put(source, key, data)
        self._bump(source, "miss")
        return data

    async def post_json(
        self, source: str, url: str, *, json_body: dict[str, Any],
        headers: dict[str, str] | None = None, auth: tuple[str, str] | None = None,
        cache_key: str | None = None, ttl: int | None = None,
    ) -> Any | None:
        key = cache_key or f"POST {url} {sorted(json_body.items())}"
        ttl = CACHE_TTL.get(source, 3600) if ttl is None else ttl
        cached = self.store.cache_get(source, key, ttl)
        if cached is not None:
            self._bump(source, "hit")
            return cached

        bucket = self._buckets.get(source)
        if bucket:
            await bucket.take()
        async with self._sem:
            assert self._client is not None
            try:
                resp = await self._client.post(
                    url, json=json_body, headers=headers, auth=auth
                )
                resp.raise_for_status()
                data = resp.json()
            except (httpx.HTTPError, ValueError) as exc:
                log.warning("%s: %s", source, exc)
                self._bump(source, "error")
                return None
        self.store.cache_put(source, key, data)
        self._bump(source, "miss")
        return data
