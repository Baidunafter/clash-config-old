#!/usr/bin/env python3
"""HTTP helpers shared by preflight.py and build.py.

* retries with exponential backoff for transient failures (network errors,
  HTTP 408/425/429/5xx); 404 and other client errors fail immediately;
* optional on-disk cache (``SOURCE_CACHE_DIR``), so the preflight run warms the
  cache and the build step does not download every file a second time;
* parallel prefetch.
"""
from __future__ import annotations

import hashlib
import os
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Iterable

USER_AGENT = "Baidunafter/clash-config-ruleset-builder"
RETRY_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


class FetchError(RuntimeError):
    """Network-level failure."""


class HttpStatusError(FetchError):
    def __init__(self, status: int, url: str):
        super().__init__(f"HTTP {status}: {url}")
        self.status = status
        self.url = url


def cache_enabled() -> bool:
    return bool(os.environ.get("SOURCE_CACHE_DIR", "").strip())


def _cache_path(url: str) -> Path | None:
    directory = os.environ.get("SOURCE_CACHE_DIR", "").strip()
    if not directory:
        return None
    return Path(directory) / hashlib.sha256(url.encode("utf-8")).hexdigest()


def _cache_read(url: str) -> bytes | None:
    path = _cache_path(url)
    if path is None or not path.is_file():
        return None
    ttl = float(os.environ.get("SOURCE_CACHE_TTL", "1800"))
    if time.time() - path.stat().st_mtime > ttl:
        return None
    return path.read_bytes()


def _cache_write(url: str, data: bytes) -> None:
    path = _cache_path(url)
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def fetch_bytes(
    url: str,
    timeout: float = 45,
    retries: int = 3,
    backoff: float = 1.5,
    opener: Callable[..., object] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> bytes:
    cached = _cache_read(url)
    if cached is not None:
        return cached

    open_url = opener or urllib.request.urlopen
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(retries + 1):
        try:
            with open_url(request, timeout=timeout) as response:  # type: ignore[operator]
                data = response.read()
        except urllib.error.HTTPError as exc:
            if exc.code in RETRY_STATUS and attempt < retries:
                sleep(backoff * (2 ** attempt))
                continue
            raise HttpStatusError(exc.code, url) from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            if attempt < retries:
                sleep(backoff * (2 ** attempt))
                continue
            reason = getattr(exc, "reason", exc)
            raise FetchError(f"network error for {url}: {reason}") from exc
        _cache_write(url, data)
        return data
    raise FetchError(f"unreachable: {url}")  # pragma: no cover


def fetch_text(url: str, timeout: float = 45, **kwargs) -> str:
    return fetch_bytes(url, timeout=timeout, **kwargs).decode("utf-8", errors="replace")


def prefetch(urls: Iterable[str], fetch: Callable[[str], object] = fetch_bytes, workers: int = 8) -> dict[str, Exception | None]:
    """Download ``urls`` in parallel (warming the cache). Errors are returned, not raised."""
    unique = sorted(set(urls))
    results: dict[str, Exception | None] = {}
    if not unique:
        return results

    def run(url: str) -> Exception | None:
        try:
            fetch(url)
            return None
        except Exception as exc:  # noqa: BLE001 - reported per URL by the caller
            return exc

    with ThreadPoolExecutor(max_workers=min(workers, len(unique))) as pool:
        for url, error in zip(unique, pool.map(run, unique)):
            results[url] = error
    return results
