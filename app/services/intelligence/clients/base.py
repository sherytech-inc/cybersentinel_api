"""
CyberSentinel — Base Async HTTP Client
Shared foundation for AbuseIPDB, VirusTotal, GeoIP clients.
Features: retry, exponential backoff, 429 handling, structured logging.
"""
import asyncio, logging
from typing import Any, Optional
import httpx
from app.core.config import get_settings
from app.services.intelligence.exceptions import (
    ProviderError,
    ProviderNotFoundError,
    ProviderQuotaExceededError,
    ProviderUnavailableError,
)

logger = logging.getLogger(__name__)
_s = get_settings()

class BaseHTTPClient:
    _base_url: str = ""
    _default_headers: dict = {}
    _timeout: float = 10.0

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None
        self._max_retries = _s.HTTP_MAX_RETRIES
        self._backoff = _s.HTTP_RETRY_BACKOFF
        self._retry_statuses = set(_s.HTTP_RETRY_STATUSES)

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers=self._default_headers,
            timeout=self._timeout,
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *_: Any):
        if self._client: await self._client.aclose()

    async def _get(self, path: str, params=None,
                   extra_headers=None, provider_name="provider") -> Optional[dict]:
        url = f"{self._base_url}{path}"
        headers = {**self._default_headers, **(extra_headers or {})}
        for attempt in range(1, self._max_retries + 1):
            try:
                r = await self._client.get(url, params=params, headers=headers)
                if r.status_code == 429:
                    wait = int(r.headers.get("Retry-After", self._backoff * attempt))
                    logger.warning("[%s] Rate-limited. Waiting %ds", provider_name, wait)
                    await asyncio.sleep(wait); continue
                if r.status_code in self._retry_statuses:
                    wait = self._backoff * (2 ** (attempt - 1))
                    await asyncio.sleep(wait); continue
                if r.status_code == 404:
                    raise ProviderNotFoundError(f"[{provider_name}] No record found.")
                if r.status_code >= 400:
                    logger.error("[%s] HTTP %d", provider_name, r.status_code)
                    if r.status_code == 401 or r.status_code == 403:
                        raise ProviderError(f"[{provider_name}] Authentication failed (HTTP {r.status_code}).")
                    raise ProviderUnavailableError(f"[{provider_name}] Upstream error (HTTP {r.status_code}).")
                return r.json()
            except httpx.TimeoutException:
                logger.warning("[%s] Timeout on attempt %d", provider_name, attempt)
                await asyncio.sleep(self._backoff * (2 ** (attempt - 1)))
            except httpx.RequestError as e:
                logger.error("[%s] Request error: %s", provider_name, e)
                raise ProviderUnavailableError(f"[{provider_name}] Request error: {e}")
        
        # If we exhausted retries and the last failure was due to 429
        if 'r' in locals() and r.status_code == 429:
            raise ProviderQuotaExceededError(f"[{provider_name}] Quota exceeded after {self._max_retries} attempts.")
        raise ProviderUnavailableError(f"[{provider_name}] All {self._max_retries} attempts exhausted.")

    async def _post(self, path: str, data=None, json_data=None,
                    extra_headers=None, provider_name="provider") -> httpx.Response | None:
        url = f"{self._base_url}{path}"
        headers = {**self._default_headers, **(extra_headers or {})}
        for attempt in range(1, self._max_retries + 1):
            try:
                r = await self._client.post(url, data=data, json=json_data, headers=headers)
                if r.status_code == 429:
                    wait = int(r.headers.get("Retry-After", self._backoff * attempt))
                    logger.warning("[%s] Rate-limited POST. Waiting %ds", provider_name, wait)
                    await asyncio.sleep(wait); continue
                if r.status_code in self._retry_statuses:
                    wait = self._backoff * (2 ** (attempt - 1))
                    await asyncio.sleep(wait); continue
                return r
            except httpx.TimeoutException:
                await asyncio.sleep(self._backoff * (2 ** (attempt - 1)))
            except httpx.RequestError as e:
                logger.error("[%s] POST Request error: %s", provider_name, e)
                return None
        logger.error("[%s] All %d POST attempts exhausted", provider_name, self._max_retries)
        return None