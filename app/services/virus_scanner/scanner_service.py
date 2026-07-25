import asyncio
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx

from app.core.config import get_settings
from app.schemas.operations import ScanStatus, VirusScanResponse

logger = logging.getLogger(__name__)
settings = get_settings()
_HASH_RE = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")


class VirusScannerService:
    def __init__(self, repository=None):
        self._repo = repository

    @staticmethod
    def valid_hash(value: str) -> bool:
        return bool(_HASH_RE.fullmatch(value.strip()))

    @staticmethod
    def valid_url(value: str) -> bool:
        try:
            parsed = urlparse(value.strip())
            return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
        except ValueError:
            return False

    async def scan(self, target: str, scan_type: str, auth_token: Optional[str] = None) -> VirusScanResponse:
        if scan_type == "url":
            return await self.scan_url(target)
        if scan_type == "hash":
            return await self.scan_hash(target)
        return self._result(target, scan_type, ScanStatus.invalid_target, "Invalid scan type.")

    async def scan_url(self, target: str) -> VirusScanResponse:
        target = target.strip()
        if not self.valid_url(target):
            return self._result(target, "url", ScanStatus.invalid_target, "Enter a valid HTTP or HTTPS URL.")
        if not settings.VIRUSTOTAL_API_KEY:
            return self._not_configured(target, "url")
        try:
            async with self._client() as client:
                response = await client.post("/urls", data={"url": target})
                error = self._http_error(response, target, "url")
                if error: return error
                analysis_id = (response.json().get("data") or {}).get("id")
                if not analysis_id:
                    return self._result(target, "url", ScanStatus.failed, "VirusTotal did not return an analysis identifier.", contacted=True)
                return await self._poll(client, target, "url", analysis_id)
        except asyncio.CancelledError:
            raise
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            logger.warning("VirusTotal URL scan unavailable | type=%s", type(exc).__name__)
            return self._unavailable(target, "url")

    async def scan_hash(self, target: str) -> VirusScanResponse:
        target = target.strip()
        if not self.valid_hash(target):
            return self._result(target, "hash", ScanStatus.invalid_target, "Enter a valid MD5, SHA-1, or SHA-256 hash.")
        if not settings.VIRUSTOTAL_API_KEY:
            return self._not_configured(target, "hash")
        try:
            async with self._client() as client:
                response = await client.get(f"/files/{target}")
                error = self._http_error(response, target, "hash")
                if error: return error
                stats = ((response.json().get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
                return self._completed(target, "hash", stats)
        except asyncio.CancelledError:
            raise
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            logger.warning("VirusTotal hash scan unavailable | type=%s", type(exc).__name__)
            return self._unavailable(target, "hash")

    async def scan_file(self, filename: str, content: bytes) -> VirusScanResponse:
        safe_name = Path(filename or "selected-file").name
        if len(content) > settings.VIRUS_SCANNER_MAX_FILE_BYTES:
            return self._result(safe_name, "file", ScanStatus.file_too_large, "File size exceeds the 10 MB limit.")
        if not content:
            return self._result(safe_name, "file", ScanStatus.invalid_target, "The selected file is empty.")
        if not settings.VIRUSTOTAL_API_KEY:
            return self._not_configured(safe_name, "file")
        try:
            async with self._client() as client:
                response = await client.post(
                    "/files",
                    files={"file": (safe_name, content, "application/octet-stream")},
                )
                error = self._http_error(response, safe_name, "file")
                if error: return error
                analysis_id = (response.json().get("data") or {}).get("id")
                if not analysis_id:
                    return self._result(safe_name, "file", ScanStatus.failed, "VirusTotal did not return an analysis identifier.", contacted=True)
                return await self._poll(client, safe_name, "file", analysis_id)
        except asyncio.CancelledError:
            raise
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            logger.warning("VirusTotal file scan unavailable | type=%s", type(exc).__name__)
            return self._unavailable(safe_name, "file")

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=settings.VIRUSTOTAL_BASE_URL,
            headers={"x-apikey": settings.VIRUSTOTAL_API_KEY or "", "Accept": "application/json"},
            timeout=settings.VIRUSTOTAL_TIMEOUT,
        )

    async def _poll(self, client, target: str, scan_type: str, analysis_id: str) -> VirusScanResponse:
        for _ in range(settings.VIRUS_SCANNER_POLL_ATTEMPTS):
            response = await client.get(f"/analyses/{analysis_id}")
            error = self._http_error(response, target, scan_type)
            if error: return error
            attributes = (response.json().get("data") or {}).get("attributes") or {}
            if attributes.get("status") == "completed":
                return self._completed(target, scan_type, attributes.get("stats") or {}, analysis_id)
            await asyncio.sleep(settings.VIRUS_SCANNER_POLL_INTERVAL_SECONDS)
        return self._result(target, scan_type, ScanStatus.pending, "Analysis is pending.", analysis_id=analysis_id, contacted=True)

    def _http_error(self, response, target: str, scan_type: str) -> VirusScanResponse | None:
        if response.status_code < 400: return None
        if response.status_code == 404:
            message = (
                "No existing VirusTotal report was found for this hash."
                if scan_type == "hash"
                else "The VirusTotal analysis was not found."
            )
            return self._result(target, scan_type, ScanStatus.not_found, message, contacted=True)
        if response.status_code == 429:
            return self._result(target, scan_type, ScanStatus.quota_exceeded, "VirusTotal is rate limited. Please try again shortly.", contacted=True)
        if response.status_code in {401, 403}:
            return self._result(target, scan_type, ScanStatus.not_configured, "VirusTotal integration is not configured correctly.", contacted=True)
        return self._unavailable(target, scan_type, contacted=True)

    def _completed(self, target: str, scan_type: str, stats: dict, analysis_id: str | None = None) -> VirusScanResponse:
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        verdict = "malicious" if malicious else "suspicious" if suspicious else "clean"
        return VirusScanResponse(
            target=target, scan_type=scan_type, status=ScanStatus.completed,
            verdict=verdict, malicious=malicious, suspicious=suspicious,
            harmless=int(stats.get("harmless") or 0), undetected=int(stats.get("undetected") or 0),
            analysis_id=analysis_id, message="Scan completed.", provider_contacted=True,
            scanned_at=datetime.now(timezone.utc),
        )

    def _result(self, target, scan_type, status, message, *, analysis_id=None, contacted=False):
        return VirusScanResponse(
            target=target, scan_type=scan_type, status=status, verdict="unknown",
            analysis_id=analysis_id, message=message, provider_contacted=contacted,
            scanned_at=datetime.now(timezone.utc),
        )

    def _not_configured(self, target, scan_type):
        return self._result(target, scan_type, ScanStatus.not_configured, "VirusTotal integration is not configured.")

    def _unavailable(self, target, scan_type, contacted=False):
        return self._result(target, scan_type, ScanStatus.unavailable, "VirusTotal is temporarily unavailable.", contacted=contacted)
