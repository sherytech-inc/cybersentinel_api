"""
CyberSentinel — VirusTotal Client
Queries /ip_addresses/{ip}. Weight in scoring: 40%.
"""
import logging
from datetime import datetime, timezone
from typing import Optional
from app.core.config import get_settings
from app.schemas.intelligence import VirusTotalIntelResult, IntelProviderStatus
from app.services.intelligence.clients.base import BaseHTTPClient
from app.services.intelligence.exceptions import (
    ProviderError,
    ProviderNotFoundError,
    ProviderQuotaExceededError,
    ProviderUnavailableError,
)

logger = logging.getLogger(__name__)
_s = get_settings()

class VirusTotalClient(BaseHTTPClient):
    _base_url: str = _s.VIRUSTOTAL_BASE_URL
    _timeout: float = _s.VIRUSTOTAL_TIMEOUT

    def __init__(self):
        super().__init__()
        self._default_headers = {
            "Accept": "application/json",
            "x-apikey": _s.VIRUSTOTAL_API_KEY or "",
        }

    async def get_ip_report(self, ip: str) -> VirusTotalIntelResult:
        if not _s.VIRUSTOTAL_API_KEY:
            return VirusTotalIntelResult(
                status=IntelProviderStatus.not_configured,
                message="VirusTotal integration is not configured.",
            )
        try:
            raw = await self._get(
                f"/ip_addresses/{ip}", provider_name="VirusTotal"
            )
            attributes = (raw.get("data") or {}).get("attributes") or {}
            stats = attributes.get("last_analysis_stats") or {}
            malicious = int(stats.get("malicious") or 0)
            suspicious = int(stats.get("suspicious") or 0)
            harmless = int(stats.get("harmless") or 0)
            undetected = int(stats.get("undetected") or 0)
            return VirusTotalIntelResult(
                status=IntelProviderStatus.completed,
                malicious=malicious,
                suspicious=suspicious,
                harmless=harmless,
                undetected=undetected,
                total_engines=malicious + suspicious + harmless + undetected,
                last_analysis_date=str(attributes.get("last_analysis_date") or ""),
            )
        except ProviderNotFoundError:
            return VirusTotalIntelResult(
                status=IntelProviderStatus.not_found,
                message="No VirusTotal report was found for this IP.",
            )
        except ProviderQuotaExceededError:
            return VirusTotalIntelResult(
                status=IntelProviderStatus.quota_exceeded,
                message="VirusTotal is rate limited.",
            )
        except (ProviderError, ProviderUnavailableError) as exc:
            logger.warning("VirusTotal IP lookup unavailable | type=%s", type(exc).__name__)
            return VirusTotalIntelResult(
                status=IntelProviderStatus.unavailable,
                message="VirusTotal is temporarily unavailable.",
            )

    async def submit_url(self, url: str) -> Optional[str]:
        # Form data submission for VT v3 url scanning
        r = await self._post(f"/urls", data={"url": url}, provider_name="VirusTotal URL Submit")
        if r is None: return None
        if r.status_code == 429:
            return "429"
        if r.status_code >= 400:
            return None
        try:
            return r.json().get("data", {}).get("id")
        except:
            return None

    async def get_analysis(self, analysis_id: str) -> Optional[dict]:
        r = await self._get(f"/analyses/{analysis_id}", provider_name="VirusTotal Analysis")
        return r

    async def get_file_report(self, file_hash: str) -> Optional[dict]:
        r = await self._get(f"/files/{file_hash}", provider_name="VirusTotal File Hash")
        return r
