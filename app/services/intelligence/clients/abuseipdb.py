"""
CyberSentinel — AbuseIPDB Client
Queries /check endpoint. Weight in scoring: 40%.
"""
import logging
from typing import Optional
from app.core.config import get_settings
from app.schemas.intelligence import AbuseIpDbIntelResult, IntelProviderStatus
from app.services.intelligence.clients.base import BaseHTTPClient
from app.services.intelligence.exceptions import (
    ProviderError,
    ProviderNotFoundError,
    ProviderQuotaExceededError,
    ProviderUnavailableError,
)

logger = logging.getLogger(__name__)
_s = get_settings()

class AbuseIPDBClient(BaseHTTPClient):
    _base_url: str = _s.ABUSEIPDB_BASE_URL
    _timeout: float = _s.ABUSEIPDB_TIMEOUT

    def __init__(self):
        super().__init__()
        self._default_headers = {
            "Accept": "application/json",
            "Key": _s.ABUSEIPDB_API_KEY or "",
        }

    async def check_ip(self, ip: str) -> AbuseIpDbIntelResult:
        if not _s.ABUSEIPDB_API_KEY:
            return AbuseIpDbIntelResult(
                status=IntelProviderStatus.not_configured,
                message="AbuseIPDB integration is not configured.",
            )
        try:
            raw = await self._get(
                "/check",
                params={"ipAddress": ip, "maxAgeInDays": _s.ABUSEIPDB_MAX_AGE_DAYS},
                provider_name="AbuseIPDB",
            )
            data = raw.get("data") or {}
            return AbuseIpDbIntelResult(
                status=IntelProviderStatus.completed,
                abuse_confidence_score=int(data.get("abuseConfidenceScore") or 0),
                total_reports=int(data.get("totalReports") or 0),
                num_distinct_users=int(data.get("numDistinctUsers") or 0),
                last_reported_at=(
                    str(data.get("lastReportedAt"))
                    if data.get("lastReportedAt")
                    else None
                ),
                is_whitelisted=data.get("isWhitelisted"),
                is_tor=data.get("isTor"),
            )
        except ProviderNotFoundError:
            return AbuseIpDbIntelResult(
                status=IntelProviderStatus.not_found,
                message="No AbuseIPDB report was found for this IP.",
            )
        except ProviderQuotaExceededError:
            return AbuseIpDbIntelResult(
                status=IntelProviderStatus.quota_exceeded,
                message="AbuseIPDB is rate limited.",
            )
        except (ProviderError, ProviderUnavailableError) as exc:
            logger.warning("AbuseIPDB lookup unavailable | type=%s", type(exc).__name__)
            return AbuseIpDbIntelResult(
                status=IntelProviderStatus.unavailable,
                message="AbuseIPDB is temporarily unavailable.",
            )
