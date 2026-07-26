"""
CyberSentinel — GeoIP Client
Uses ip-api.com free tier. No key required. Weight: 20%.
"""
import logging
from typing import Optional
from app.core.config import get_settings
from app.schemas.intelligence import GeoIpIntelResult, IntelProviderStatus
from app.services.intelligence.clients.base import BaseHTTPClient
from app.services.intelligence.exceptions import (
    ProviderError,
    ProviderNotFoundError,
    ProviderQuotaExceededError,
    ProviderUnavailableError,
)

logger = logging.getLogger(__name__)
_s = get_settings()

_FIELDS = ("status,message,country,countryCode,regionName,city,"
           "lat,lon,timezone,isp,org,as,proxy,hosting")

class GeoIPClient(BaseHTTPClient):
    _base_url: str = _s.GEOIP_BASE_URL
    _timeout: float = _s.GEOIP_TIMEOUT

    def __init__(self):
        super().__init__()
        self._default_headers = {"Accept": "application/json"}

    async def lookup(self, ip: str) -> GeoIpIntelResult:
        try:
            raw = await self._get(f"/{ip}", params={"fields": _FIELDS},
                                  provider_name="GeoIP")
            if raw.get("status") == "fail":
                logger.warning("GeoIP fail for %s: %s", ip, raw.get("message"))
                # ip-api returns fail for invalid IPs or reserved IPs
                return GeoIpIntelResult(status=IntelProviderStatus.not_found, message=raw.get("message"))
            as_raw = raw.get("as", "Unknown")
            asn = as_raw.split(" ")[0] if as_raw else "Unknown"
            return GeoIpIntelResult(
                status=IntelProviderStatus.completed,
                country=raw.get("country", "Unknown"),
                country_code=raw.get("countryCode", "XX"),
                region=raw.get("regionName"),
                city=raw.get("city"),
                asn=asn,
                organization=raw.get("org", "Unknown"),
                isp=raw.get("isp"),
                is_proxy=bool(raw.get("proxy", False)),
                is_hosting=bool(raw.get("hosting", False)),
            )
        except ProviderNotFoundError:
            return GeoIpIntelResult(
                status=IntelProviderStatus.not_found,
                message="No GeoIP record was found.",
            )
        except ProviderQuotaExceededError:
            return GeoIpIntelResult(
                status=IntelProviderStatus.quota_exceeded,
                message="GeoIP is rate limited.",
            )
        except (ProviderUnavailableError, ProviderError) as exc:
            logger.warning("GeoIP lookup unavailable | type=%s", type(exc).__name__)
            return GeoIpIntelResult(
                status=IntelProviderStatus.unavailable,
                message="GeoIP is temporarily unavailable.",
            )
        except Exception as exc:
            logger.warning("GeoIP response invalid | type=%s", type(exc).__name__)
            return GeoIpIntelResult(
                status=IntelProviderStatus.unavailable,
                message="GeoIP returned an invalid response.",
            )
