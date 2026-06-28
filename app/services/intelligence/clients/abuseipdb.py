"""
CyberSentinel — AbuseIPDB Client
Queries /check endpoint. Weight in scoring: 40%.
"""
import logging
from typing import Optional
from app.core.config import get_settings
from app.schemas.intelligence import AbuseIPDBResult
from app.services.intelligence.clients.base import BaseHTTPClient

logger = logging.getLogger(__name__)
_s = get_settings()

class AbuseIPDBClient(BaseHTTPClient):
    _base_url: str = _s.ABUSEIPDB_BASE_URL
    _timeout: float = _s.ABUSEIPDB_TIMEOUT

    def __init__(self):
        super().__init__()
        self._default_headers = {
            "Key": _s.ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        }

    async def check_ip(self, ip: str) -> Optional[AbuseIPDBResult]:
        raw = await self._get(
            path="/check",
            params={"ipAddress": ip,
                    "maxAgeInDays": _s.ABUSEIPDB_MAX_AGE_DAYS,
                    "verbose": ""},
            provider_name="AbuseIPDB",
        )
        if raw is None: return None
        try:
            d = raw.get("data", {})
            return AbuseIPDBResult(
                abuse_confidence_score=d.get("abuseConfidenceScore", 0),
                total_reports=d.get("totalReports", 0),
                num_distinct_users=d.get("numDistinctUsers", 0),
                is_whitelisted=bool(d.get("isWhitelisted", False)),
                is_tor=bool(d.get("isTor", False)),
            )
        except Exception as e:
            logger.exception("AbuseIPDB parse error for %s: %s", ip, e)
            return None