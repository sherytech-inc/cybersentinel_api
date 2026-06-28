"""
CyberSentinel — VirusTotal Client
Queries /ip_addresses/{ip}. Weight in scoring: 40%.
"""
import logging
from datetime import datetime, timezone
from typing import Optional
from app.core.config import get_settings
from app.schemas.intelligence import VirusTotalResult
from app.services.intelligence.clients.base import BaseHTTPClient

logger = logging.getLogger(__name__)
_s = get_settings()

class VirusTotalClient(BaseHTTPClient):
    _base_url: str = _s.VIRUSTOTAL_BASE_URL
    _timeout: float = _s.VIRUSTOTAL_TIMEOUT

    def __init__(self):
        super().__init__()
        self._default_headers = {
            "x-apikey": _s.VIRUSTOTAL_API_KEY,
            "Accept": "application/json",
        }

    async def get_ip_report(self, ip: str) -> Optional[VirusTotalResult]:
        raw = await self._get(f"/ip_addresses/{ip}", provider_name="VirusTotal")
        if raw is None: return None
        try:
            attrs = raw.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            ts = attrs.get("last_analysis_date")
            date_str = (datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
                        if ts else None)
            m = int(stats.get("malicious", 0))
            s = int(stats.get("suspicious", 0))
            h = int(stats.get("harmless", 0))
            u = int(stats.get("undetected", 0))
            return VirusTotalResult(
                vt_malicious=m, vt_suspicious=s,
                vt_harmless=h, vt_undetected=u,
                vt_total_engines=m+s+h+u,
                last_analysis_date=date_str,
            )
        except Exception as e:
            logger.exception("VirusTotal parse error for %s: %s", ip, e)
            return None