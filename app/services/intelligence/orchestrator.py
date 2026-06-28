import asyncio
import logging
from typing import Optional

from app.core.config import get_settings
from app.schemas.intelligence import IntelligenceResponse, IntelSeverity
from app.services.intelligence.cache import get_cache
from app.services.intelligence.clients.abuseipdb import AbuseIPDBClient
from app.services.intelligence.clients.virustotal import VirusTotalClient
from app.services.intelligence.clients.geoip import GeoIPClient

logger = logging.getLogger(__name__)
_settings = get_settings()

class ThreatIntelligenceOrchestrator:
    """
    Orchestrates multi-provider threat intelligence enrichment,
    manages caching, and computes unified threat scores.
    """

    @staticmethod
    def _compute_composite_score(abuse_score: int, vt_malicious: int, is_proxy: bool) -> int:
        """Computes a weighted 0-100 score based on provider feedback."""
        # Normalize VirusTotal: If 5+ engines flag it, treat VT score as 100
        vt_normalized = min((vt_malicious / 5) * 100, 100.0)
        geo_score = 70.0 if is_proxy else 0.0

        weights = _settings
        composite = (
            (abuse_score * weights.SCORE_WEIGHT_ABUSEIPDB) +
            (vt_normalized * weights.SCORE_WEIGHT_VIRUSTOTAL) +
            (geo_score * weights.SCORE_WEIGHT_GEO)
        )
        return int(min(max(composite, 0), 100))

    @staticmethod
    def _determine_severity(score: int) -> IntelSeverity:
        """Maps a numeric score to a strict severity band."""
        settings = _settings
        if score <= settings.SEVERITY_SAFE_MAX:
            return IntelSeverity.SAFE
        if score <= settings.SEVERITY_LOW_MAX:
            return IntelSeverity.LOW
        if score <= settings.SEVERITY_HIGH_MAX:
            return IntelSeverity.HIGH
        return IntelSeverity.CRITICAL

    async def enrich_ip(self, ip: str) -> IntelligenceResponse:
        cache = get_cache()
        
        # 1. Check Cache
        cached_res = await cache.get(ip)
        if cached_res:
            # Return copy with cached flag flipped to True
            cached_res.cached = True
            return cached_res

        # 2. Parallel Execution of External APIs
        async with AbuseIPDBClient() as abuse_client, \
                   VirusTotalClient() as vt_client, \
                   GeoIPClient() as geo_client:
            
            tasks = [
                abuse_client.check_ip(ip),
                vt_client.get_ip_report(ip),
                geo_client.lookup(ip)
            ]
            
            abuse_res, vt_res, geo_res = await asyncio.gather(*tasks, return_exceptions=True)

        # 3. Handle Graceful Degradation & Schema Guarantees
        providers_available = []
        providers_failed = []

        # Extract AbuseIPDB
        if abuse_res and not isinstance(abuse_res, Exception):
            abuse_score = abuse_res.abuse_confidence_score
            abuse_reports = abuse_res.total_reports
            abuse_users = abuse_res.num_distinct_users
            is_tor = abuse_res.is_tor
            is_whitelisted = abuse_res.is_whitelisted
            providers_available.append("AbuseIPDB")
        else:
            abuse_score, abuse_reports, abuse_users, is_tor, is_whitelisted = 0, 0, 0, False, False
            providers_failed.append("AbuseIPDB")

        # Extract VirusTotal
        if vt_res and not isinstance(vt_res, Exception):
            vt_malicious = vt_res.vt_malicious
            vt_suspicious = vt_res.vt_suspicious
            vt_harmless = vt_res.vt_harmless
            vt_total = vt_res.vt_total_engines
            vt_date = vt_res.last_analysis_date
            providers_available.append("VirusTotal")
        else:
            vt_malicious, vt_suspicious, vt_harmless, vt_total, vt_date = 0, 0, 0, 0, None
            providers_failed.append("VirusTotal")

        # Extract GeoIP
        if geo_res and not isinstance(geo_res, Exception):
            country = geo_res.country
            country_code = geo_res.country_code
            city = geo_res.city
            asn = geo_res.asn
            org = geo_res.organization
            isp = geo_res.isp
            is_proxy = geo_res.is_proxy
            is_hosting = geo_res.is_hosting
            providers_available.append("GeoIP")
        else:
            country, country_code, city, asn, org, isp, is_proxy, is_hosting = (
                "Unknown", "XX", None, "Unknown", "Unknown", None, False, False
            )
            providers_failed.append("GeoIP")

        # 4. Compute Metrics
        intel_score = self._compute_composite_score(abuse_score, vt_malicious, is_proxy)
        intel_severity = self._determine_severity(intel_score)

        response = IntelligenceResponse(
            ip=ip,
            abuse_score=abuse_score,
            abuse_total_reports=abuse_reports,
            abuse_distinct_users=abuse_users,
            is_tor=is_tor,
            is_whitelisted=is_whitelisted,
            vt_malicious=vt_malicious,
            vt_suspicious=vt_suspicious,
            vt_harmless=vt_harmless,
            vt_total_engines=vt_total,
            vt_last_analysis_date=vt_date,
            country=country,
            country_code=country_code,
            city=city,
            asn=asn,
            organization=org,
            isp=isp,
            is_proxy=is_proxy,
            is_hosting=is_hosting,
            intel_score=intel_score,
            intel_severity=intel_severity,
            cached=False,
            providers_available=providers_available,
            providers_failed=providers_failed
        )

        # 5. Save to Cache
        await cache.set(ip, response)
        return response