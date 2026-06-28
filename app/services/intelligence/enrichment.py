"""
CyberSentinel — Intelligence Enrichment Service
Orchestrates: cache check → concurrent provider queries → scoring → cache store.
Never raises. All provider failures are absorbed and logged.
"""
import asyncio, logging
from typing import Optional
from app.schemas.intelligence import (
    AbuseIPDBResult, GeoIPResult, IntelligenceResponse, VirusTotalResult)
from app.services.intelligence.cache import IntelligenceCache
from app.services.intelligence.clients.abuseipdb import AbuseIPDBClient
from app.services.intelligence.clients.geoip import GeoIPClient
from app.services.intelligence.clients.virustotal import VirusTotalClient
from app.services.intelligence.scoring import ThreatScoringEngine

logger = logging.getLogger(__name__)

class IntelligenceEnrichmentService:
    def __init__(self, cache: IntelligenceCache, scorer: ThreatScoringEngine):
        self._cache  = cache
        self._scorer = scorer

    async def enrich(self, ip: str) -> IntelligenceResponse:
        cached = await self._cache.get(ip)
        if cached is not None:
            return cached

        abuse, vt, geo = await self._query_all_providers(ip)
        intel_score, intel_severity = self._scorer.compute(abuse, vt, geo)

        avail, failed = [], []
        for name, val in [("AbuseIPDB",abuse),("VirusTotal",vt),("GeoIP",geo)]:
            (avail if val is not None else failed).append(name)

        resp = IntelligenceResponse(
            ip=ip,
            abuse_score=abuse.abuse_confidence_score if abuse else 0,
            abuse_total_reports=abuse.total_reports if abuse else 0,
            abuse_distinct_users=abuse.num_distinct_users if abuse else 0,
            is_tor=abuse.is_tor if abuse else False,
            is_whitelisted=abuse.is_whitelisted if abuse else False,
            vt_malicious=vt.vt_malicious if vt else 0,
            vt_suspicious=vt.vt_suspicious if vt else 0,
            vt_harmless=vt.vt_harmless if vt else 0,
            vt_total_engines=vt.vt_total_engines if vt else 0,
            vt_last_analysis_date=vt.last_analysis_date if vt else None,
            country=geo.country if geo else "Unknown",
            country_code=geo.country_code if geo else "XX",
            city=geo.city if geo else None,
            asn=geo.asn if geo else "Unknown",
            organization=geo.organization if geo else "Unknown",
            isp=geo.isp if geo else None,
            is_proxy=geo.is_proxy if geo else False,
            is_hosting=geo.is_hosting if geo else False,
            intel_score=intel_score,
            intel_severity=intel_severity,
            cached=False,
            providers_available=avail,
            providers_failed=failed,
        )
        await self._cache.set(ip, resp)
        return resp

    async def enrich_bulk(self, ips: list[str]) -> list[IntelligenceResponse]:
        results = await asyncio.gather(
            *[self.enrich(ip) for ip in ips], return_exceptions=True)
        return [
            r if not isinstance(r, Exception)
            else self._default_response(ip)
            for ip, r in zip(ips, results)
        ]

    async def _query_all_providers(self, ip):
        async with (AbuseIPDBClient() as ab,
                    VirusTotalClient() as vt,
                    GeoIPClient()     as geo):
            results = await asyncio.gather(
                ab.check_ip(ip), vt.get_ip_report(ip), geo.lookup(ip),
                return_exceptions=True)
        return tuple(None if isinstance(r, Exception) else r for r in results)

    @staticmethod
    def _default_response(ip: str) -> IntelligenceResponse:
        from app.schemas.intelligence import IntelSeverity
        return IntelligenceResponse(ip=ip, intel_score=0,
            intel_severity=IntelSeverity.SAFE,
            providers_failed=["AbuseIPDB","VirusTotal","GeoIP"])