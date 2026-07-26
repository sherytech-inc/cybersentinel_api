"""
CyberSentinel — Intelligence Enrichment Service
Orchestrates: cache check → concurrent provider queries → scoring → cache store.
Never raises. All provider failures are absorbed and logged.
"""
from datetime import datetime, timezone
import asyncio, logging
from typing import Optional
from app.schemas.intelligence import (
    AbuseIpDbIntelResult, GeoIpIntelResult, IntelligenceResponse, 
    VirusTotalIntelResult, IntelStatus, IntelProviderStatus)
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

    def derive_intel_status(
        self,
        virustotal: VirusTotalIntelResult,
        abuseipdb: AbuseIpDbIntelResult,
        geoip: GeoIpIntelResult,
    ) -> IntelStatus:
        security = [virustotal, abuseipdb]
        configured = [
            provider for provider in security
            if provider.status != IntelProviderStatus.not_configured
        ]
        if not configured:
            return IntelStatus.not_configured
        successful_security = [
            provider for provider in configured
            if provider.status == IntelProviderStatus.completed
        ]
        all_providers = [virustotal, abuseipdb, geoip]
        if all(provider.status == IntelProviderStatus.completed for provider in all_providers):
            return IntelStatus.completed
        if successful_security:
            return IntelStatus.partial
        if all(provider.status == IntelProviderStatus.not_found for provider in configured):
            return IntelStatus.not_found
        if all(provider.status == IntelProviderStatus.quota_exceeded for provider in configured):
            return IntelStatus.quota_exceeded
        return IntelStatus.unavailable

    async def enrich(self, ip: str) -> IntelligenceResponse:
        cached = await self._cache.get(ip)
        if cached is not None:
            return cached

        abuse, vt, geo = await self._query_all_providers(ip)
        status = self.derive_intel_status(vt, abuse, geo)

        if status in (IntelStatus.not_configured, IntelStatus.not_found, IntelStatus.quota_exceeded, IntelStatus.unavailable, IntelStatus.failed):
            intel_score = None
            intel_severity = None
            score_confidence = None
        elif status == IntelStatus.partial:
            intel_score = None
            intel_severity = None
            score_confidence = "LIMITED"
        else: # completed
            intel_score, intel_severity = self._scorer.compute(abuse, vt, geo)
            score_confidence = "FULL"

        providers_used = []
        for name, p in [("VIRUSTOTAL", vt), ("ABUSEIPDB", abuse)]:
            if p.status == IntelProviderStatus.completed:
                providers_used.append(name)

        if status == IntelStatus.not_configured:
            msg = "Security providers are not configured."
        elif status == IntelStatus.partial:
            msg = "Partial intelligence is available."
        elif status == IntelStatus.completed:
            msg = "All providers successfully queried."
        else:
            msg = f"Lookup failed: {status.value}"

        resp = IntelligenceResponse(
            ip=ip,
            status=status,
            intel_score=intel_score,
            severity=intel_severity.value if intel_severity else "N/A",
            score_confidence=score_confidence,
            providers_used=providers_used,
            providers_queried=["VIRUSTOTAL", "ABUSEIPDB", "GEOIP"],
            providers_available=providers_used + (
                ["GEOIP"] if geo.status == IntelProviderStatus.completed else []
            ),
            analysis_status=(
                "complete" if status == IntelStatus.completed
                else "partial" if status == IntelStatus.partial
                else "failed"
            ),
            virustotal=vt,
            abuseipdb=abuse,
            geoip=geo,
            message=msg,
            looked_up_at=datetime.now(timezone.utc),
            cached=False,
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
        
        abuse = results[0] if not isinstance(results[0], Exception) else AbuseIpDbIntelResult(status=IntelProviderStatus.unavailable, message="AbuseIPDB is temporarily unavailable.")
        vt_res = results[1] if not isinstance(results[1], Exception) else VirusTotalIntelResult(status=IntelProviderStatus.unavailable, message="VirusTotal is temporarily unavailable.")
        geo_res = results[2] if not isinstance(results[2], Exception) else GeoIpIntelResult(status=IntelProviderStatus.unavailable, message="GeoIP is temporarily unavailable.")
        
        return abuse, vt_res, geo_res

    @staticmethod
    def _default_response(ip: str) -> IntelligenceResponse:
        return IntelligenceResponse(
            ip=ip,
            status=IntelStatus.unavailable,
            intel_score=None,
            severity="N/A",
            score_confidence=None,
            virustotal=VirusTotalIntelResult(status=IntelProviderStatus.unavailable),
            abuseipdb=AbuseIpDbIntelResult(status=IntelProviderStatus.unavailable),
            geoip=GeoIpIntelResult(status=IntelProviderStatus.unavailable),
            message="Internal error during bulk lookup.",
            looked_up_at=datetime.now(timezone.utc),
        )
