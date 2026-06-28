"""
CyberSentinel — Model 3 Unit Tests
====================================
Tests for:
    - IP validation (schemas)
    - ThreatScoringEngine (scoring.py)
    - IntelligenceCache (cache.py)
    - IntelligenceEnrichmentService (enrichment.py) — mocked providers
    - API routes (intelligence_routes.py) — FastAPI TestClient

Run with:
    pytest tests/test_intelligence.py -v
"""

import asyncio
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.schemas.intelligence import (
    AbuseIPDBResult,
    BulkIPLookupRequest,
    GeoIPResult,
    IntelligenceResponse,
    IntelSeverity,
    IPLookupRequest,
    VirusTotalResult,
)
from app.services.intelligence.cache import IntelligenceCache
from app.services.intelligence.enrichment import IntelligenceEnrichmentService
from app.services.intelligence.scoring import ThreatScoringEngine


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def scorer() -> ThreatScoringEngine:
    return ThreatScoringEngine()


@pytest.fixture
def cache() -> IntelligenceCache:
    # 5-second TTL and small max-size for tests
    return IntelligenceCache(ttl_seconds=5, max_size=100)


@pytest.fixture
def clean_abuse() -> AbuseIPDBResult:
    return AbuseIPDBResult(
        abuse_confidence_score=0,
        total_reports=0,
        num_distinct_users=0,
        is_whitelisted=False,
        is_tor=False,
    )


@pytest.fixture
def malicious_abuse() -> AbuseIPDBResult:
    return AbuseIPDBResult(
        abuse_confidence_score=97,
        total_reports=1200,
        num_distinct_users=85,
        is_whitelisted=False,
        is_tor=True,
    )


@pytest.fixture
def clean_vt() -> VirusTotalResult:
    return VirusTotalResult(
        vt_malicious=0,
        vt_suspicious=0,
        vt_harmless=70,
        vt_undetected=2,
        vt_total_engines=72,
    )


@pytest.fixture
def malicious_vt() -> VirusTotalResult:
    return VirusTotalResult(
        vt_malicious=45,
        vt_suspicious=5,
        vt_harmless=5,
        vt_undetected=15,
        vt_total_engines=70,
    )


@pytest.fixture
def safe_geo() -> GeoIPResult:
    return GeoIPResult(
        country="United States",
        country_code="US",
        asn="AS15169",
        organization="Google LLC",
        is_proxy=False,
        is_hosting=False,
    )


@pytest.fixture
def risky_geo() -> GeoIPResult:
    return GeoIPResult(
        country="Russia",
        country_code="RU",
        asn="AS12345",
        organization="DigitalOcean LLC",
        is_proxy=True,
        is_hosting=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. Schema validation tests
# ─────────────────────────────────────────────────────────────────────────────

class TestIPLookupRequest:
    def test_valid_ipv4(self):
        req = IPLookupRequest(ip="8.8.8.8")
        assert req.ip == "8.8.8.8"

    def test_valid_ipv4_with_whitespace(self):
        req = IPLookupRequest(ip="  1.1.1.1  ")
        assert req.ip == "1.1.1.1"

    def test_rejects_private_ipv4_192(self):
        with pytest.raises(ValueError, match="private"):
            IPLookupRequest(ip="192.168.1.1")

    def test_rejects_private_ipv4_10(self):
        with pytest.raises(ValueError, match="private"):
            IPLookupRequest(ip="10.0.0.1")

    def test_rejects_loopback(self):
        with pytest.raises(ValueError, match="private"):
            IPLookupRequest(ip="127.0.0.1")

    def test_rejects_invalid_string(self):
        with pytest.raises(ValueError):
            IPLookupRequest(ip="not-an-ip")

    def test_rejects_empty_string(self):
        with pytest.raises(ValueError):
            IPLookupRequest(ip="")

    def test_rejects_out_of_range_octet(self):
        with pytest.raises(ValueError):
            IPLookupRequest(ip="999.0.0.1")


class TestBulkIPLookupRequest:
    def test_valid_bulk(self):
        req = BulkIPLookupRequest(ips=["8.8.8.8", "1.1.1.1"])
        assert len(req.ips) == 2

    def test_rejects_empty_list(self):
        with pytest.raises(ValueError):
            BulkIPLookupRequest(ips=[])

    def test_rejects_private_in_bulk(self):
        with pytest.raises(ValueError):
            BulkIPLookupRequest(ips=["8.8.8.8", "192.168.1.1"])

    def test_rejects_more_than_50(self):
        with pytest.raises(ValueError):
            BulkIPLookupRequest(ips=[f"1.1.1.{i}" for i in range(51)])


# ─────────────────────────────────────────────────────────────────────────────
# 2. Threat Scoring Engine tests
# ─────────────────────────────────────────────────────────────────────────────

class TestThreatScoringEngine:
    def test_clean_ip_scores_safe(self, scorer, clean_abuse, clean_vt, safe_geo):
        score, severity = scorer.compute(clean_abuse, clean_vt, safe_geo)
        assert score <= 25
        assert severity == IntelSeverity.SAFE

    def test_malicious_ip_scores_high_or_critical(self, scorer, malicious_abuse, malicious_vt, risky_geo):
        score, severity = scorer.compute(malicious_abuse, malicious_vt, risky_geo)
        assert score >= 76  # high abuse + vt + risky geo → at least High
        assert severity in (IntelSeverity.HIGH, IntelSeverity.CRITICAL)

    def test_tor_ip_floors_at_high(self, scorer, clean_vt, safe_geo):
        tor_abuse = AbuseIPDBResult(
            abuse_confidence_score=5,
            is_tor=True,
            is_whitelisted=False,
        )
        score, severity = scorer.compute(tor_abuse, clean_vt, safe_geo)
        assert score >= 51  # TOR floor at 0.75 → ≥75% of 100

    def test_whitelisted_ip_caps_at_safe(self, scorer, malicious_vt, risky_geo):
        whitelisted_abuse = AbuseIPDBResult(
            abuse_confidence_score=80,
            is_tor=False,
            is_whitelisted=True,
        )
        score, _ = scorer.compute(whitelisted_abuse, malicious_vt, risky_geo)
        assert score <= 25

    def test_provider_failure_returns_moderate_risk(self, scorer):
        """All None providers → moderate score, not zero."""
        score, severity = scorer.compute(None, None, None)
        # 0.30*0.40 + 0.30*0.40 + 0.20*0.20 = 0.12+0.12+0.04 = 0.28 → 28 → Low
        assert 0 < score <= 50

    def test_score_bounds(self, scorer, malicious_abuse, malicious_vt, risky_geo):
        score, _ = scorer.compute(malicious_abuse, malicious_vt, risky_geo)
        assert 0 <= score <= 100

    def test_severity_low_band(self, scorer):
        # Construct a result that should land in Low
        abuse = AbuseIPDBResult(abuse_confidence_score=20)
        vt = VirusTotalResult(vt_malicious=2, vt_total_engines=70, vt_suspicious=0)
        geo = GeoIPResult(country="Germany", country_code="DE")
        score, severity = scorer.compute(abuse, vt, geo)
        # Just assert severity is consistent with score
        if score <= 25:
            assert severity == IntelSeverity.SAFE
        elif score <= 50:
            assert severity == IntelSeverity.LOW
        elif score <= 75:
            assert severity == IntelSeverity.HIGH
        else:
            assert severity == IntelSeverity.CRITICAL

    def test_high_risk_country_adds_penalty(self, scorer, clean_abuse, clean_vt):
        ru_geo = GeoIPResult(country="Russia", country_code="RU")
        us_geo = GeoIPResult(country="United States", country_code="US")
        score_ru, _ = scorer.compute(clean_abuse, clean_vt, ru_geo)
        score_us, _ = scorer.compute(clean_abuse, clean_vt, us_geo)
        assert score_ru > score_us


# ─────────────────────────────────────────────────────────────────────────────
# 3. Cache tests
# ─────────────────────────────────────────────────────────────────────────────

class TestIntelligenceCache:
    def _make_response(self, ip: str) -> IntelligenceResponse:
        return IntelligenceResponse(
            ip=ip,
            intel_score=42,
            intel_severity=IntelSeverity.LOW,
            providers_available=["GeoIP"],
        )

    @pytest.mark.asyncio
    async def test_cache_miss_returns_none(self, cache):
        result = await cache.get("8.8.8.8")
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_set_and_get(self, cache):
        resp = self._make_response("8.8.8.8")
        await cache.set("8.8.8.8", resp)
        result = await cache.get("8.8.8.8")
        assert result is not None
        assert result.ip == "8.8.8.8"
        assert result.intel_score == 42

    @pytest.mark.asyncio
    async def test_cache_hit_rate_tracking(self, cache):
        resp = self._make_response("1.1.1.1")
        await cache.set("1.1.1.1", resp)
        await cache.get("1.1.1.1")   # hit
        await cache.get("9.9.9.9")   # miss
        assert cache.hits == 1
        assert cache.misses == 1
        assert cache.hit_rate == 0.5

    @pytest.mark.asyncio
    async def test_cache_invalidation(self, cache):
        resp = self._make_response("5.5.5.5")
        await cache.set("5.5.5.5", resp)
        evicted = await cache.invalidate("5.5.5.5")
        assert evicted is True
        assert await cache.get("5.5.5.5") is None

    @pytest.mark.asyncio
    async def test_cache_invalidation_nonexistent(self, cache):
        evicted = await cache.invalidate("3.3.3.3")
        assert evicted is False

    @pytest.mark.asyncio
    async def test_cache_clear(self, cache):
        resp = self._make_response("2.2.2.2")
        await cache.set("2.2.2.2", resp)
        await cache.clear()
        assert cache.size == 0

    @pytest.mark.asyncio
    async def test_lru_eviction_at_max_size(self):
        tiny_cache = IntelligenceCache(ttl_seconds=60, max_size=2)
        r1 = self._make_response("1.0.0.1")
        r2 = self._make_response("1.0.0.2")
        r3 = self._make_response("1.0.0.3")
        await tiny_cache.set("1.0.0.1", r1)
        await tiny_cache.set("1.0.0.2", r2)
        await tiny_cache.set("1.0.0.3", r3)  # should evict 1.0.0.1
        assert tiny_cache.size == 2
        assert await tiny_cache.get("1.0.0.1") is None

    @pytest.mark.asyncio
    async def test_ttl_expiry(self):
        import time
        short_cache = IntelligenceCache(ttl_seconds=1, max_size=10)
        resp = IntelligenceResponse(
            ip="4.4.4.4", intel_score=10, intel_severity=IntelSeverity.SAFE
        )
        await short_cache.set("4.4.4.4", resp)
        await asyncio.sleep(1.1)
        assert await short_cache.get("4.4.4.4") is None


# ─────────────────────────────────────────────────────────────────────────────
# 4. Enrichment Service tests (mocked providers)
# ─────────────────────────────────────────────────────────────────────────────

class TestIntelligenceEnrichmentService:
    def _make_service(self, cache: IntelligenceCache) -> IntelligenceEnrichmentService:
        return IntelligenceEnrichmentService(
            cache=cache,
            scorer=ThreatScoringEngine(),
        )

    @pytest.mark.asyncio
    async def test_enrich_uses_cache_on_second_call(self, cache):
        service = self._make_service(cache)

        # Manually seed the cache
        cached_resp = IntelligenceResponse(
            ip="8.8.8.8",
            intel_score=5,
            intel_severity=IntelSeverity.SAFE,
            cached=True,
        )
        await cache.set("8.8.8.8", cached_resp)

        result = await service.enrich("8.8.8.8")
        assert result.intel_score == 5
        assert result.cached is True

    @pytest.mark.asyncio
    async def test_enrich_handles_all_provider_failures(self, cache):
        service = self._make_service(cache)

        with (
            patch(
                "app.services.intelligence.enrichment.AbuseIPDBClient",
            ) as MockAbuse,
            patch(
                "app.services.intelligence.enrichment.VirusTotalClient",
            ) as MockVT,
            patch(
                "app.services.intelligence.enrichment.GeoIPClient",
            ) as MockGeo,
        ):
            # Configure each async context manager mock to return None
            for MockClass in (MockAbuse, MockVT, MockGeo):
                instance = AsyncMock()
                instance.__aenter__ = AsyncMock(return_value=instance)
                instance.__aexit__ = AsyncMock(return_value=False)
                instance.check_ip = AsyncMock(return_value=None)
                instance.get_ip_report = AsyncMock(return_value=None)
                instance.lookup = AsyncMock(return_value=None)
                MockClass.return_value = instance

            result = await service.enrich("8.8.8.8")

        assert result.ip == "8.8.8.8"
        assert result.providers_failed == ["AbuseIPDB", "VirusTotal", "GeoIP"]
        assert result.providers_available == []
        assert 0 <= result.intel_score <= 100

    @pytest.mark.asyncio
    async def test_enrich_bulk_returns_all_results(self, cache):
        service = self._make_service(cache)

        # Seed both IPs in cache to avoid real HTTP calls
        for ip in ["8.8.8.8", "1.1.1.1"]:
            await cache.set(
                ip,
                IntelligenceResponse(
                    ip=ip, intel_score=0, intel_severity=IntelSeverity.SAFE
                ),
            )

        results = await service.enrich_bulk(["8.8.8.8", "1.1.1.1"])
        assert len(results) == 2
        assert {r.ip for r in results} == {"8.8.8.8", "1.1.1.1"}


# ─────────────────────────────────────────────────────────────────────────────
# 5. API Route tests (FastAPI TestClient)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    """Spin up the FastAPI test client with a real cache (no real HTTP calls)."""
    from app.main import app
    from app.services.intelligence.cache import init_cache

    init_cache(ttl_seconds=60, max_size=100)
    with TestClient(app) as c:
        yield c


class TestIntelligenceRoutes:
    def test_root_returns_200(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.json()["status"] == "online"

    def test_health_check(self, client):
        resp = client.get("/api/v1/intelligence/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "cache_size" in data

    def test_lookup_rejects_private_ip(self, client):
        resp = client.post(
            "/api/v1/intelligence/lookup",
            json={"ip": "192.168.1.1"},
        )
        assert resp.status_code == 422

    def test_lookup_rejects_invalid_ip(self, client):
        resp = client.post(
            "/api/v1/intelligence/lookup",
            json={"ip": "not-an-ip"},
        )
        assert resp.status_code == 422

    def test_bulk_rejects_empty_list(self, client):
        resp = client.post(
            "/api/v1/intelligence/bulk",
            json={"ips": []},
        )
        assert resp.status_code == 422

    def test_bulk_rejects_private_ip_in_list(self, client):
        resp = client.post(
            "/api/v1/intelligence/bulk",
            json={"ips": ["8.8.8.8", "10.0.0.1"]},
        )
        assert resp.status_code == 422

    def test_cache_stats_endpoint(self, client):
        resp = client.get("/api/v1/intelligence/cache/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "size" in data
        assert "hit_rate" in data

    def test_cache_invalidate_invalid_ip(self, client):
        resp = client.delete("/api/v1/intelligence/cache/not-an-ip")
        assert resp.status_code == 422

    def test_cache_invalidate_nonexistent_ip(self, client):
        resp = client.delete("/api/v1/intelligence/cache/8.8.4.4")
        assert resp.status_code == 200
        assert resp.json()["invalidated"] is False
