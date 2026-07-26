import httpx
import pytest
from fastapi import Depends, FastAPI, HTTPException

from app.api.auth_dependencies import verify_local_token
from app.api.auth_dependencies import get_current_analyst
from app.api.intelligence_routes import router as intelligence_router
from app.api.scanner_routes import router as scanner_router
from app.core.config import get_settings
from app.schemas.intelligence import (
    AbuseIpDbIntelResult,
    GeoIpIntelResult,
    IntelProviderStatus,
    IntelStatus,
    VirusTotalIntelResult,
)
from app.schemas.operations import ScanStatus
from app.services.intelligence.enrichment import IntelligenceEnrichmentService
from app.services.intelligence.cache import init_cache
from app.services.intelligence.clients.abuseipdb import AbuseIPDBClient
from app.services.intelligence.clients.geoip import GeoIPClient
from app.services.virus_scanner.scanner_service import VirusScannerService


def client_for(handler):
    return httpx.AsyncClient(
        base_url="https://www.virustotal.com/api/v3",
        transport=httpx.MockTransport(handler),
    )


@pytest.mark.asyncio
async def test_scanner_routes_require_local_token_and_bearer_jwt(monkeypatch):
    test_app = FastAPI()
    test_app.include_router(
        scanner_router, dependencies=[Depends(verify_local_token)]
    )
    monkeypatch.setenv("CYBERSENTINEL_LOCAL_TOKEN", "scanner-local-token")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=test_app), base_url="http://test"
    ) as client:
        no_local = await client.post("/api/v1/scanner/hash", json={"hash": "0" * 64})
        no_jwt = await client.post(
            "/api/v1/scanner/hash",
            headers={"X-CyberSentinel-Local-Token": "scanner-local-token"},
            json={"hash": "0" * 64},
        )
    assert no_local.status_code == 403
    assert no_jwt.status_code == 401


@pytest.mark.asyncio
async def test_invalid_url_and_hash_do_not_contact_virustotal(monkeypatch):
    service = VirusScannerService()
    assert (await service.scan_url("ftp://example.com")).status == ScanStatus.invalid_target
    invalid = await service.scan_hash("not-a-hash")
    assert invalid.status == ScanStatus.invalid_target
    assert invalid.message == "Enter a valid MD5, SHA-1, or SHA-256 hash."


@pytest.mark.asyncio
async def test_missing_key_is_safe_not_configured(monkeypatch):
    monkeypatch.setattr(get_settings(), "VIRUSTOTAL_API_KEY", None)
    response = await VirusScannerService().scan_hash("0" * 64)
    assert response.status == ScanStatus.not_configured
    assert response.verdict == "unknown"


@pytest.mark.asyncio
async def test_known_and_unknown_hash_contracts(monkeypatch):
    monkeypatch.setattr(get_settings(), "VIRUSTOTAL_API_KEY", "test-key")
    service = VirusScannerService()

    def known(request):
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {
            "malicious": 1, "suspicious": 0, "harmless": 60, "undetected": 9
        }}}})

    monkeypatch.setattr(service, "_client", lambda: client_for(known))
    complete = await service.scan_hash("a" * 64)
    assert complete.status == ScanStatus.completed
    assert complete.verdict == "malicious"

    service2 = VirusScannerService()
    monkeypatch.setattr(service2, "_client", lambda: client_for(lambda request: httpx.Response(404)))
    missing = await service2.scan_hash("b" * 64)
    assert missing.status == ScanStatus.not_found
    assert "No existing VirusTotal report" in missing.message


@pytest.mark.asyncio
async def test_url_submission_and_file_upload(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(settings, "VIRUS_SCANNER_POLL_INTERVAL_SECONDS", 0.0)

    def handler(request):
        if request.method == "POST" and request.url.path.endswith("/urls"):
            return httpx.Response(200, json={"data": {"id": "url-analysis"}})
        if request.method == "POST" and request.url.path.endswith("/files"):
            return httpx.Response(200, json={"data": {"id": "file-analysis"}})
        return httpx.Response(200, json={"data": {"attributes": {
            "status": "completed", "stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 0}
        }}})

    service = VirusScannerService()
    monkeypatch.setattr(service, "_client", lambda: client_for(handler))
    url = await service.scan_url("https://example.com")
    assert url.status == ScanStatus.completed
    assert url.analysis_id == "url-analysis"

    file_result = await service.scan_file("../sample.bin", b"safe test bytes")
    assert file_result.status == ScanStatus.completed
    assert file_result.target == "sample.bin"
    assert file_result.analysis_id == "file-analysis"


@pytest.mark.asyncio
async def test_oversized_file_rejected_without_network(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "VIRUS_SCANNER_MAX_FILE_BYTES", 3)
    response = await VirusScannerService().scan_file("large.bin", b"1234")
    assert response.status == ScanStatus.file_too_large
    assert response.provider_contacted is False


@pytest.mark.asyncio
async def test_virustotal_outage_is_sanitized(monkeypatch):
    monkeypatch.setattr(get_settings(), "VIRUSTOTAL_API_KEY", "test-key")
    service = VirusScannerService()

    def outage(request):
        raise httpx.ConnectError("secret upstream detail", request=request)

    monkeypatch.setattr(service, "_client", lambda: client_for(outage))
    response = await service.scan_hash("c" * 64)
    assert response.status == ScanStatus.unavailable
    assert "secret" not in (response.message or "")


@pytest.mark.asyncio
async def test_empty_or_malformed_stats_never_claim_clean(monkeypatch):
    monkeypatch.setattr(get_settings(), "VIRUSTOTAL_API_KEY", "test-key")
    service = VirusScannerService()
    monkeypatch.setattr(
        service,
        "_client",
        lambda: client_for(
            lambda request: httpx.Response(
                200,
                json={"data": {"attributes": {"last_analysis_stats": {}}}},
            )
        ),
    )
    response = await service.scan_hash("d" * 64)
    assert response.status == ScanStatus.failed
    assert response.verdict == "unknown"


def test_hash_validation_identifies_all_supported_lengths():
    service = VirusScannerService()
    assert service.valid_hash("a" * 32)
    assert service.valid_hash("b" * 40)
    assert service.valid_hash("c" * 64)
    assert not service.valid_hash("d" * 63)


@pytest.mark.asyncio
async def test_intelligence_lookup_requires_active_analyst(monkeypatch):
    init_cache(ttl_seconds=60, max_size=10)
    auth_app = FastAPI()
    auth_app.include_router(intelligence_router)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=auth_app),
        base_url="http://test",
    ) as client:
        no_jwt = await client.post(
            "/api/v1/intelligence/lookup",
            json={"ip": "8.8.8.8"},
        )
    assert no_jwt.status_code == 401

    test_app = FastAPI()
    test_app.include_router(intelligence_router)

    async def inactive_analyst():
        raise HTTPException(status_code=403, detail="Account is deactivated.")

    test_app.dependency_overrides[get_current_analyst] = inactive_analyst
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=test_app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/api/v1/intelligence/lookup",
            json={"ip": "8.8.8.8"},
        )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_partial_intelligence_has_no_underweighted_score():
    class Cache:
        async def get(self, ip):
            return None

        async def set(self, ip, response):
            return None

    class Scorer:
        def compute(self, *args):
            raise AssertionError("partial evidence must not be scored")

    service = IntelligenceEnrichmentService(cache=Cache(), scorer=Scorer())
    service._query_all_providers = lambda ip: None

    async def partial_results(ip):
        return (
            AbuseIpDbIntelResult(status=IntelProviderStatus.unavailable),
            VirusTotalIntelResult(
                status=IntelProviderStatus.completed,
                malicious=0,
                suspicious=0,
                harmless=60,
                undetected=10,
                total_engines=70,
            ),
            GeoIpIntelResult(status=IntelProviderStatus.completed),
        )

    service._query_all_providers = partial_results
    response = await service.enrich("8.8.8.8")
    assert response.status == IntelStatus.partial
    assert response.analysis_status == "partial"
    assert response.intel_score is None
    assert response.message == "Partial intelligence is available."


@pytest.mark.asyncio
async def test_url_pending_and_virustotal_rate_limit_are_normalized(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(settings, "VIRUS_SCANNER_POLL_ATTEMPTS", 1)
    monkeypatch.setattr(settings, "VIRUS_SCANNER_POLL_INTERVAL_SECONDS", 0.0)

    def pending_handler(request):
        if request.method == "POST":
            return httpx.Response(200, json={"data": {"id": "analysis-id"}})
        return httpx.Response(
            200,
            json={"data": {"attributes": {"status": "queued"}}},
        )

    pending_service = VirusScannerService()
    monkeypatch.setattr(
        pending_service,
        "_client",
        lambda: client_for(pending_handler),
    )
    pending = await pending_service.scan_url("https://example.com")
    assert pending.status == ScanStatus.pending
    assert pending.analysis_id == "analysis-id"
    assert pending.message == "Analysis is still pending."

    limited_service = VirusScannerService()
    monkeypatch.setattr(
        limited_service,
        "_client",
        lambda: client_for(lambda request: httpx.Response(429)),
    )
    limited = await limited_service.scan_hash("e" * 64)
    assert limited.status == ScanStatus.quota_exceeded
    assert limited.message == "Provider rate limited."


@pytest.mark.asyncio
async def test_provider_timeout_is_sanitized(monkeypatch):
    monkeypatch.setattr(get_settings(), "VIRUSTOTAL_API_KEY", "test-key")
    service = VirusScannerService()

    def timeout(request):
        raise httpx.ReadTimeout("private provider detail", request=request)

    monkeypatch.setattr(service, "_client", lambda: client_for(timeout))
    response = await service.scan_hash("f" * 64)
    assert response.status == ScanStatus.unavailable
    assert response.message == "Provider temporarily unavailable."


@pytest.mark.asyncio
async def test_abuse_rate_limit_and_geoip_malformed_response_are_safe(
    monkeypatch,
):
    monkeypatch.setattr(get_settings(), "ABUSEIPDB_API_KEY", "test-key")
    abuse = AbuseIPDBClient()
    abuse._max_retries = 1
    abuse._backoff = 0
    abuse._max_retry_wait = 0
    abuse._client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                429,
                headers={"Retry-After": "9999"},
            )
        )
    )
    abuse_result = await abuse.check_ip("8.8.8.8")
    await abuse._client.aclose()
    assert abuse_result.status == IntelProviderStatus.quota_exceeded
    assert abuse_result.message == "AbuseIPDB is rate limited."

    geo = GeoIPClient()
    geo._max_retries = 1
    geo._client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=["malformed"])
        )
    )
    geo_result = await geo.lookup("8.8.8.8")
    await geo._client.aclose()
    assert geo_result.status == IntelProviderStatus.unavailable
    assert geo_result.message == "GeoIP returned an invalid response."


@pytest.mark.asyncio
async def test_provider_metadata_is_normalized(monkeypatch):
    monkeypatch.setattr(get_settings(), "ABUSEIPDB_API_KEY", "test-key")
    abuse = AbuseIPDBClient()
    abuse._client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={
                    "data": {
                        "abuseConfidenceScore": 3,
                        "totalReports": 2,
                        "numDistinctUsers": 2,
                        "lastReportedAt": "2026-07-20T10:00:00Z",
                    }
                },
            )
        )
    )
    abuse_result = await abuse.check_ip("8.8.8.8")
    await abuse._client.aclose()
    assert abuse_result.last_reported_at == "2026-07-20T10:00:00Z"

    geo = GeoIPClient()
    geo._client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={
                    "status": "success",
                    "country": "United States",
                    "countryCode": "US",
                    "regionName": "California",
                    "city": "Mountain View",
                    "isp": "Example ISP",
                    "org": "Example Org",
                    "as": "AS15169 Example",
                },
            )
        )
    )
    geo_result = await geo.lookup("8.8.8.8")
    await geo._client.aclose()
    assert geo_result.region == "California"
    assert geo_result.asn == "AS15169"


def test_one_available_security_provider_produces_partial_result():
    service = IntelligenceEnrichmentService(cache=None, scorer=None)
    status = service.derive_intel_status(
        VirusTotalIntelResult(status=IntelProviderStatus.completed),
        AbuseIpDbIntelResult(status=IntelProviderStatus.unavailable),
        GeoIpIntelResult(status=IntelProviderStatus.completed),
    )
    assert status == IntelStatus.partial
