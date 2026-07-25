"""
CyberSentinel — Intelligence API Routes
Routes ONLY: validate → call service → return response.
No business logic belongs here.
"""
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from datetime import datetime, timezone
from app.core.config import Settings, get_settings
from app.schemas.intelligence import (
    BulkIntelligenceResponse, BulkIPLookupRequest,
    HealthResponse, IntelligenceResponse, IPLookupRequest, IntelStatus,
    _IPV4_RE, _PRIVATE_PREFIXES, VirusTotalIntelResult, AbuseIpDbIntelResult, GeoIpIntelResult, IntelProviderStatus)
from app.services.intelligence.exceptions import InvalidIntelTargetError
from app.services.intelligence import (
    IntelligenceEnrichmentService, get_enrichment_service)
from app.services.intelligence.cache import IntelligenceCache, get_cache

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/intelligence", tags=["Threat Intelligence"])

def validate_public_ip(v: str) -> str:
    v = v.strip()
    if not _IPV4_RE.match(v):
        raise InvalidIntelTargetError(f"'{v}' is not a valid IPv4 address.")
    if any(v.startswith(p) for p in _PRIVATE_PREFIXES):
        raise InvalidIntelTargetError(f"'{v}' is a private/reserved address.")
    return v

@router.post(
    "/lookup", 
    response_model=IntelligenceResponse,
    responses={
        422: {"model": IntelligenceResponse},
        429: {"model": IntelligenceResponse},
        503: {"model": IntelligenceResponse},
    }
)
async def lookup_ip(
    body: IPLookupRequest,
    service: IntelligenceEnrichmentService = Depends(get_enrichment_service),
):
    """Enrich a single IP address with threat intelligence."""
    try:
        validated_ip = validate_public_ip(body.ip)
    except InvalidIntelTargetError as exc:
        return JSONResponse(
            status_code=422,
            content=IntelligenceResponse(
                ip=body.ip,
                status=IntelStatus.invalid_target,
                virustotal=VirusTotalIntelResult(status=IntelProviderStatus.unavailable),
                abuseipdb=AbuseIpDbIntelResult(status=IntelProviderStatus.unavailable),
                geoip=GeoIpIntelResult(status=IntelProviderStatus.unavailable),
                message=str(exc),
                looked_up_at=datetime.now(timezone.utc),
            ).model_dump(mode="json"),
        )
    
    resp = await service.enrich(validated_ip)
    
    status_code = 200
    if resp.status == IntelStatus.not_configured:
        status_code = 503
    elif resp.status == IntelStatus.not_found:
        status_code = 404
    elif resp.status == IntelStatus.quota_exceeded:
        status_code = 429
    elif resp.status == IntelStatus.unavailable:
        status_code = 503

    return JSONResponse(status_code=status_code, content=resp.model_dump(mode="json"))

@router.post("/bulk", response_model=BulkIntelligenceResponse)
async def lookup_bulk(
    body: BulkIPLookupRequest,
    service: IntelligenceEnrichmentService = Depends(get_enrichment_service),
) -> BulkIntelligenceResponse:
    """Enrich up to 50 IPs concurrently."""
    results = await service.enrich_bulk(body.ips)
    succeeded = sum(1 for r in results if r.providers_available)
    return BulkIntelligenceResponse(
        results=results, total=len(results),
        succeeded=succeeded, failed=len(results)-succeeded)

@router.delete("/cache/{ip}")
async def invalidate_cache(
    ip: str, cache: IntelligenceCache = Depends(get_cache)) -> dict:
    try:
        validated_ip = validate_public_ip(ip)
    except InvalidIntelTargetError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    evicted = await cache.invalidate(validated_ip)
    return {"ip": validated_ip, "invalidated": evicted}

@router.get("/cache/stats")
async def cache_stats(cache: IntelligenceCache = Depends(get_cache)) -> dict:
    return cache.stats()

@router.get("/health", response_model=HealthResponse)
async def health_check(
    cache: IntelligenceCache = Depends(get_cache),
    settings: Settings = Depends(get_settings)) -> HealthResponse:
    return HealthResponse(status="ok", version=settings.APP_VERSION,
                          cache_size=cache.size)
