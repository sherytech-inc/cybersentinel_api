"""
CyberSentinel — Intelligence API Routes
Routes ONLY: validate → call service → return response.
No business logic belongs here.
"""
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from app.core.config import Settings, get_settings
from app.schemas.intelligence import (
    BulkIntelligenceResponse, BulkIPLookupRequest,
    HealthResponse, IntelligenceResponse, IPLookupRequest)
from app.services.intelligence import (
    IntelligenceEnrichmentService, get_enrichment_service)
from app.services.intelligence.cache import IntelligenceCache, get_cache

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/intelligence", tags=["Threat Intelligence"])

@router.post("/lookup", response_model=IntelligenceResponse)
async def lookup_ip(
    body: IPLookupRequest,
    service: IntelligenceEnrichmentService = Depends(get_enrichment_service),
) -> IntelligenceResponse:
    """Enrich a single IP address with threat intelligence."""
    return await service.enrich(body.ip)

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
    try: req = IPLookupRequest(ip=ip)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    evicted = await cache.invalidate(req.ip)
    return {"ip": req.ip, "invalidated": evicted}

@router.get("/cache/stats")
async def cache_stats(cache: IntelligenceCache = Depends(get_cache)) -> dict:
    return cache.stats()

@router.get("/health", response_model=HealthResponse)
async def health_check(
    cache: IntelligenceCache = Depends(get_cache),
    settings: Settings = Depends(get_settings)) -> HealthResponse:
    return HealthResponse(status="ok", version=settings.APP_VERSION,
                          cache_size=cache.size)
