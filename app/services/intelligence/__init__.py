"""CyberSentinel — Intelligence Service Package factory."""
from app.services.intelligence.cache import get_cache
from app.services.intelligence.enrichment import IntelligenceEnrichmentService
from app.services.intelligence.scoring import scoring_engine

def get_enrichment_service() -> IntelligenceEnrichmentService:
    """FastAPI dependency. Usage: Depends(get_enrichment_service)"""
    return IntelligenceEnrichmentService(
        cache=get_cache(),
        scorer=scoring_engine,
    )

__all__ = ["IntelligenceEnrichmentService", "get_enrichment_service"]