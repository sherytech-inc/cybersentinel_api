"""
CyberSentinel — Database Client
================================
Async Supabase / PostgreSQL client using supabase-py.

Provides a singleton client used by all repository classes.
Never instantiate this directly — use get_db_client() as a FastAPI dependency.
"""

import logging
from typing import Optional

from supabase import AsyncClient, acreate_client

from app.core.config import get_settings

logger = logging.getLogger(__name__)
_settings = get_settings()

_client: Optional[AsyncClient] = None


async def init_db() -> AsyncClient:
    """
    Initialise the Supabase async client singleton.
    Called once at application startup from lifespan().
    """
    global _client
    if not _settings.SUPABASE_URL or not _settings.SUPABASE_SERVICE_ROLE_KEY:
        logger.warning(
            "SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not set — "
            "database operations will fail. Set them in .env."
        )
        return None  # type: ignore[return-value]

    _client = await acreate_client(
        _settings.SUPABASE_URL,
        _settings.SUPABASE_SERVICE_ROLE_KEY,  # service role for backend ops
    )
    logger.info("Supabase client initialised — URL=%s", _settings.SUPABASE_URL)
    return _client


async def get_db_client() -> AsyncClient:
    """
    FastAPI dependency — returns the Supabase client.

    Usage:
        db: AsyncClient = Depends(get_db_client)
    """
    if _client is None:
        raise RuntimeError(
            "Database client not initialised. "
            "Ensure init_db() is called during application startup."
        )
    return _client
