"""
CyberSentinel — Database Client
================================
Async Supabase / PostgreSQL client using supabase-py.

Provides a singleton client used by all repository classes.
Never instantiate this directly — use get_db_client() as a FastAPI dependency.
"""

import logging
from typing import Optional

from fastapi import Request
from supabase import AsyncClient, acreate_client

from app.core.config import get_settings

logger = logging.getLogger(__name__)
_settings = get_settings()

has_demo_columns: bool = False
has_analyst_notes_table: bool = True

def db_has_demo_columns() -> bool:
    global has_demo_columns
    return has_demo_columns

def disable_demo_columns() -> None:
    """Downgrade optional demo-column support after a schema mismatch."""
    global has_demo_columns
    has_demo_columns = False

def db_has_analyst_notes_table() -> bool:
    global has_analyst_notes_table
    return has_analyst_notes_table

async def init_db():
    # Only used to check columns at startup
    global has_demo_columns, has_analyst_notes_table
    if not _settings.SUPABASE_URL or not _settings.SUPABASE_ANON_KEY:
        logger.warning("SUPABASE_URL or SUPABASE_ANON_KEY not set")
        return
        
    client = await acreate_client(_settings.SUPABASE_URL, _settings.SUPABASE_ANON_KEY)
    
    try:
        await client.table("packets").select("is_demo").limit(1).execute()
        has_demo_columns = True
    except Exception:
        has_demo_columns = False
        
    try:
        await client.table("analyst_notes").select("id").limit(1).execute()
        has_analyst_notes_table = True
    except Exception:
        has_analyst_notes_table = False

async def get_db_client(
    request: Request = None,
    access_token: Optional[str] = None,
) -> AsyncClient:
    """
    FastAPI dependency — returns the Supabase client scoped to the current user's JWT.
    
    Usage:
        db: AsyncClient = Depends(get_db_client)
    """
    token = access_token
    if token is None and request is not None:
        auth_header = request.headers.get("Authorization")
        if auth_header:
            token = auth_header.replace("Bearer ", "").strip()

    if not token:
        # If no auth header, return an anonymous client (will be restricted by RLS)
        return await acreate_client(_settings.SUPABASE_URL, _settings.SUPABASE_ANON_KEY)

    client = await acreate_client(_settings.SUPABASE_URL, _settings.SUPABASE_ANON_KEY)
    # Pass the user's JWT directly to the PostgREST client to enforce RLS
    client.postgrest.auth(token)
    return client
