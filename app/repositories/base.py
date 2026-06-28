"""
CyberSentinel — Base Repository
=================================
Generic async CRUD operations for Supabase.
All domain repositories inherit from this class.

Pattern: Repository layer handles ONLY database I/O.
         Business logic stays in services.
"""

import logging
from typing import Any, Generic, Optional, TypeVar

from supabase import AsyncClient

logger = logging.getLogger(__name__)

T = TypeVar("T")


class BaseRepository(Generic[T]):
    """
    Generic async Supabase repository.

    Args:
        client: Supabase AsyncClient (injected via FastAPI dependency).
        table:  Supabase table name.
    """

    def __init__(self, client: AsyncClient, table: str) -> None:
        self._db = client
        self._table = table

    async def insert(self, data: dict) -> Optional[dict]:
        """Insert a single row. Returns the created row or None on failure."""
        try:
            result = await self._db.table(self._table).insert(data).execute()
            return result.data[0] if result.data else None
        except Exception as exc:
            logger.exception("INSERT failed on %s: %s", self._table, exc)
            return None

    async def insert_many(self, rows: list[dict]) -> list[dict]:
        """Bulk insert rows. Returns list of created rows."""
        try:
            result = await self._db.table(self._table).insert(rows).execute()
            return result.data or []
        except Exception as exc:
            logger.exception("BULK INSERT failed on %s: %s", self._table, exc)
            return []

    async def get_by_id(self, record_id: str) -> Optional[dict]:
        """Fetch a single row by primary key (UUID string)."""
        try:
            result = (
                await self._db.table(self._table)
                .select("*")
                .eq("id", record_id)
                .limit(1)
                .execute()
            )
            return result.data[0] if result.data else None
        except Exception as exc:
            logger.exception("GET_BY_ID failed on %s id=%s: %s", self._table, record_id, exc)
            return None

    async def list(
        self,
        filters: Optional[dict] = None,
        order_by: str = "created_at",
        descending: bool = True,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[dict], int]:
        """
        Paginated list with optional filters.

        Returns:
            (rows, total_count)
        """
        try:
            offset = (page - 1) * page_size
            query = self._db.table(self._table).select("*", count="exact")

            if filters:
                for key, value in filters.items():
                    query = query.eq(key, value)

            query = query.order(order_by, desc=descending)
            query = query.range(offset, offset + page_size - 1)

            result = await query.execute()
            total = result.count or 0
            return result.data or [], total
        except Exception as exc:
            logger.exception("LIST failed on %s: %s", self._table, exc)
            return [], 0

    async def update(self, record_id: str, data: dict) -> Optional[dict]:
        """Update a row by ID. Returns updated row or None."""
        try:
            result = (
                await self._db.table(self._table)
                .update(data)
                .eq("id", record_id)
                .execute()
            )
            return result.data[0] if result.data else None
        except Exception as exc:
            logger.exception("UPDATE failed on %s id=%s: %s", self._table, record_id, exc)
            return None

    async def delete(self, record_id: str) -> bool:
        """Delete a row by ID. Returns True on success."""
        try:
            await self._db.table(self._table).delete().eq("id", record_id).execute()
            return True
        except Exception as exc:
            logger.exception("DELETE failed on %s id=%s: %s", self._table, record_id, exc)
            return False

    async def count(self, filters: Optional[dict] = None) -> int:
        """Count rows matching optional filters."""
        try:
            query = self._db.table(self._table).select("id", count="exact")
            if filters:
                for key, value in filters.items():
                    query = query.eq(key, value)
            result = await query.execute()
            return result.count or 0
        except Exception as exc:
            logger.exception("COUNT failed on %s: %s", self._table, exc)
            return 0
