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
_reported_insert_errors: set[str] = set()

T = TypeVar("T")


_in_memory_demo_store: dict[str, list[dict]] = {
    "packets": [],
    "threat_alerts": [],
    "firewall_actions": [],
    "analyst_notes": []
}


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
        from app.database.client import db_has_demo_columns, db_has_analyst_notes_table
        
        is_demo = data.get("is_demo") or False
        use_in_memory = False
        
        if self._table == "analyst_notes":
            if not db_has_analyst_notes_table():
                use_in_memory = True
        elif is_demo:
            if not db_has_demo_columns():
                use_in_memory = True
                
        if use_in_memory and self._table in _in_memory_demo_store:
            import uuid
            from datetime import datetime, timezone
            new_data = {**data}
            if "id" not in new_data and self._table != "threat_alerts":
                new_data["id"] = str(uuid.uuid4())
            elif "alert_id" not in new_data and self._table == "threat_alerts":
                new_data["alert_id"] = str(uuid.uuid4())
            if "created_at" not in new_data:
                new_data["created_at"] = datetime.now(timezone.utc).isoformat()
            if "updated_at" not in new_data:
                new_data["updated_at"] = datetime.now(timezone.utc).isoformat()
            _in_memory_demo_store[self._table].append(new_data)
            return new_data

        try:
            # Strip demo columns if DB doesn't support them
            clean_data = data
            if not db_has_demo_columns():
                clean_data = {k: v for k, v in data.items() if k not in ["is_demo", "demo_run_id", "demo_scenario"]}
            result = await self._db.table(self._table).insert(clean_data).execute()
            return result.data[0] if result.data else None
        except Exception as exc:
            key = f"{self._table}:{type(exc).__name__}:{exc}"
            if key not in _reported_insert_errors:
                _reported_insert_errors.add(key)
                logger.error(
                    "INSERT failed on %s | type=%s reason=%s",
                    self._table,
                    type(exc).__name__,
                    exc,
                )
            return None

    async def insert_many(self, rows: list[dict]) -> list[dict]:
        """Bulk insert rows. Returns list of created rows."""
        from app.database.client import db_has_demo_columns, db_has_analyst_notes_table
        
        use_in_memory = False
        if self._table == "analyst_notes":
            if not db_has_analyst_notes_table():
                use_in_memory = True
                
        if use_in_memory and self._table in _in_memory_demo_store:
            import uuid
            from datetime import datetime, timezone
            inserted = []
            for r in rows:
                new_row = {**r}
                if "id" not in new_row and self._table != "threat_alerts":
                    new_row["id"] = str(uuid.uuid4())
                elif "alert_id" not in new_row and self._table == "threat_alerts":
                    new_row["alert_id"] = str(uuid.uuid4())
                if "created_at" not in new_row:
                    new_row["created_at"] = datetime.now(timezone.utc).isoformat()
                if "updated_at" not in new_row:
                    new_row["updated_at"] = datetime.now(timezone.utc).isoformat()
                _in_memory_demo_store[self._table].append(new_row)
                inserted.append(new_row)
            return inserted

        # Split into demo and non-demo rows
        demo_rows = []
        non_demo_rows = []
        for r in rows:
            if r.get("is_demo") or False:
                demo_rows.append(r)
            else:
                non_demo_rows.append(r)

        inserted_rows = []
        
        if demo_rows:
            if not db_has_demo_columns() and self._table in _in_memory_demo_store:
                import uuid
                from datetime import datetime, timezone
                for r in demo_rows:
                    new_row = {**r}
                    if "id" not in new_row and self._table != "threat_alerts":
                        new_row["id"] = str(uuid.uuid4())
                    elif "alert_id" not in new_row and self._table == "threat_alerts":
                        new_row["alert_id"] = str(uuid.uuid4())
                    if "created_at" not in new_row:
                        new_row["created_at"] = datetime.now(timezone.utc).isoformat()
                    if "updated_at" not in new_row:
                        new_row["updated_at"] = datetime.now(timezone.utc).isoformat()
                    _in_memory_demo_store[self._table].append(new_row)
                    inserted_rows.append(new_row)
            else:
                try:
                    clean_demo_rows = demo_rows
                    if not db_has_demo_columns():
                        clean_demo_rows = [{k: v for k, v in r.items() if k not in ["is_demo", "demo_run_id", "demo_scenario"]} for r in demo_rows]
                    result = await self._db.table(self._table).insert(clean_demo_rows).execute()
                    inserted_rows.extend(result.data or [])
                except Exception as exc:
                    logger.exception("BULK INSERT demo rows failed on %s: %s", self._table, exc)

        if non_demo_rows:
            try:
                result = await self._db.table(self._table).insert(non_demo_rows).execute()
                inserted_rows.extend(result.data or [])
            except Exception as exc:
                logger.exception("BULK INSERT non-demo failed on %s: %s", self._table, exc)

        return inserted_rows

    async def get_by_id(self, record_id: str) -> Optional[dict]:
        """Fetch a single row by primary key (UUID string)."""
        id_col = "alert_id" if self._table == "threat_alerts" else "id"
        
        # Check in-memory store first
        if self._table in _in_memory_demo_store:
            for r in _in_memory_demo_store[self._table]:
                if r.get(id_col) == record_id:
                    return r
                    
        try:
            result = (
                await self._db.table(self._table)
                .select("*")
                .eq(id_col, record_id)
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
        from app.database.client import db_has_analyst_notes_table
        if self._table == "analyst_notes" and not db_has_analyst_notes_table():
            demo_rows = _in_memory_demo_store.get("analyst_notes", [])
            if filters:
                for key, value in filters.items():
                    demo_rows = [r for r in demo_rows if r.get(key) == value]
            demo_rows = sorted(demo_rows, key=lambda x: x.get(order_by, ""), reverse=descending)
            total = len(demo_rows)
            offset = (page - 1) * page_size
            return demo_rows[offset:offset + page_size], total

        try:
            offset = (page - 1) * page_size
            from app.database.client import db_has_demo_columns
            from app.core.config import get_settings
            settings = get_settings()

            query = self._db.table(self._table).select("*", count="exact")

            if filters:
                for key, value in filters.items():
                    query = query.eq(key, value)
            
            if db_has_demo_columns():
                if not settings.ENABLE_DEMO_MODE:
                    query = query.eq("is_demo", False)

            query = query.order(order_by, desc=descending)
            query = query.range(offset, offset + page_size - 1)

            result = await query.execute()
            rows = result.data or []
            total = result.count or 0

            if settings.ENABLE_DEMO_MODE and not db_has_demo_columns():
                demo_rows = _in_memory_demo_store.get(self._table, [])
                if filters:
                    for key, value in filters.items():
                        demo_rows = [r for r in demo_rows if r.get(key) == value]
                
                rows.extend(demo_rows)
                rows = sorted(rows, key=lambda x: x.get(order_by, ""), reverse=descending)
                total += len(demo_rows)
                rows = rows[offset:offset + page_size]

            return rows, total
        except Exception as exc:
            logger.exception("LIST failed on %s: %s", self._table, exc)
            return [], 0

    async def update(self, record_id: str, data: dict) -> Optional[dict]:
        """Update a row by ID. Returns updated row or None."""
        from app.database.client import db_has_analyst_notes_table, db_has_demo_columns
        
        is_demo = data.get("is_demo") or False
        use_in_memory = False
        if self._table == "analyst_notes":
            if not db_has_analyst_notes_table():
                use_in_memory = True
        elif is_demo:
            if not db_has_demo_columns():
                use_in_memory = True
                
        if use_in_memory and self._table in _in_memory_demo_store:
            from datetime import datetime, timezone
            id_col = "alert_id" if self._table == "threat_alerts" else "id"
            for i, r in enumerate(_in_memory_demo_store[self._table]):
                if r.get(id_col) == record_id:
                    updated = {**r, **data, "updated_at": datetime.now(timezone.utc).isoformat()}
                    _in_memory_demo_store[self._table][i] = updated
                    return updated
            return None

        try:
            clean_data = data
            if not db_has_demo_columns():
                clean_data = {k: v for k, v in data.items() if k not in ["is_demo", "demo_run_id", "demo_scenario"]}
                
            id_col = "alert_id" if self._table == "threat_alerts" else "id"
            result = (
                await self._db.table(self._table)
                .update(clean_data)
                .eq(id_col, record_id)
                .execute()
            )
            return result.data[0] if result.data else None
        except Exception as exc:
            logger.exception("UPDATE failed on %s id=%s: %s", self._table, record_id, exc)
            return None

    async def delete(self, record_id: str) -> bool:
        """Delete a row by ID. Returns True on success."""
        from app.database.client import db_has_analyst_notes_table
        if self._table == "analyst_notes" and not db_has_analyst_notes_table():
            _in_memory_demo_store["analyst_notes"] = [
                r for r in _in_memory_demo_store["analyst_notes"]
                if r.get("id") != record_id
            ]
            return True

        try:
            id_col = "alert_id" if self._table == "threat_alerts" else "id"
            await self._db.table(self._table).delete().eq(id_col, record_id).execute()
            return True
        except Exception as exc:
            logger.exception("DELETE failed on %s id=%s: %s", self._table, record_id, exc)
            return False

    async def count(self, filters: Optional[dict] = None) -> int:
        """Count rows matching optional filters."""
        from app.database.client import db_has_analyst_notes_table
        if self._table == "analyst_notes" and not db_has_analyst_notes_table():
            demo_rows = _in_memory_demo_store.get("analyst_notes", [])
            if filters:
                for key, value in filters.items():
                    demo_rows = [r for r in demo_rows if r.get(key) == value]
            return len(demo_rows)

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
