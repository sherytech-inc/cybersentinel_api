"""
CyberSentinel — Domain Repositories
======================================
One repository class per database table.
Each class adds table-specific query methods on top of BaseRepository.

Business logic is NOT here — repositories only do I/O.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from supabase import AsyncClient

from app.repositories.base import BaseRepository

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Packet Repository
# ─────────────────────────────────────────────────────────────────────────────

class PacketRepository(BaseRepository):
    def __init__(self, client: AsyncClient) -> None:
        super().__init__(client, "packets")

    async def get_by_session(self, session_id: str) -> list[dict]:
        """Fetch all packets in a given capture session."""
        try:
            result = (
                await self._db.table("packets")
                .select("*")
                .eq("session_id", session_id)
                .order("captured_at", desc=False)
                .execute()
            )
            return result.data or []
        except Exception as exc:
            logger.exception("get_by_session failed: %s", exc)
            return []

    async def get_stats(
        self,
        since: Optional[datetime] = None,
        include_demo: bool = False,
    ) -> dict:
        """Aggregate packet counts grouped by severity."""
        try:
            query = self._db.table("packets").select("severity", count="exact")
            from app.database.client import db_has_demo_columns
            if db_has_demo_columns():
                if not include_demo:
                    query = query.eq("is_demo", False)
                if since:
                    query = query.gte("captured_at", since.isoformat())
                result = await query.execute()
                rows = result.data or []
            else:
                if since:
                    query = query.gte("captured_at", since.isoformat())
                result = await query.execute()
                rows = result.data or []
                if include_demo:
                    from app.repositories.base import _in_memory_demo_store
                    demo_rows = _in_memory_demo_store.get("packets", [])
                    if since:
                        from datetime import datetime
                        demo_rows = [
                            r for r in demo_rows
                            if datetime.fromisoformat(r["captured_at"].replace("Z", "+00:00")) >= since
                        ]
                    rows.extend(demo_rows)

            stats: dict = {"Normal": 0, "Suspicious": 0, "Malicious": 0, "Unknown": 0}
            for row in rows:
                key = row.get("severity") or "Unknown"
                stats[key] = stats.get(key, 0) + 1
            return stats
        except Exception as exc:
            if db_has_demo_columns() and "is_demo" in str(exc):
                from app.database.client import disable_demo_columns
                disable_demo_columns()
                logger.warning(
                    "Optional demo columns are unavailable; retrying packet statistics against the current schema."
                )
                return await self.get_stats(since=since, include_demo=include_demo)
            logger.exception("get_stats failed: %s", exc)
            return {}


# ─────────────────────────────────────────────────────────────────────────────
# Firewall Log Repository
# ─────────────────────────────────────────────────────────────────────────────

class FirewallLogRepository(BaseRepository):
    def __init__(self, client: AsyncClient) -> None:
        super().__init__(client, "firewall_logs")

    async def get_anomalous(self, limit: int = 100) -> list[dict]:
        """Return the most recent anomalous firewall events."""
        try:
            result = (
                await self._db.table("firewall_logs")
                .select("*")
                .eq("is_anomalous", True)
                .order("logged_at", desc=True)
                .limit(limit)
                .execute()
            )
            return result.data or []
        except Exception as exc:
            logger.exception("get_anomalous failed: %s", exc)
            return []

    async def get_top_blocked_ips(self, limit: int = 10) -> list[dict]:
        """Return top IPs by block count (aggregated in Python — Supabase free tier)."""
        try:
            result = (
                await self._db.table("firewall_logs")
                .select("source_ip")
                .eq("action", "BLOCK")
                .execute()
            )
            rows = result.data or []
            counts: dict = {}
            for row in rows:
                ip = row.get("source_ip", "")
                counts[ip] = counts.get(ip, 0) + 1
            sorted_ips = sorted(counts.items(), key=lambda x: x[1], reverse=True)
            return [{"ip": ip, "count": c} for ip, c in sorted_ips[:limit]]
        except Exception as exc:
            logger.exception("get_top_blocked_ips failed: %s", exc)
            return []

    async def import_firewall_batch_atomic(
        self,
        file_sha256: str,
        source_filename: str,
        source_format: str,
        imported_count: int,
        rejected_count: int,
        imported_by: str,
        entries: list
    ) -> str:
        """Call the atomic import RPC."""
        # The RPC expects p_entries as a JSONB array, so we serialize the Pydantic models.
        # supabase-py translates keyword arguments into Postgres RPC arguments.
        # Note: the RPC arguments must match exactly.
        p_entries = [entry.model_dump(mode='json') for entry in entries]
        
        # supabase-py rpc call
        result = await self._db.rpc(
            "import_firewall_batch_atomic",
            {
                "p_file_sha256": file_sha256,
                "p_source_filename": source_filename,
                "p_source_format": source_format,
                "p_imported_count": imported_count,
                "p_rejected_count": rejected_count,
                "p_imported_by": str(imported_by),
                "p_entries": p_entries
            }
        ).execute()
        
        return result.data


# ─────────────────────────────────────────────────────────────────────────────
# Virus Scan Repository
# ─────────────────────────────────────────────────────────────────────────────

class VirusScanRepository(BaseRepository):
    def __init__(self, client: AsyncClient) -> None:
        super().__init__(client, "virus_scans")

    async def get_by_target(self, scan_target: str) -> Optional[dict]:
        """Find an existing scan result by target (deduplication)."""
        try:
            result = (
                await self._db.table("virus_scans")
                .select("*")
                .eq("scan_target", scan_target)
                .order("created_at", desc=True)
                .limit(1)
                .execute()
            )
            return result.data[0] if result.data else None
        except Exception as exc:
            logger.exception("get_by_target failed: %s", exc)
            return None


# ─────────────────────────────────────────────────────────────────────────────
# IP Intelligence Repository
# ─────────────────────────────────────────────────────────────────────────────

class IPIntelligenceRepository(BaseRepository):
    def __init__(self, client: AsyncClient) -> None:
        super().__init__(client, "ip_intelligence")

    async def get_by_ip(self, ip_address: str) -> Optional[dict]:
        try:
            result = (
                await self._db.table("ip_intelligence")
                .select("*")
                .eq("ip_address", ip_address)
                .limit(1)
                .execute()
            )
            return result.data[0] if result.data else None
        except Exception as exc:
            logger.exception("get_by_ip failed for %s: %s", ip_address, exc)
            return None

    async def upsert(self, data: dict) -> Optional[dict]:
        """Insert or update IP intelligence record."""
        try:
            result = (
                await self._db.table("ip_intelligence")
                .upsert(data, on_conflict="ip_address")
                .execute()
            )
            return result.data[0] if result.data else None
        except Exception as exc:
            logger.exception("upsert failed for IP intelligence: %s", exc)
            return None


# ─────────────────────────────────────────────────────────────────────────────
# Threat Score Repository
# ─────────────────────────────────────────────────────────────────────────────

class ThreatScoreRepository(BaseRepository):
    def __init__(self, client: AsyncClient) -> None:
        super().__init__(client, "threat_scores")

    async def get_recent_by_ip(self, ip: str, limit: int = 10) -> list[dict]:
        try:
            result = (
                await self._db.table("threat_scores")
                .select("*")
                .eq("source_ip", ip)
                .order("scored_at", desc=True)
                .limit(limit)
                .execute()
            )
            return result.data or []
        except Exception as exc:
            logger.exception("get_recent_by_ip failed: %s", exc)
            return []


# ─────────────────────────────────────────────────────────────────────────────
# Response Action Repository
# ─────────────────────────────────────────────────────────────────────────────

class ResponseActionRepository(BaseRepository):
    def __init__(self, client: AsyncClient) -> None:
        super().__init__(client, "response_actions")


# ─────────────────────────────────────────────────────────────────────────────
# Report Repository
# ─────────────────────────────────────────────────────────────────────────────

class ReportRepository(BaseRepository):
    def __init__(self, client: AsyncClient) -> None:
        super().__init__(client, "reports")


# ─────────────────────────────────────────────────────────────────────────────
# Copilot Conversation Repository
# ─────────────────────────────────────────────────────────────────────────────

class CopilotConversationRepository(BaseRepository):
    def __init__(self, client: AsyncClient) -> None:
        super().__init__(client, "copilot_conversations")

    async def get_session_history(self, session_id: str, limit: int = 20) -> list[dict]:
        """Retrieve the latest N messages in chronological order."""
        try:
            result = (
                await self._db.table("copilot_conversations")
                .select("*")
                .eq("session_id", session_id)
                .order("created_at", desc=True)
                .limit(limit)
                .execute()
            )
            rows = result.data or []
            rows.reverse()
            return rows
        except Exception as exc:
            logger.warning(
                "Copilot history unavailable | type=%s",
                type(exc).__name__,
            )
            return []


# ─────────────────────────────────────────────────────────────────────────────
# Firewall Action Repository
# ─────────────────────────────────────────────────────────────────────────────

class FirewallActionRepository(BaseRepository):
    def __init__(self, client: AsyncClient) -> None:
        super().__init__(client, "firewall_actions")

    async def get_actions_for_ip(self, ip: str, limit: int = 20) -> list[dict]:
        """Return all firewall actions targeting a specific IP."""
        try:
            result = (
                await self._db.table("firewall_actions")
                .select("*")
                .eq("ip", ip)
                .order("created_at", desc=True)
                .limit(limit)
                .execute()
            )
            return result.data or []
        except Exception as exc:
            logger.exception("get_actions_for_ip failed: %s", exc)
            return []

    async def get_blocked_ips(self, include_demo: bool = False) -> list[str]:
        """Return unique currently-blocked IPs."""
        try:
            query = self._db.table("firewall_actions").select("ip").eq("action", "BLOCK")
            from app.database.client import db_has_demo_columns
            if db_has_demo_columns():
                if not include_demo:
                    query = query.eq("is_demo", False)
                result = await query.order("created_at", desc=True).execute()
                rows = result.data or []
            else:
                result = await query.order("created_at", desc=True).execute()
                rows = result.data or []
                if include_demo:
                    from app.repositories.base import _in_memory_demo_store
                    demo_rows = [
                        r for r in _in_memory_demo_store.get("firewall_actions", [])
                        if r.get("action") == "BLOCK"
                    ]
                    rows.extend(demo_rows)
            
            seen = set()
            ips = []
            for row in rows:
                ip = row.get("ip", "")
                if ip and ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
            return ips
        except Exception as exc:
            logger.exception("get_blocked_ips failed: %s", exc)
            return []

    async def count(self, filters: Optional[dict] = None, include_demo: bool = False) -> int:
        """Count rows matching optional filters, optionally excluding demo data."""
        try:
            query = self._db.table(self._table).select("id", count="exact")
            from app.database.client import db_has_demo_columns
            if db_has_demo_columns():
                if not include_demo:
                    query = query.eq("is_demo", False)
                if filters:
                    for key, value in filters.items():
                        query = query.eq(key, value)
                result = await query.execute()
                return result.count or 0
            else:
                if filters:
                    for key, value in filters.items():
                        query = query.eq(key, value)
                result = await query.execute()
                total = result.count or 0
                if include_demo:
                    from app.repositories.base import _in_memory_demo_store
                    demo_rows = _in_memory_demo_store.get(self._table, [])
                    if filters:
                        for key, value in filters.items():
                            demo_rows = [r for r in demo_rows if r.get(key) == value]
                    total += len(demo_rows)
                return total
        except Exception as exc:
            logger.exception("COUNT failed on %s: %s", self._table, exc)
            return 0


# ─────────────────────────────────────────────────────────────────────────────
# Threat Alert Repository (Phase 7)
# ─────────────────────────────────────────────────────────────────────────────

class ThreatAlertRepository(BaseRepository):
    def __init__(self, client: AsyncClient) -> None:
        super().__init__(client, "threat_alerts")

    async def insert_alert(self, data: dict) -> Optional[dict]:
        return await self.insert(data)

    async def update_alert(self, alert_id: str, data: dict) -> Optional[dict]:
        return await self.update(alert_id, data)

    async def get_all(self, page: int = 1, page_size: int = 50) -> tuple[list[dict], int]:
        return await self.list(order_by="created_at", descending=True, page=page, page_size=page_size)

    async def get_by_severity(self, severities: list[str], page: int = 1, page_size: int = 50) -> tuple[list[dict], int]:
        try:
            offset = (page - 1) * page_size
            query = (
                self._db.table(self._table)
                .select("*", count="exact")
                .in_("severity", severities)
                .order("created_at", desc=True)
                .range(offset, offset + page_size - 1)
            )
            result = await query.execute()
            return result.data or [], result.count or 0
        except Exception as exc:
            logger.exception("get_by_severity failed: %s", exc)
            return [], 0

    async def get_history(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        ip: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[dict], int]:
        try:
            offset = (page - 1) * page_size
            from app.database.client import db_has_demo_columns
            from app.core.config import get_settings
            settings = get_settings()
            
            query = self._db.table(self._table).select("*", count="exact")

            if severity:
                query = query.eq("severity", severity)
            if status:
                query = query.eq("status", status)
            if ip:
                query = query.eq("source_ip", ip)
            if start_date:
                query = query.gte("created_at", start_date.isoformat())
            if end_date:
                query = query.lte("created_at", end_date.isoformat())

            if db_has_demo_columns():
                if not settings.ENABLE_DEMO_MODE:
                    query = query.eq("is_demo", False)

            query = query.order("created_at", desc=True)
            query = query.range(offset, offset + page_size - 1)

            result = await query.execute()
            rows = result.data or []
            total = result.count or 0

            if settings.ENABLE_DEMO_MODE and not db_has_demo_columns():
                from app.repositories.base import _in_memory_demo_store
                demo_rows = _in_memory_demo_store.get(self._table, [])
                if severity:
                    demo_rows = [r for r in demo_rows if r.get("severity") == severity]
                if status:
                    demo_rows = [r for r in demo_rows if r.get("status") == status]
                if ip:
                    demo_rows = [r for r in demo_rows if r.get("source_ip") == ip]
                if start_date:
                    demo_rows = [r for r in demo_rows if r.get("created_at", "") >= start_date.isoformat()]
                if end_date:
                    demo_rows = [r for r in demo_rows if r.get("created_at", "") <= end_date.isoformat()]
                
                rows.extend(demo_rows)
                rows = sorted(rows, key=lambda x: x.get("created_at", ""), reverse=True)
                total += len(demo_rows)
                rows = rows[offset:offset + page_size]

            return rows, total
        except Exception as exc:
            logger.exception("get_history failed: %s", exc)
            return [], 0


    async def update_status(self, alert_id: str, status: str, timeline_event: dict) -> Optional[dict]:
        try:
            # We must fetch the existing timeline to append to it
            existing = await self.get_by_id(alert_id)
            if not existing:
                return None
            
            timeline = existing.get("timeline") or []
            if not isinstance(timeline, list):
                timeline = []
            timeline.append(timeline_event)

            data = {
                "status": status,
                "timeline": timeline,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
            return await self.update(alert_id, data)
        except Exception as exc:
            logger.exception("update_status failed for alert_id=%s: %s", alert_id, exc)
            return None

    async def get_stats(self, include_demo: bool = False) -> dict:
        try:
            # Select severity, status, action to aggregate in Python
            query = self._db.table(self._table).select("severity, status, action")
            from app.database.client import db_has_demo_columns
            if db_has_demo_columns():
                if not include_demo:
                    query = query.eq("is_demo", False)
                result = await query.execute()
                rows = result.data or []
            else:
                result = await query.execute()
                rows = result.data or []
                if include_demo:
                    from app.repositories.base import _in_memory_demo_store
                    rows.extend(_in_memory_demo_store.get("threat_alerts", []))
            
            stats = {
                "total_alerts": len(rows),
                "critical_alerts": 0,
                "high_alerts": 0,
                "open_alerts": 0,
                "investigating_alerts": 0,
                "blocked_alerts": 0,
                "resolved_alerts": 0,
                "active_investigations": 0,
                "false_positives": 0
            }

            for row in rows:
                sev = row.get("severity")
                stat = row.get("status")

                if sev == "CRITICAL":
                    stats["critical_alerts"] += 1
                elif sev == "HIGH":
                    stats["high_alerts"] += 1

                if stat == "OPEN":
                    stats["open_alerts"] += 1
                elif stat == "INVESTIGATING":
                    stats["investigating_alerts"] += 1
                    stats["active_investigations"] += 1
                elif stat == "RESOLVED":
                    stats["resolved_alerts"] += 1
                elif stat == "FALSE_POSITIVE":
                    stats["false_positives"] += 1

                # `action` is a recommendation, not proof of OS enforcement.

            return stats
        except Exception as exc:
            logger.exception("get_stats failed: %s", exc)
            return {}

    async def increment_occurrence(
        self,
        alert_id: str,
        updated_fields: dict,
        *,
        identity: Optional[dict] = None,
    ) -> Optional[dict]:
        try:
            existing = await self.get_by_id(alert_id)
            if not existing:
                return None

            count = existing.get("occurrence_count", 1) + 1
            timeline = existing.get("timeline") or []
            if not isinstance(timeline, list):
                timeline = []

            # Append duplicate occurrence event to timeline
            timeline.append({
                "event": "DUPLICATE_OCCURRENCE",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "occurrence_number": count,
                "threat_score": updated_fields.get("threat_score"),
                "context": identity or {},
            })

            data = {
                **updated_fields,
                "occurrence_count": count,
                "timeline": timeline,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
            return await self.update(alert_id, data)
        except Exception as exc:
            logger.exception("increment_occurrence failed for alert_id=%s: %s", alert_id, exc)
            return None

    async def find_active_alert(
        self,
        *,
        source_ip: str,
        threat_type: str,
        flow_id: Optional[str],
        session_id: Optional[str],
        timeframe_seconds: int,
    ) -> Optional[dict]:
        """Find only a matching active occurrence, not merely the same IP."""
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(seconds=timeframe_seconds)).isoformat()
            result = (
                await self._db.table(self._table)
                .select("*")
                .eq("source_ip", source_ip)
                .in_("status", ["OPEN", "INVESTIGATING"])
                .gte("updated_at", cutoff)
                .order("updated_at", desc=True)
                .limit(20)
                .execute()
            )
            candidates = result.data or []

            def identities(row: dict) -> list[dict]:
                timeline = row.get("timeline")
                if not isinstance(timeline, list):
                    return []
                return [
                    event.get("context")
                    for event in timeline
                    if isinstance(event, dict)
                    and isinstance(event.get("context"), dict)
                ]

            if flow_id:
                return next(
                    (
                        row
                        for row in candidates
                        if any(
                            str(context.get("flow_id") or "") == str(flow_id)
                            for context in identities(row)
                        )
                    ),
                    None,
                )
            if session_id:
                return next(
                    (
                        row
                        for row in candidates
                        if any(
                            str(context.get("session_id") or "")
                            == str(session_id)
                            for context in identities(row)
                        )
                        and str(
                            row.get("model1_classification") or "unknown"
                        ).lower()
                        == threat_type
                    ),
                    None,
                )
            return next(
                (
                    row
                    for row in candidates
                    if str(
                        row.get("model1_classification") or "unknown"
                    ).lower()
                    == threat_type
                ),
                None,
            )
        except Exception as exc:
            logger.warning(
                "Active alert lookup unavailable | type=%s",
                type(exc).__name__,
            )
            raise RuntimeError("active_alert_lookup_unavailable") from exc


# ─────────────────────────────────────────────────────────────────────────────
# Analyst Note Repository
# ─────────────────────────────────────────────────────────────────────────────

class AnalystNoteRepository(BaseRepository):
    def __init__(self, client: AsyncClient) -> None:
        super().__init__(client, "analyst_notes")
        
    async def get_by_alert(self, alert_id: str, limit: int = 50) -> list[dict]:
        try:
            result = (
                await self._db.table(self._table)
                .select("*")
                .eq("alert_id", alert_id)
                .order("created_at", desc=False)
                .order("id", desc=False)
                .limit(limit)
                .execute()
            )
            return result.data or []
        except Exception as exc:
            logger.exception("get_by_alert failed for alert_id=%s: %s", alert_id, exc)
            return []
