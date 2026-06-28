"""
CyberSentinel — Domain Repositories
======================================
One repository class per database table.
Each class adds table-specific query methods on top of BaseRepository.

Business logic is NOT here — repositories only do I/O.
"""

import logging
from datetime import datetime
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
    ) -> dict:
        """Aggregate packet counts grouped by severity."""
        try:
            query = self._db.table("packets").select("severity", count="exact")
            if since:
                query = query.gte("captured_at", since.isoformat())
            result = await query.execute()
            rows = result.data or []
            stats: dict = {"Normal": 0, "Suspicious": 0, "Malicious": 0, "Unknown": 0}
            for row in rows:
                key = row.get("severity") or "Unknown"
                stats[key] = stats.get(key, 0) + 1
            return stats
        except Exception as exc:
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
        """Retrieve the last N messages in a copilot session."""
        try:
            result = (
                await self._db.table("copilot_conversations")
                .select("*")
                .eq("session_id", session_id)
                .order("created_at", desc=False)
                .limit(limit)
                .execute()
            )
            return result.data or []
        except Exception as exc:
            logger.exception("get_session_history failed: %s", exc)
            return []
