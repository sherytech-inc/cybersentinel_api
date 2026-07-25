"""
CyberSentinel — Response Service
===================================
Orchestrates Phase 8 SOC response actions (block, unblock, investigate, resolve).
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from app.repositories.repositories import FirewallActionRepository, ThreatAlertRepository
from app.services.threat_response.alert_service import AlertService
from app.services.websocket.connection_manager import get_websocket_hub

logger = logging.getLogger(__name__)


class ResponseService:
    def __init__(
        self,
        firewall_action_repo: FirewallActionRepository,
        threat_alert_repo: ThreatAlertRepository,
        alert_service: AlertService,
    ) -> None:
        self.firewall_action_repo = firewall_action_repo
        self.threat_alert_repo = threat_alert_repo
        self.alert_service = alert_service
        self.hub = get_websocket_hub()

    async def get_overview_stats(self) -> dict:
        """Aggregate stats for the Response Center dashboard."""
        from app.core.config import get_settings
        settings = get_settings()
        include_demo = settings.ENABLE_DEMO_MODE

        alert_stats = await self.threat_alert_repo.get_stats(include_demo=include_demo)
        active_threats = alert_stats.get("open_alerts", 0) + alert_stats.get("investigating_alerts", 0)
        
        blocked_ips = await self.firewall_action_repo.get_blocked_ips(include_demo=include_demo)
        
        # Simple count of all actions
        total_actions = await self.firewall_action_repo.count(include_demo=include_demo)

        return {
            "active_threats": active_threats,
            "blocked_ips": len(blocked_ips),
            "total_actions": total_actions,
        }

    async def get_threat_queue(self, page: int = 1, page_size: int = 50) -> tuple[list[dict], int]:
        """Get paginated list of OPEN and INVESTIGATING threats."""
        offset = (page - 1) * page_size
        from app.core.config import get_settings
        settings = get_settings()
        from app.database.client import db_has_demo_columns
        
        query = (
            self.threat_alert_repo._db.table(self.threat_alert_repo._table)
            .select("*", count="exact")
        )
        if db_has_demo_columns():
            if not settings.ENABLE_DEMO_MODE:
                query = query.eq("is_demo", False)
        
        query = (
            query.in_("status", ["OPEN", "INVESTIGATING"])
            .order("created_at", desc=True)
            .range(offset, offset + page_size - 1)
        )
        try:
            result = await query.execute()
            rows = result.data or []
            total = result.count or 0
            
            if settings.ENABLE_DEMO_MODE and not db_has_demo_columns():
                from app.repositories.base import _in_memory_demo_store
                demo_rows = [
                    r for r in _in_memory_demo_store.get("threat_alerts", [])
                    if r.get("status") in ["OPEN", "INVESTIGATING"]
                ]
                rows.extend(demo_rows)
                rows = sorted(rows, key=lambda x: x.get("created_at", ""), reverse=True)
                total += len(demo_rows)
                rows = rows[offset:offset + page_size]
                
            return rows, total
        except Exception as exc:
            logger.exception("Failed to get threat queue: %s", exc)
            return [], 0

    async def block_ip(self, ip: str, user_id: uuid.UUID, reason: Optional[str] = None) -> Optional[dict]:
        """Block an IP, log it, and broadcast."""
        # Idempotency check: see if there's already a BLOCK action for this IP
        existing = await self.firewall_action_repo._db.table(self.firewall_action_repo._table)\
            .select("*").eq("ip", ip).eq("action", "BLOCK").execute()
        if existing and existing.data:
            from fastapi import HTTPException
            raise HTTPException(status_code=409, detail="IP is already blocked")
            
        now = datetime.now(timezone.utc).isoformat()
        
        # 1. Insert Firewall Action
        action_data = {
            "ip": ip,
            "action": "BLOCK",
            "reason": reason,
            "source": "USER",
            "created_at": now
        }
        action_record = await self.firewall_action_repo.insert(action_data)
        
        if not action_record:
            return None
            
        # 2. Insert Audit Log
        audit_data = {
            "user_id": str(user_id) if user_id else None,
            "action": "BLOCK",
            "resource": "RESPONSE",
            "resource_id": action_record.get("id"),
            "ip_address": ip,
            "payload": {"reason": reason},
            "created_at": now
        }
        await self.firewall_action_repo._db.table("audit_logs").insert(audit_data).execute()
        
        # 3. Broadcast
        await self.hub.broadcast("blocked_ip_added", {"ip": ip, "reason": reason})
        await self.hub.broadcast("response_action_created", {"ip": ip, "action": "BLOCK"})
        await self.hub.broadcast("analytics_updated", {})
        
        return action_record

    async def unblock_ip(self, ip: str, user_id: uuid.UUID, reason: Optional[str] = None) -> Optional[dict]:
        """Unblock an IP, log it, and broadcast."""
        now = datetime.now(timezone.utc).isoformat()
        
        action_data = {
            "ip": ip,
            "action": "UNBLOCK",
            "reason": reason,
            "source": "USER",
            "created_at": now
        }
        action_record = await self.firewall_action_repo.insert(action_data)
        
        if not action_record:
            return None
            
        audit_data = {
            "user_id": str(user_id) if user_id else None,
            "action": "UNBLOCK",
            "resource": "RESPONSE",
            "resource_id": action_record.get("id"),
            "ip_address": ip,
            "payload": {"reason": reason},
            "created_at": now
        }
        await self.firewall_action_repo._db.table("audit_logs").insert(audit_data).execute()
        
        await self.hub.broadcast("blocked_ip_removed", {"ip": ip, "reason": reason})
        await self.hub.broadcast("response_action_created", {"ip": ip, "action": "UNBLOCK"})
        await self.hub.broadcast("analytics_updated", {})
        
        return action_record

    async def investigate_threat(self, alert_id: str) -> Optional[dict]:
        """Update threat status to INVESTIGATING."""
        updated = await self.alert_service.update_status(alert_id, "INVESTIGATING", "Moved to investigation")
        if updated:
            now = datetime.now(timezone.utc).isoformat()
            audit_data = {
                "action": "INVESTIGATE",
                "resource": "RESPONSE",
                "resource_id": alert_id,
                "ip_address": updated.get("source_ip"),
                "created_at": now
            }
            await self.firewall_action_repo._db.table("audit_logs").insert(audit_data).execute()
        return updated

    async def resolve_threat(self, alert_id: str, user_id: uuid.UUID, notes: Optional[str] = None) -> Optional[dict]:
        """Update threat status to RESOLVED."""
        updated = await self.alert_service.update_status(alert_id, "RESOLVED", notes)
        if updated:
            now = datetime.now(timezone.utc).isoformat()
            audit_data = {
                "user_id": str(user_id) if user_id else None,
                "action": "RESOLVE",
                "resource": "RESPONSE",
                "resource_id": alert_id,
                "ip_address": updated.get("source_ip"),
                "payload": {"notes": notes} if notes else {},
                "created_at": now
            }
            await self.firewall_action_repo._db.table("audit_logs").insert(audit_data).execute()
        return updated

    async def ignore_threat(self, alert_id: str, user_id: uuid.UUID, notes: Optional[str] = None) -> Optional[dict]:
        """Update threat status to FALSE_POSITIVE."""
        updated = await self.alert_service.update_status(alert_id, "FALSE_POSITIVE", notes)
        if updated:
            now = datetime.now(timezone.utc).isoformat()
            audit_data = {
                "user_id": str(user_id) if user_id else None,
                "action": "IGNORE",
                "resource": "RESPONSE",
                "resource_id": alert_id,
                "ip_address": updated.get("source_ip"),
                "payload": {"notes": notes} if notes else {},
                "created_at": now
            }
            await self.firewall_action_repo._db.table("audit_logs").insert(audit_data).execute()
        return updated

    async def get_action_history(self, page: int = 1, page_size: int = 50) -> tuple[list[dict], int]:
        """Get paginated firewall actions and response actions."""
        # Read from audit_logs so RESOLVE, IGNORE, BLOCK are all shown in Action History
        offset = (page - 1) * page_size
        count_res = await self.firewall_action_repo._db.table("audit_logs").select("*", count="exact").eq("resource", "RESPONSE").execute()
        total = count_res.count if count_res and hasattr(count_res, 'count') and count_res.count is not None else 0
        
        data_res = await self.firewall_action_repo._db.table("audit_logs").select("*, profiles!left(display_name)").eq("resource", "RESPONSE").order("created_at", desc=True).range(offset, offset + page_size - 1).execute()
        items = data_res.data if data_res else []
        
        mapped_items = []
        for item in items:
            payload = item.get("payload") or {}
            profile = item.get("profiles") or {}
            analyst_name = profile.get("display_name") if profile else None

            mapped_items.append({
                "id": str(item.get("id")),
                "ip": item.get("ip_address") or "Unknown",
                "action": item.get("action"),
                "reason": payload.get("reason") or payload.get("notes"),
                "analyst_name": analyst_name,
                "status": "SUCCESS",
                "created_at": item.get("created_at"),
                "recorded": True,
                "enforced": False,
                "note": payload.get("notes"),
                "message": "Action recorded but not enforced at OS level."
            })
        return mapped_items, total

    async def get_audit_log(self, page: int = 1, page_size: int = 50) -> tuple[list[dict], int]:
        """Get paginated audit logs for Response Center."""
        offset = (page - 1) * page_size
        
        # Get count
        count_res = await (
            self.firewall_action_repo._db.table("audit_logs")
            .select("*", count="exact")
            .eq("resource", "RESPONSE")
            .execute()
        )
        total = count_res.count if count_res and hasattr(count_res, 'count') and count_res.count is not None else 0
        
        # Get data
        data_res = await (
            self.firewall_action_repo._db.table("audit_logs")
            .select("*")
            .eq("resource", "RESPONSE")
            .order("created_at", desc=True)
            .range(offset, offset + page_size - 1)
            .execute()
        )
        items = data_res.data if data_res else []
        
        # Map back to what schema expects
        for item in items:
            item["target_ip"] = item.get("ip_address", "Unknown")
            item["user_name"] = str(item.get("user_id") or "System")
            payload = item.get("payload") or {}
            item["reason"] = payload.get("reason") or payload.get("notes")
            item["details"] = payload
        
        return items, total
