import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from supabase import AsyncClient
from .analytics_service import AnalyticsService
from .export_service import ExportService

logger = logging.getLogger(__name__)

class ReportService:
    def __init__(self, db: AsyncClient):
        self._db = db
        self.analytics = AnalyticsService(db)
        self.export = ExportService(db, self.analytics)

    async def get_dashboard_data(self, time_range: str) -> Dict[str, Any]:
        """Returns all dashboard components combined to reduce API calls."""
        return await self.export.generate_json(time_range)

    async def create_snapshot(self, time_range: str) -> Optional[Dict[str, Any]]:
        """Generates a snapshot and saves it to report_snapshots."""
        try:
            data = await self.get_dashboard_data(time_range)
            kpis = data.get("kpis", {})
            snapshot = {
                "generated_at": data["generated_at"],
                "time_range": time_range,
                "total_threats": kpis.get("total_threats", 0),
                "critical_threats": kpis.get("critical_threats", 0),
                "blocked_ips": kpis.get("blocked_ips", 0),
                "report_json": data
            }
            res = await self._db.table("report_snapshots").insert(snapshot).execute()
            if res.data:
                return res.data[0]
            return None
        except Exception as e:
            logger.exception("create_snapshot failed: %s", e)
            return None

    async def get_snapshots(self) -> list:
        try:
            res = await self._db.table("report_snapshots").select("id, generated_at, time_range, total_threats, critical_threats, blocked_ips").order("generated_at", desc=True).limit(50).execute()
            return res.data
        except Exception as e:
            logger.exception("get_snapshots failed: %s", e)
            return []
