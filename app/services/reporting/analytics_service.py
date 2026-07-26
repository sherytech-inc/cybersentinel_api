import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
from supabase import AsyncClient
from app.core.config import get_settings

logger = logging.getLogger(__name__)

TIME_RANGES = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


@dataclass
class ReportRows:
    rows: list[dict] = field(default_factory=list)
    available: bool = True
    message: str | None = None


class AnalyticsService:
    def __init__(self, db: AsyncClient):
        self._db = db

    def _get_time_cutoff(self, time_range: str) -> str:
        """Returns the ISO-8601 cutoff string based on time_range (24h, 7d, 30d)."""
        now = datetime.now(timezone.utc)
        delta = TIME_RANGES.get(time_range, TIME_RANGES["24h"])
        return (now - delta).isoformat()

    async def _count_total_threats(self, time_range: str) -> int:
        cutoff = self._get_time_cutoff(time_range)
        query = self._db.table("threat_alerts").select("alert_id", count="exact").gte("created_at", cutoff)
        from app.database.client import db_has_demo_columns
        if db_has_demo_columns() and not get_settings().ENABLE_DEMO_MODE: query = query.neq("is_demo", True)
        res = await query.execute()
        return res.count or 0

    async def _count_active_threats(self) -> int:
        # Active threats are OPEN or INVESTIGATING
        query = self._db.table("threat_alerts").select("alert_id", count="exact").in_("status", ["OPEN", "INVESTIGATING"])
        from app.database.client import db_has_demo_columns
        from app.core.config import get_settings
        if db_has_demo_columns() and not get_settings().ENABLE_DEMO_MODE: query = query.neq("is_demo", True)
        res = await query.execute()
        count = res.count or 0
        if not db_has_demo_columns() and get_settings().ENABLE_DEMO_MODE:
            from app.repositories.base import _in_memory_demo_store
            count += sum(1 for t in _in_memory_demo_store.get("threat_alerts", []) if t.get("status") in ("OPEN", "INVESTIGATING"))
        return count

    async def _count_block_actions(self, time_range: str) -> int:
        cutoff = self._get_time_cutoff(time_range)
        query = self._db.table("firewall_actions").select("id", count="exact").eq("action", "BLOCK").gte("created_at", cutoff)
        from app.database.client import db_has_demo_columns
        if db_has_demo_columns() and not get_settings().ENABLE_DEMO_MODE: query = query.neq("is_demo", True)
        res = await query.execute()
        return res.count or 0

    async def _count_currently_blocked_ips(self) -> int:
        query = self._db.table("firewall_actions").select("ip, action, created_at").order("created_at", desc=False)
        from app.database.client import db_has_demo_columns
        if db_has_demo_columns() and not get_settings().ENABLE_DEMO_MODE: query = query.neq("is_demo", True)
        res = await query.execute()
        rows = res.data or []
        
        latest_actions: dict[str, str] = {}
        for row in rows:
            latest_actions[row["ip"]] = row["action"]
        return sum(1 for action in latest_actions.values() if action == "BLOCK")

    async def _count_response_actions(self, time_range: str) -> int:
        cutoff = self._get_time_cutoff(time_range)
        from app.database.client import db_has_demo_columns
        
        # firewall actions
        fw_query = self._db.table("firewall_actions").select("id", count="exact").in_("action", ["BLOCK", "UNBLOCK"]).gte("created_at", cutoff)
        if db_has_demo_columns() and not get_settings().ENABLE_DEMO_MODE: fw_query = fw_query.neq("is_demo", True)
        fw_res = await fw_query.execute()
        fw_count = fw_res.count or 0
        
        # audit logs for RESOLVE / IGNORE
        # audit logs may not have is_demo column, but threat_alerts does. 
        # Since audit logs don't have is_demo column (we didn't add it in phase 11 to audit_logs), we just query it normally
        audit_res = await self._db.table("audit_logs").select("id", count="exact").eq("resource", "RESPONSE").in_("action", ["RESOLVE", "IGNORE"]).gte("created_at", cutoff).execute()
        audit_count = audit_res.count or 0

        return fw_count + audit_count

    async def _count_critical_threats(self, time_range: str) -> int:
        cutoff = self._get_time_cutoff(time_range)
        query = self._db.table("threat_alerts").select("alert_id", count="exact").eq("severity", "CRITICAL").gte("created_at", cutoff)
        from app.database.client import db_has_demo_columns
        if db_has_demo_columns() and not get_settings().ENABLE_DEMO_MODE: query = query.neq("is_demo", True)
        res = await query.execute()
        return res.count or 0

    async def get_kpis(self, time_range: str) -> Dict[str, Any]:
        try:
            return {
                "total_threats": await self._count_total_threats(time_range),
                "critical_threats": await self._count_critical_threats(time_range),
                "response_actions": await self._count_response_actions(time_range),
                "recorded_blocks": await self._count_block_actions(time_range),
                "os_enforced_blocks": 0
            }
        except Exception as e:
            logger.warning("Reporting KPIs unavailable: %s", type(e).__name__)
            return {"total_threats": 0, "critical_threats": 0, "response_actions": 0, "recorded_blocks": 0, "os_enforced_blocks": 0}

    async def get_threat_trends(self, time_range: str) -> List[Dict[str, Any]]:
        cutoff = self._get_time_cutoff(time_range)
        try:
            query = self._db.table("threat_alerts").select("created_at").gte("created_at", cutoff).order("created_at")
            from app.database.client import db_has_demo_columns
            if db_has_demo_columns() and not get_settings().ENABLE_DEMO_MODE: query = query.neq("is_demo", True)
            res = await query.execute()
            data = res.data
            # Group by hour/day based on time_range
            trends = {}
            for row in data:
                dt = datetime.fromisoformat(row["created_at"].replace("Z", "+00:00"))
                if time_range == "24h":
                    key = dt.strftime("%Y-%m-%d %H:00")
                else:
                    key = dt.strftime("%Y-%m-%d")
                trends[key] = trends.get(key, 0) + 1
            
            result = [{"time": k, "count": v} for k, v in sorted(trends.items())]
            return result
        except Exception:
            logger.exception("get_threat_trends failed")
            return []

    async def get_severity_distribution(self, time_range: str) -> List[Dict[str, Any]]:
        cutoff = self._get_time_cutoff(time_range)
        try:
            query = self._db.table("threat_alerts").select("severity").gte("created_at", cutoff)
            from app.database.client import db_has_demo_columns
            if db_has_demo_columns() and not get_settings().ENABLE_DEMO_MODE: query = query.neq("is_demo", True)
            res = await query.execute()
            counts = {}
            for row in res.data:
                sev = row.get("severity", "UNKNOWN")
                counts[sev] = counts.get(sev, 0) + 1
            return [{"severity": k, "count": v} for k, v in counts.items()]
        except Exception:
            return []

    async def get_top_attackers(self, time_range: str) -> List[Dict[str, Any]]:
        import ipaddress
        cutoff = self._get_time_cutoff(time_range)
        try:
            query = self._db.table("threat_alerts").select("source_ip, severity").gte("created_at", cutoff)
            from app.database.client import db_has_demo_columns
            if db_has_demo_columns() and not get_settings().ENABLE_DEMO_MODE: query = query.neq("is_demo", True)
            res = await query.execute()
            ips = {}
            for row in res.data:
                ip = row["source_ip"]
                if ip not in ips:
                    ips[ip] = {"count": 0, "critical": False}
                ips[ip]["count"] += 1
                if row.get("severity") == "CRITICAL":
                    ips[ip]["critical"] = True
                    
            sorted_ips = sorted(ips.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
            
            top_attackers = []
            for ip, stats in sorted_ips:
                try:
                    if ipaddress.ip_address(ip).is_private:
                        country = "Internal"
                    else:
                        country = "Unknown"
                except ValueError:
                    country = "Unknown"
                    
                # get intel for this IP
                intel_res = await self._db.table("ip_intelligence").select("country").eq("ip_address", ip).execute()
                if intel_res.data and intel_res.data[0].get("country"):
                    country = intel_res.data[0]["country"]
                top_attackers.append({
                    "ip": ip,
                    "count": stats["count"],
                    "country": country,
                    "highest_severity": "CRITICAL" if stats["critical"] else "HIGH"
                })
            return top_attackers
        except Exception:
            logger.exception("get_top_attackers failed")
            return []
            
    async def get_top_threat_types(self, time_range: str) -> List[Dict[str, Any]]:
        cutoff = self._get_time_cutoff(time_range)
        try:
            query = self._db.table("threat_alerts").select("model1_classification").gte("created_at", cutoff)
            from app.database.client import db_has_demo_columns
            if db_has_demo_columns() and not get_settings().ENABLE_DEMO_MODE: query = query.neq("is_demo", True)
            res = await query.execute()
            counts = {}
            for row in res.data:
                ttype = row.get("model1_classification") or "Suspicious Traffic"
                counts[ttype] = counts.get(ttype, 0) + 1
            sorted_types = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:5]
            return [{"type": k, "count": v} for k, v in sorted_types]
        except Exception:
            return []

    async def get_intelligence_overview(self, time_range: str) -> Dict[str, Any]:
        # Uses last updated intelligence
        cutoff = self._get_time_cutoff(time_range)
        try:
            # Blacklisted IPs seen recently
            query = self._db.table("threat_alerts").select("source_ip").gte("created_at", cutoff)
            from app.database.client import db_has_demo_columns
            if db_has_demo_columns() and not get_settings().ENABLE_DEMO_MODE: query = query.neq("is_demo", True)
            alerts_res = await query.execute()
            unique_ips = list(set([r["source_ip"] for r in alerts_res.data]))
            
            blacklisted = 0
            asns = set()
            countries = set()
            malicious_sources = 0
            
            # chunking requests if large
            if unique_ips:
                intel_res = await self._db.table("ip_intelligence").select("ip_address, abuse_confidence_score, vt_malicious, asn, country").in_("ip_address", unique_ips).execute()
                for row in intel_res.data:
                    if row.get("abuse_confidence_score", 0) > 0 or row.get("vt_malicious", 0) > 0:
                        blacklisted += 1
                        if row.get("vt_malicious", 0) > 0:
                            malicious_sources += 1
                    if row.get("asn"):
                        asns.add(row["asn"])
                    if row.get("country"):
                        countries.add(row["country"])

            return {
                "blacklisted_ips_seen": blacklisted,
                "unique_asns": len(asns),
                "high_risk_countries": len(countries),
                "known_malicious_sources": malicious_sources
            }
        except Exception:
            logger.exception("get_intelligence_overview failed")
            return {"blacklisted_ips_seen": 0, "unique_asns": 0, "high_risk_countries": 0, "known_malicious_sources": 0}

    async def get_response_analytics(self, time_range: str) -> Dict[str, Any]:
        cutoff = self._get_time_cutoff(time_range)
        try:
            from app.database.client import db_has_demo_columns
            
            # blocks and unblocks
            fw_query = self._db.table("firewall_actions").select("action").gte("created_at", cutoff)
            if db_has_demo_columns() and not get_settings().ENABLE_DEMO_MODE: fw_query = fw_query.neq("is_demo", True)
            res_fw = await fw_query.execute()
            blocks = sum(1 for r in res_fw.data if r.get("action") == "BLOCK")
            unblocks = sum(1 for r in res_fw.data if r.get("action") == "UNBLOCK")
            
            # resolved and false positives
            alert_query = self._db.table("threat_alerts").select("status").gte("updated_at", cutoff)
            if db_has_demo_columns() and not get_settings().ENABLE_DEMO_MODE: alert_query = alert_query.neq("is_demo", True)
            res_alerts = await alert_query.execute()
            resolved = sum(1 for r in res_alerts.data if r.get("status") == "RESOLVED")
            false_pos = sum(1 for r in res_alerts.data if r.get("status") == "FALSE_POSITIVE")
            investigating = sum(1 for r in res_alerts.data if r.get("status") == "INVESTIGATING")

            return {
                "blocks": blocks,
                "unblocks": unblocks,
                "investigations": investigating,
                "resolved": resolved,
                "ignored": false_pos
            }
        except Exception:
            return {"blocks": 0, "unblocks": 0, "investigations": 0, "resolved": 0, "ignored": 0}

    async def get_incident_timeline(self, time_range: str) -> List[Dict[str, Any]]:
        cutoff = self._get_time_cutoff(time_range)
        try:
            from app.database.client import db_has_demo_columns
            
            alert_query = self._db.table("threat_alerts").select("created_at, summary").gte("created_at", cutoff).order("created_at", desc=True).limit(20)
            if db_has_demo_columns() and not get_settings().ENABLE_DEMO_MODE: alert_query = alert_query.neq("is_demo", True)
            alerts_res = await alert_query.execute()
            
            audit_res = await self._db.table("audit_logs").select("created_at, action, ip_address").eq("resource", "RESPONSE").gte("created_at", cutoff).order("created_at", desc=True).limit(20).execute()
            
            timeline = []
            for r in alerts_res.data:
                timeline.append({
                    "time": r["created_at"],
                    "event": f"Threat Detected: {r.get('summary', 'Unknown')}"
                })
            for r in audit_res.data:
                timeline.append({
                    "time": r["created_at"],
                    "event": f"Response: {r.get('action')} on {r.get('ip_address')}"
                })
                
            timeline.sort(key=lambda x: x["time"], reverse=True)
            return timeline[:20]
        except Exception:
            return []

    async def get_report_alerts(
        self,
        time_range: str = "24h",
        *,
        limit: int = 200,
    ) -> ReportRows:
        """Return recent alert evidence without turning failures into zero data."""
        cutoff = self._get_time_cutoff(time_range)
        try:
            query = (
                self._db.table("threat_alerts")
                .select(
                    "alert_id,created_at,source_ip,model1_classification,"
                    "severity,threat_score,status,action,summary"
                )
                .gte("created_at", cutoff)
                .order("created_at", desc=True)
                .limit(limit)
            )
            from app.database.client import db_has_demo_columns

            if db_has_demo_columns() and not get_settings().ENABLE_DEMO_MODE:
                query = query.neq("is_demo", True)
            result = await query.execute()
            return ReportRows(rows=result.data or [])
        except Exception as exc:
            logger.warning(
                "Report alert source unavailable | type=%s",
                type(exc).__name__,
            )
            return ReportRows(
                available=False,
                message="Recent alert data is temporarily unavailable.",
            )

    async def get_report_actions(
        self,
        time_range: str = "24h",
        *,
        limit: int = 200,
    ) -> ReportRows:
        """Combine recorded firewall and response-audit actions."""
        cutoff = self._get_time_cutoff(time_range)
        rows: list[dict] = []
        failures: list[str] = []

        try:
            query = (
                self._db.table("firewall_actions")
                .select("id,created_at,ip,action,reason,source")
                .gte("created_at", cutoff)
                .order("created_at", desc=True)
                .limit(limit)
            )
            from app.database.client import db_has_demo_columns

            if db_has_demo_columns() and not get_settings().ENABLE_DEMO_MODE:
                query = query.neq("is_demo", True)
            result = await query.execute()
            for item in result.data or []:
                rows.append(
                    {
                        "action_id": str(item.get("id") or ""),
                        "timestamp": item.get("created_at"),
                        "target": item.get("ip"),
                        "action": item.get("action") or "UNKNOWN",
                        "status": "RECORDED",
                        "analyst": item.get("source"),
                        "related_alert": None,
                        "result": item.get("reason"),
                        "platform": None,
                    }
                )
        except Exception as exc:
            failures.append("firewall")
            logger.warning(
                "Report firewall action source unavailable | type=%s",
                type(exc).__name__,
            )

        try:
            result = await (
                self._db.table("audit_logs")
                .select("id,created_at,ip_address,action,resource_id,payload,user_id")
                .eq("resource", "RESPONSE")
                .gte("created_at", cutoff)
                .order("created_at", desc=True)
                .limit(limit)
                .execute()
            )
            for item in result.data or []:
                payload = item.get("payload")
                if not isinstance(payload, dict):
                    payload = {}
                action = str(item.get("action") or "UNKNOWN").upper()
                rows.append(
                    {
                        "action_id": str(item.get("id") or ""),
                        "timestamp": item.get("created_at"),
                        "target": item.get("ip_address"),
                        "action": action,
                        "status": "RECORDED",
                        "analyst": (
                            str(item.get("user_id"))
                            if item.get("user_id")
                            else None
                        ),
                        "related_alert": item.get("resource_id"),
                        "result": (
                            payload.get("result")
                            or payload.get("message")
                            or payload.get("reason")
                            or payload.get("notes")
                        ),
                        "platform": payload.get("platform"),
                    }
                )
        except Exception as exc:
            failures.append("audit")
            logger.warning(
                "Report response audit source unavailable | type=%s",
                type(exc).__name__,
            )

        rows.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
        if failures:
            return ReportRows(
                rows=rows[:limit],
                available=False,
                message="Some response action data is temporarily unavailable.",
            )
        return ReportRows(rows=rows[:limit])

    async def enrich_attacker_countries(
        self,
        source_ips: list[str],
    ) -> ReportRows:
        """Return available country evidence for the supplied IP addresses."""
        if not source_ips:
            return ReportRows()
        try:
            result = await (
                self._db.table("ip_intelligence")
                .select("ip_address,country")
                .in_("ip_address", source_ips)
                .execute()
            )
            return ReportRows(rows=result.data or [])
        except Exception as exc:
            logger.warning(
                "Report intelligence source unavailable | type=%s",
                type(exc).__name__,
            )
            return ReportRows(
                available=False,
                message="IP intelligence enrichment is temporarily unavailable.",
            )
