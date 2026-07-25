import json
import logging
from typing import Any

from app.core.config import get_settings
from app.services.packet_capture.capture_service import get_capture_service

logger = logging.getLogger(__name__)


class ContextBuilder:
    FLOW_LIMIT = 10
    ALERT_LIMIT = 5
    PACKET_ID_LIMIT = 8

    async def build(self, db, intent: str, user_input: str) -> dict:
        """Build bounded, authoritative context without making repositories mandatory."""
        context = self._live_context()
        threat_rows = await self._recent_threats(db)
        context["recent_flows"] = self._merge_recent_flows(
            context.pop("_completed_flows", []), threat_rows
        )
        context["recent_alerts"] = [self._alert_summary(row) for row in threat_rows[: self.ALERT_LIMIT]]
        context["suspicious_ips"] = self._suspicious_ips(threat_rows)
        context["monitoring_assessment"] = self._monitoring_assessment(context)
        return self._bounded(context)

    def _live_context(self) -> dict:
        try:
            capture = get_capture_service()
            status = capture.get_status()
            analysis = status.get("analysis") or {}
            flow_stats = status.get("flows") or {}
            state = str(status.get("state") or "stopped").lower()
            completed = capture.flow_manager.get_recent_completed(self.FLOW_LIMIT)
            return {
                "capture_state": state,
                "monitoring_active": state in {"running", "replay"},
                "interface": status.get("interface"),
                "captured_count": status.get("packets_captured", 0),
                "analyzed_count": analysis.get("analyzed_packets", 0),
                "pending_count": analysis.get("pending_packets", 0),
                "deferred_count": analysis.get("deferred_packets", 0),
                "cancelled_count": analysis.get("cancelled_packets", 0),
                "failed_count": analysis.get("failed_packets", 0),
                "packet_rate": status.get("packets_per_second", 0.0),
                "analysis_queue": {
                    "depth": analysis.get("queue_depth", 0),
                    "capacity": analysis.get("queue_capacity", 0),
                },
                "_completed_flows": [item.model_dump() for item in completed],
                "live_context_available": True,
            }
        except Exception as exc:
            logger.warning("Copilot live context unavailable | type=%s", type(exc).__name__)
            return {
                "capture_state": "unavailable",
                "monitoring_active": False,
                "live_context_available": False,
                "_completed_flows": [],
            }

    async def _recent_threats(self, db) -> list[dict]:
        try:
            result = (
                await db.table("threat_scores")
                .select("*")
                .order("scored_at", desc=True)
                .limit(self.FLOW_LIMIT)
                .execute()
            )
            return result.data or []
        except Exception as exc:
            logger.warning("Copilot optional threat context unavailable | type=%s", type(exc).__name__)
            return []

    def _merge_recent_flows(self, flows: list[dict], threats: list[dict]) -> list[dict]:
        summaries: list[dict] = []
        for flow in flows[: self.FLOW_LIMIT]:
            threat = next(
                (row for row in threats if row.get("source_ip") == flow.get("src_ip")),
                {},
            )
            summaries.append({
                "flow_id": flow.get("flow_id") or threat.get("flow_id"),
                "packet_ids": list(threat.get("packet_ids") or [])[: self.PACKET_ID_LIMIT],
                "source_ip": flow.get("src_ip") or threat.get("source_ip"),
                "destination_ip": flow.get("dst_ip") or threat.get("destination_ip"),
                "source_port": flow.get("src_port") or threat.get("source_port"),
                "destination_port": flow.get("dst_port") or threat.get("destination_port"),
                "protocol": flow.get("protocol") or threat.get("protocol"),
                "model1": {
                    "result": threat.get("model1_classification") or threat.get("model1_prediction"),
                    "confidence": threat.get("model1_confidence") or threat.get("model1_score"),
                },
                "model2": {
                    "anomaly_score": threat.get("model2_anomaly_score") or threat.get("model2_score"),
                    "normalized_score": threat.get("model2_normalized_score"),
                },
                "model3": {
                    "available": threat.get("model3_available"),
                    "intelligence_score": threat.get("model3_intel_score") or threat.get("model3_score"),
                },
                "analysis_status": threat.get("analysis_status") or "unavailable",
                "threat_score": threat.get("threat_score"),
                "severity": threat.get("severity"),
                "action": threat.get("recommendation") or threat.get("action"),
            })
        return summaries

    @staticmethod
    def _alert_summary(row: dict) -> dict:
        return {
            "alert_id": row.get("alert_id") or row.get("id"),
            "source_ip": row.get("source_ip"),
            "severity": row.get("severity"),
            "threat_score": row.get("threat_score"),
            "analysis_status": row.get("analysis_status"),
            "action": row.get("recommendation") or row.get("action"),
        }

    @staticmethod
    def _suspicious_ips(rows: list[dict]) -> list[dict]:
        result = []
        seen = set()
        for row in rows:
            ip = row.get("source_ip")
            severity = str(row.get("severity") or "").lower()
            if ip and ip not in seen and severity in {"medium", "high", "critical"}:
                seen.add(ip)
                result.append({"ip": ip, "severity": row.get("severity"), "score": row.get("threat_score")})
            if len(result) == 5:
                break
        return result

    @staticmethod
    def _monitoring_assessment(context: dict) -> str:
        if not context.get("live_context_available"):
            return "live_context_unavailable"
        if not context.get("monitoring_active"):
            return "monitoring_inactive_no_current_safety_conclusion"
        if context.get("pending_count", 0) > 0 and not context.get("recent_flows"):
            return "monitoring_active_analysis_pending"
        statuses = {
            str(flow.get("analysis_status") or "").lower()
            for flow in context.get("recent_flows", [])
        }
        if statuses.intersection({"partial", "failed", "unavailable"}):
            return "analysis_incomplete"
        if "complete" in statuses:
            return "completed_analysis_available"
        return "monitoring_active_no_completed_analysis"

    def _bounded(self, context: dict) -> dict:
        max_chars = get_settings().COPILOT_CONTEXT_MAX_CHARS
        if len(json.dumps(context, default=str)) <= max_chars:
            return context
        context["recent_flows"] = context.get("recent_flows", [])[:5]
        context["recent_alerts"] = context.get("recent_alerts", [])[:3]
        return context
