import json
import logging
from collections import Counter
from typing import Any

from app.core.config import get_settings
from app.services.packet_capture.capture_service import get_capture_service
from app.services.threat_response.alert_service import AlertService
from app.services.websocket.connection_manager import get_websocket_hub

logger = logging.getLogger(__name__)


class ContextBuilder:
    FLOW_LIMIT = 10
    ALERT_LIMIT = 5
    ACTION_LIMIT = 10
    PACKET_ID_LIMIT = 8
    QUERY_LIMIT = 20

    async def build(self, db, intent: str, user_input: str) -> dict:
        """Build bounded, authoritative context without making storage mandatory."""
        context = self._live_context()
        session_id = context.get("session_id")
        live_analysis_rows = get_websocket_hub().get_recent_analysis_context(
            self.FLOW_LIMIT,
            str(session_id) if session_id else None,
        )
        packet_rows, packet_context_available = await self._recent_packet_analyses(
            db, session_id
        )
        threat_rows, threat_context_available = await self._recent_threats(
            db, session_id
        )
        alert_rows, alerts_available = await self._recent_alerts(db)
        action_rows, actions_available = await self._recent_actions(db)

        completed_flows = context.pop("_completed_flows", [])
        context["recent_flows"] = self._merge_recent_flows(
            completed_flows,
            live_analysis_rows,
            packet_rows,
            threat_rows,
        )
        context["latest_analyzed_flow"] = next(
            (
                flow
                for flow in context["recent_flows"]
                if flow.get("analysis_status") in {"complete", "partial"}
            ),
            None,
        )
        context["live_analysis_context_available"] = bool(live_analysis_rows)
        context["packet_analysis_context_available"] = packet_context_available
        context["threat_score_context_available"] = threat_context_available

        recent_alert_rows = alert_rows[: self.ALERT_LIMIT]
        open_alert_rows = [
            row
            for row in alert_rows
            if str(row.get("status") or "").upper() in {"OPEN", "INVESTIGATING"}
        ][: self.ALERT_LIMIT]
        alert_summaries = [
            self._alert_summary(row)
            for row in recent_alert_rows
        ]
        context["recent_alerts"] = alert_summaries
        context["open_alerts"] = [
            self._alert_summary(row)
            for row in open_alert_rows
        ]
        context["unresolved_alerts_shown"] = len(context["open_alerts"])
        context["latest_alert"] = (
            self._alert_summary(alert_rows[0]) if alert_rows else None
        )
        context["latest_suspicious_or_malicious_alert"] = next(
            (
                self._alert_summary(row)
                for row in alert_rows
                if str(row.get("severity") or "").upper() in {"HIGH", "CRITICAL"}
            ),
            None,
        )
        context["recent_response_actions"] = [
            self._action_summary(row)
            for row in self._prioritize_rows(action_rows, user_input)[
                : self.ACTION_LIMIT
            ]
        ]
        context["alert_context_available"] = alerts_available
        context["response_action_context_available"] = actions_available
        context["suspicious_ips"] = self._suspicious_ips(alert_rows)
        context["monitoring_assessment"] = self._monitoring_assessment(context)
        context["report_guidance"] = {
            "summary_included": False,
            "exports_included": False,
            "can_direct_user_to_reports": True,
            "export_performed": False,
        }
        return self._bounded(context)

    def _live_context(self) -> dict:
        try:
            capture = get_capture_service()
            status = capture.get_status()
            analysis = status.get("analysis") or {}
            flow_stats = status.get("flows") or {}
            state = str(status.get("state") or "stopped").lower()
            captured = self._count(status.get("packets_captured"))
            complete = self._count(analysis.get("completed_packets"))
            partial = self._count(analysis.get("partial_packets"))
            analyzed = complete + partial
            failed = self._count(analysis.get("failed_packets"))
            deferred = self._count(analysis.get("deferred_packets"))
            cancelled = self._count(analysis.get("cancelled_packets"))
            pending = self._count(analysis.get("pending_packets"))
            not_analyzed = max(
                captured
                - analyzed
                - failed
                - deferred
                - cancelled
                - pending,
                0,
            )
            monitoring_active = state in {"running", "replay"}
            session_id = status.get("session_id")
            completed_flows = capture.flow_manager.get_recent_completed(
                self.FLOW_LIMIT
            )
            get_active_flows = getattr(
                capture.flow_manager,
                "get_active_flows",
                None,
            )
            active_flows = (
                get_active_flows() if callable(get_active_flows) else []
            )
            flow_records: list[dict] = []
            seen_flow_ids: set[str] = set()
            for item in [*active_flows, *completed_flows]:
                record = item.model_dump()
                flow_id = str(record.get("flow_id") or "")
                if flow_id and flow_id not in seen_flow_ids:
                    seen_flow_ids.add(flow_id)
                    flow_records.append(record)
            return {
                "capture_state": state,
                "capture_mode": (
                    "replay"
                    if state == "replay"
                    else "live"
                    if state in {"running", "starting", "stopping"}
                    else "inactive"
                ),
                "session_id": session_id,
                "session_scope": (
                    "current_session"
                    if monitoring_active
                    else "last_in_memory_session"
                    if session_id and captured > 0
                    else "no_session"
                ),
                "last_session_memory_only": bool(
                    not monitoring_active and session_id and captured > 0
                ),
                "monitoring_active": monitoring_active,
                "interface": status.get("interface"),
                "captured_count": captured,
                "analyzed_count": analyzed,
                "complete_count": complete,
                "partial_count": partial,
                "pending_count": pending,
                "failed_count": failed,
                "deferred_count": deferred,
                "cancelled_count": cancelled,
                "not_analyzed_count": not_analyzed,
                "packet_rate": (
                    status.get("packets_per_second", 0.0)
                    if monitoring_active
                    else 0.0
                ),
                "analysis_queue": {
                    "depth": self._count(analysis.get("queue_depth")),
                    "capacity": self._count(analysis.get("queue_capacity")),
                },
                "last_reliable_score": flow_stats.get("last_reliable_score"),
                "highest_severity": flow_stats.get("highest_severity"),
                "_completed_flows": flow_records,
                "live_context_available": True,
            }
        except Exception as exc:
            logger.warning(
                "Copilot live context unavailable | type=%s",
                type(exc).__name__,
            )
            return {
                "capture_state": "unavailable",
                "capture_mode": "unavailable",
                "monitoring_active": False,
                "live_context_available": False,
                "_completed_flows": [],
            }

    async def _recent_packet_analyses(
        self, db, session_id: Any
    ) -> tuple[list[dict], bool]:
        try:
            query = db.table("packets").select("*")
            if session_id:
                query = query.eq("session_id", str(session_id))
            result = await (
                query.order("captured_at", desc=True)
                .limit(self.QUERY_LIMIT)
                .execute()
            )
            return result.data or [], True
        except Exception as exc:
            logger.warning(
                "Copilot packet analysis context unavailable | type=%s",
                type(exc).__name__,
            )
            return [], False

    async def _recent_threats(
        self, db, session_id: Any
    ) -> tuple[list[dict], bool]:
        try:
            query = db.table("threat_scores").select("*")
            if session_id:
                query = query.eq("session_id", str(session_id))
            result = await (
                query.order("scored_at", desc=True)
                .limit(self.FLOW_LIMIT)
                .execute()
            )
            return result.data or [], True
        except Exception as exc:
            logger.warning(
                "Copilot optional threat context unavailable | type=%s",
                type(exc).__name__,
            )
            return [], False

    async def _recent_alerts(self, db) -> tuple[list[dict], bool]:
        try:
            result = await (
                db.table("threat_alerts")
                .select(
                    "alert_id,source_ip,severity,action,status,threat_score,"
                    "summary,explanation,model1_classification,model1_score,"
                    "model2_score,model3_score,timeline,created_at,updated_at"
                )
                .order("updated_at", desc=True)
                .limit(self.QUERY_LIMIT)
                .execute()
            )
            return result.data or [], True
        except Exception as exc:
            logger.warning(
                "Copilot alert context unavailable | type=%s",
                type(exc).__name__,
            )
            return [], False

    async def _recent_actions(self, db) -> tuple[list[dict], bool]:
        try:
            result = await (
                db.table("audit_logs")
                .select(
                    "id,action,resource_id,ip_address,payload,user_id,created_at"
                )
                .eq("resource", "RESPONSE")
                .order("created_at", desc=True)
                .limit(self.ACTION_LIMIT)
                .execute()
            )
            return result.data or [], True
        except Exception as exc:
            logger.warning(
                "Copilot response context unavailable | type=%s",
                type(exc).__name__,
            )
            return [], False

    def _merge_recent_flows(
        self,
        flows: list[dict],
        live_analysis: list[dict],
        packets: list[dict],
        threats: list[dict],
    ) -> list[dict]:
        live_by_flow = {
            str(row.get("flow_id")): row
            for row in live_analysis
            if row.get("flow_id")
        }
        packet_by_flow = {
            str(row.get("flow_id")): row
            for row in packets
            if row.get("flow_id")
        }
        flow_source_counts = Counter(
            str(flow.get("src_ip"))
            for flow in flows
            if flow.get("src_ip")
        )
        threat_source_counts = Counter(
            str(row.get("source_ip"))
            for row in threats
            if row.get("source_ip")
        )
        threat_by_source = {
            str(row.get("source_ip")): row
            for row in threats
            if row.get("source_ip")
        }

        flow_by_id = {
            str(flow.get("flow_id")): flow
            for flow in flows
            if flow.get("flow_id")
        }
        ordered_flows: list[dict] = []
        seen: set[str] = set()
        for row in live_analysis:
            flow_id = str(row.get("flow_id") or "")
            if flow_id and flow_id not in seen:
                seen.add(flow_id)
                ordered_flows.append(flow_by_id.get(flow_id, row))
        for flow in flows:
            flow_id = str(flow.get("flow_id") or "")
            if flow_id and flow_id not in seen:
                seen.add(flow_id)
                ordered_flows.append(flow)

        summaries: list[dict] = []
        for flow in ordered_flows[: self.FLOW_LIMIT]:
            flow_id = str(flow.get("flow_id") or "")
            evidence = live_by_flow.get(flow_id) or packet_by_flow.get(
                flow_id, {}
            )
            source_ip = flow.get("src_ip")
            if (
                not evidence
                and source_ip
                and flow_source_counts[str(source_ip)] == 1
                and threat_source_counts[str(source_ip)] == 1
            ):
                evidence = threat_by_source.get(str(source_ip), {})

            model1 = evidence.get("model1")
            if not isinstance(model1, dict):
                model1 = {}
            model2 = evidence.get("model2")
            if not isinstance(model2, dict):
                model2 = {}
            model3 = evidence.get("model3")
            if not isinstance(model3, dict):
                model3 = {}
            model3_available = evidence.get("model3_available")
            model3_score = self._first_present(
                evidence,
                "model3_intelligence_score",
                "model3_intel_score",
                "model3_score",
            )
            summaries.append(
                {
                    "flow_id": flow.get("flow_id"),
                    "packet_ids": list(evidence.get("packet_ids") or [])[
                        : self.PACKET_ID_LIMIT
                    ],
                    "source_ip": flow.get("src_ip"),
                    "destination_ip": flow.get("dst_ip"),
                    "source_port": flow.get("src_port"),
                    "destination_port": flow.get("dst_port"),
                    "protocol": flow.get("protocol"),
                    "total_packets": flow.get("total_packets"),
                    "ended_at": flow.get("ended_at"),
                    "model1": {
                        "result": self._first_present(
                            evidence,
                            "model1_classification",
                            "model1_prediction",
                            "ml_prediction",
                        )
                        or model1.get("classification"),
                        "confidence": self._first_present(
                            evidence,
                            "model1_confidence",
                            "model1_score",
                            "ml_confidence",
                        )
                        if self._first_present(
                            evidence,
                            "model1_confidence",
                            "model1_score",
                            "ml_confidence",
                        )
                        is not None
                        else model1.get("anomaly_probability"),
                    },
                    "model2": {
                        "anomaly_score": self._first_present(
                            evidence,
                            "model2_anomaly_score",
                            "model2_score",
                            "anomaly_score",
                        )
                        if self._first_present(
                            evidence,
                            "model2_anomaly_score",
                            "model2_score",
                            "anomaly_score",
                        )
                        is not None
                        else model2.get("anomaly_score"),
                        "normalized_score": evidence.get(
                            "model2_normalized_score"
                        ),
                    },
                    "model3": {
                        "available": model3_available,
                        "availability": (
                            "available"
                            if model3_available is True
                            else "unavailable"
                            if model3_available is False
                            else "unknown"
                        ),
                        "intelligence_score": model3_score,
                        "reputation": model3.get("reputation"),
                    },
                    "analysis_status": (
                        evidence.get("analysis_status") or "unavailable"
                    ),
                    "threat_score": evidence.get("threat_score"),
                    "severity": evidence.get("severity"),
                    "action": self._first_present(
                        evidence,
                        "recommendation",
                        "action",
                    ),
                }
            )
        return summaries

    @staticmethod
    def _alert_summary(row: dict) -> dict:
        identity = AlertService.extract_identity(row)
        return {
            "alert_id": row.get("alert_id") or row.get("id"),
            "source_ip": row.get("source_ip"),
            "severity": row.get("severity"),
            "threat_score": row.get("threat_score"),
            "status": row.get("status"),
            "recommended_action": row.get("action"),
            "threat_type": row.get("model1_classification"),
            "summary": ContextBuilder._short_text(row.get("summary"), 800),
            "analysis_status": identity.get("analysis_status"),
            "flow_id": identity.get("flow_id"),
            "session_id": identity.get("session_id"),
            "destination_ip": identity.get("destination_ip"),
            "protocol": identity.get("protocol"),
            "model_evidence": {
                "model1_classification": row.get("model1_classification"),
                "model1_score": row.get("model1_score"),
                "model2_score": row.get("model2_score"),
                "model3_score": row.get("model3_score"),
            },
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at"),
        }

    @staticmethod
    def _action_summary(row: dict) -> dict:
        payload = row.get("payload")
        if not isinstance(payload, dict):
            payload = {}
        action = str(row.get("action") or "").upper()
        enforced = payload.get("enforced")
        is_firewall_action = action in {"BLOCK", "UNBLOCK", "WHITELIST"}
        return {
            "action_id": row.get("id"),
            "alert_id": row.get("resource_id"),
            "target_ip": row.get("ip_address"),
            "action": action or None,
            "recorded": payload.get("recorded", True),
            "enforced": enforced,
            "enforcement_status": (
                "enforced"
                if enforced is True
                else "not_enforced"
                if is_firewall_action
                else "not_applicable"
            ),
            "status": (
                payload.get("status")
                or "RECORDED_ONLY"
                if is_firewall_action
                else payload.get("status") or "RECORDED"
            ),
            "result": ContextBuilder._short_text(
                payload.get("result") or payload.get("message"),
                500,
            ),
            "platform": payload.get("platform"),
            "timestamp": row.get("created_at"),
        }

    @staticmethod
    def _prioritize_rows(rows: list[dict], user_input: str) -> list[dict]:
        text = user_input.lower()
        return sorted(
            rows,
            key=lambda row: (
                0
                if any(
                    str(value).lower() in text
                    for value in (
                        row.get("ip_address"),
                        row.get("resource_id"),
                        row.get("id"),
                    )
                    if value
                )
                else 1
            ),
        )

    @staticmethod
    def _suspicious_ips(rows: list[dict]) -> list[dict]:
        result = []
        seen = set()
        for row in rows:
            ip = row.get("source_ip")
            severity = str(row.get("severity") or "").lower()
            if (
                ip
                and ip not in seen
                and severity in {"medium", "high", "critical"}
            ):
                seen.add(ip)
                result.append(
                    {
                        "ip": ip,
                        "severity": row.get("severity"),
                        "score": row.get("threat_score"),
                        "alert_id": row.get("alert_id"),
                        "status": row.get("status"),
                    }
                )
            if len(result) == ContextBuilder.ALERT_LIMIT:
                break
        return result

    @staticmethod
    def _monitoring_assessment(context: dict) -> str:
        if not context.get("live_context_available"):
            return "live_context_unavailable"
        if not context.get("monitoring_active"):
            if context.get("session_scope") == "last_in_memory_session":
                return "monitoring_inactive_last_session_available_in_memory"
            return "monitoring_inactive_no_current_safety_conclusion"
        if context.get("pending_count", 0) > 0:
            return "monitoring_active_analysis_pending"
        statuses = {
            str(flow.get("analysis_status") or "").lower()
            for flow in context.get("recent_flows", [])
        }
        if "failed" in statuses:
            return "analysis_failed"
        if statuses.intersection({"partial", "unavailable", "unknown"}):
            return "analysis_incomplete"
        if "complete" in statuses:
            return "completed_analysis_available"
        return "monitoring_active_no_completed_analysis"

    def _bounded(self, context: dict) -> dict:
        max_chars = get_settings().COPILOT_CONTEXT_MAX_CHARS
        bounded = json.loads(json.dumps(context, default=str))
        if self._size(bounded) <= max_chars:
            return bounded

        bounded["recent_flows"] = bounded.get("recent_flows", [])[:5]
        bounded["recent_alerts"] = bounded.get("recent_alerts", [])[:3]
        bounded["open_alerts"] = bounded.get("open_alerts", [])[:3]
        bounded["recent_response_actions"] = bounded.get(
            "recent_response_actions", []
        )[:5]
        if self._size(bounded) <= max_chars:
            return bounded

        for text_limit in (500, 250, 120):
            bounded = self._truncate_strings(bounded, text_limit)
            if self._size(bounded) <= max_chars:
                return bounded

        bounded["recent_flows"] = bounded.get("recent_flows", [])[:1]
        bounded["recent_alerts"] = bounded.get("recent_alerts", [])[:1]
        bounded["open_alerts"] = bounded.get("open_alerts", [])[:1]
        bounded["recent_response_actions"] = bounded.get(
            "recent_response_actions", []
        )[:1]
        bounded["suspicious_ips"] = bounded.get("suspicious_ips", [])[:1]
        if self._size(bounded) > max_chars:
            bounded = {
                key: bounded.get(key)
                for key in (
                    "capture_state",
                    "capture_mode",
                    "session_scope",
                    "monitoring_active",
                    "interface",
                    "captured_count",
                    "analyzed_count",
                    "complete_count",
                    "partial_count",
                    "pending_count",
                    "failed_count",
                    "deferred_count",
                    "not_analyzed_count",
                    "packet_rate",
                    "last_reliable_score",
                    "highest_severity",
                    "live_context_available",
                    "monitoring_assessment",
                )
            }
        return bounded

    @staticmethod
    def _size(value: Any) -> int:
        return len(json.dumps(value, default=str, separators=(",", ":")))

    @classmethod
    def _truncate_strings(cls, value: Any, limit: int) -> Any:
        if isinstance(value, dict):
            return {
                key: cls._truncate_strings(item, limit)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls._truncate_strings(item, limit) for item in value]
        if isinstance(value, str) and len(value) > limit:
            return value[:limit] + "…"
        return value

    @staticmethod
    def _short_text(value: Any, limit: int) -> Any:
        if not isinstance(value, str) or len(value) <= limit:
            return value
        return value[:limit] + "…"

    @staticmethod
    def _first_present(row: dict, *keys: str) -> Any:
        for key in keys:
            if key in row and row[key] is not None:
                return row[key]
        return None

    @staticmethod
    def _count(value: Any) -> int:
        try:
            return max(int(value or 0), 0)
        except (TypeError, ValueError):
            return 0
