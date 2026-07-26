"""Build truthful report summaries from live state and optional repositories."""

import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Optional

from supabase import AsyncClient

from app.schemas.reporting import (
    AttackerSummary,
    ClassificationDistribution,
    ModelAvailability,
    RecentAlertSummary,
    ReportSessionSummary,
    ReportSourceStatus,
    ReportSummary,
    ResponseTimelineEntry,
    SeverityDistribution,
    ThreatTypeSummary,
)
from .analytics_service import AnalyticsService, ReportRows
from .export_service import ExportService

logger = logging.getLogger(__name__)


class ReportDataUnavailable(RuntimeError):
    """Raised when a requested export cannot read its required source."""


def _non_negative(value: Any) -> int:
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def _bounded_partition(captured: int, *values: int) -> tuple[list[int], int]:
    remaining = captured
    normalized: list[int] = []
    for value in values:
        next_value = min(_non_negative(value), remaining)
        normalized.append(next_value)
        remaining -= next_value
    return normalized, remaining


class ReportService:
    def __init__(
        self,
        db: AsyncClient,
        *,
        analytics: Optional[AnalyticsService] = None,
        capture_service=None,
    ):
        self._db = db
        self.analytics = analytics or AnalyticsService(db)
        self._capture_service = capture_service
        self.export = ExportService(self.analytics)

    def _capture_status(self) -> tuple[dict, bool]:
        try:
            capture_service = self._capture_service
            if capture_service is None:
                from app.services.packet_capture.capture_service import (
                    get_capture_service,
                )

                capture_service = get_capture_service()
            return capture_service.get_status(), True
        except Exception as exc:
            logger.warning(
                "Report capture source unavailable | type=%s",
                type(exc).__name__,
            )
            return {}, False

    def _session_from_capture(
        self,
        status: dict,
        capture_available: bool,
    ) -> tuple[
        str,
        str,
        Optional[str],
        ReportSessionSummary,
        ClassificationDistribution,
        ModelAvailability,
        list[str],
    ]:
        if not capture_available:
            return (
                "unavailable",
                "inactive",
                None,
                ReportSessionSummary(),
                ClassificationDistribution(),
                ModelAvailability(),
                ["Live capture diagnostics are temporarily unavailable."],
            )

        raw_state = str(status.get("state") or "stopped").lower()
        session_id = str(status.get("session_id") or "").strip()
        captured = _non_negative(status.get("packets_captured"))
        analysis = status.get("analysis")
        if not isinstance(analysis, dict):
            analysis = {}
        flows = status.get("flows")
        if not isinstance(flows, dict):
            flows = {}

        if raw_state in {"running", "replay", "starting"}:
            timeframe = "current_session"
            monitoring_state = "running"
        elif raw_state == "stopping":
            timeframe = "current_session"
            monitoring_state = "stopping"
        elif session_id or captured > 0:
            timeframe = "last_session"
            monitoring_state = "stopped"
        else:
            timeframe = "unavailable"
            monitoring_state = "inactive"

        complete = _non_negative(analysis.get("completed_packets"))
        partial = _non_negative(analysis.get("partial_packets"))
        failed = _non_negative(analysis.get("failed_packets"))
        deferred = _non_negative(analysis.get("deferred_packets"))
        pending_requested = (
            0
            if monitoring_state in {"stopped", "inactive"}
            else _non_negative(analysis.get("pending_packets"))
        )
        partition, not_analyzed = _bounded_partition(
            captured,
            complete,
            partial,
            failed,
            deferred,
            pending_requested,
        )
        complete, partial, failed, deferred, pending = partition
        analyzed = complete + partial

        known_classification, unknown = _bounded_partition(
            analyzed,
            _non_negative(flows.get("normal_packets")),
            _non_negative(flows.get("suspicious_packets")),
            _non_negative(flows.get("malicious_packets")),
        )
        normal, suspicious, malicious = known_classification
        reported_unknown = _non_negative(flows.get("unknown_packets"))
        unknown = min(max(unknown, reported_unknown), analyzed - sum(known_classification))

        score = flows.get("last_reliable_score")
        if analyzed == 0 or not isinstance(score, (int, float)):
            score = None
        else:
            score = max(0.0, min(float(score), 100.0))
        highest_severity = (
            str(flows.get("highest_severity"))
            if analyzed > 0 and flows.get("highest_severity")
            else None
        )

        session = ReportSessionSummary(
            captured=captured,
            analyzed=analyzed,
            pending=pending,
            complete=complete,
            partial=partial,
            failed=failed,
            deferred=deferred,
            not_analyzed=not_analyzed,
            completion_percentage=(
                round(analyzed * 100.0 / captured, 2) if captured else 0.0
            ),
            threat_score=score,
            highest_severity=highest_severity,
        )
        distribution = ClassificationDistribution(
            normal=normal,
            suspicious=suspicious,
            malicious=malicious,
            unknown=unknown,
        )
        model_availability = ModelAvailability(
            model1_evaluated=analyzed,
            model2_evaluated=analyzed,
            model3_available=None,
            partial_analysis=partial,
            failed_analysis=failed,
        )
        messages: list[str] = []
        if timeframe == "unavailable":
            messages.append("No capture session data is available yet.")
        elif monitoring_state == "stopped":
            messages.append(
                "Session totals are retained only for the current application run."
            )
        if analyzed > 0:
            messages.append(
                "Model 3 availability is unavailable in aggregate capture diagnostics."
            )

        return (
            timeframe,
            monitoring_state,
            status.get("interface"),
            session,
            distribution,
            model_availability,
            messages,
        )

    async def get_summary(self) -> ReportSummary:
        capture_status, capture_available = self._capture_status()
        (
            timeframe,
            monitoring_state,
            interface_name,
            session,
            classification,
            model_availability,
            messages,
        ) = self._session_from_capture(capture_status, capture_available)

        source_status = ReportSourceStatus(
            capture="available" if capture_available else "unavailable",
            alerts="available",
            actions="available",
            intelligence="available",
        )

        alerts_result = await self.analytics.get_report_alerts()
        if not alerts_result.available:
            source_status.alerts = "unavailable"
            if alerts_result.message:
                messages.append(alerts_result.message)

        actions_result = await self.analytics.get_report_actions()
        if not actions_result.available:
            source_status.actions = "unavailable"
            if actions_result.message:
                messages.append(actions_result.message)

        severity_counts: Counter[str] = Counter()
        threat_type_counts: Counter[str] = Counter()
        attacker_counts: dict[str, dict[str, Any]] = {}
        recent_alerts: list[RecentAlertSummary] = []
        for row in alerts_result.rows:
            severity = str(row.get("severity") or "unknown").lower()
            if severity not in {"low", "medium", "high", "critical"}:
                severity = "unknown"
            severity_counts[severity] += 1

            threat_type = str(row.get("model1_classification") or "").strip()
            if threat_type:
                threat_type_counts[threat_type] += 1

            source_ip = str(row.get("source_ip") or "").strip()
            if source_ip:
                current = attacker_counts.setdefault(
                    source_ip,
                    {"count": 0, "highest_severity": None},
                )
                current["count"] += 1
                current["highest_severity"] = self._higher_severity(
                    current["highest_severity"],
                    row.get("severity"),
                )

            recent_alerts.append(
                RecentAlertSummary(
                    alert_id=str(row.get("alert_id") or ""),
                    timestamp=row.get("created_at"),
                    source_ip=source_ip or None,
                    threat_type=threat_type or None,
                    severity=row.get("severity"),
                    score=(
                        float(row["threat_score"])
                        if isinstance(row.get("threat_score"), (int, float))
                        else None
                    ),
                    status=row.get("status"),
                    action=row.get("action"),
                    summary=row.get("summary"),
                )
            )

        top_attacker_rows = sorted(
            attacker_counts.items(),
            key=lambda item: item[1]["count"],
            reverse=True,
        )[:10]
        countries_result = await self.analytics.enrich_attacker_countries(
            [item[0] for item in top_attacker_rows]
        )
        if not countries_result.available:
            source_status.intelligence = "unavailable"
            if countries_result.message:
                messages.append(countries_result.message)
        countries = {
            str(row.get("ip_address")): row.get("country")
            for row in countries_result.rows
            if row.get("ip_address")
        }

        top_attackers = [
            AttackerSummary(
                source_ip=ip,
                count=stats["count"],
                highest_severity=stats["highest_severity"],
                country=countries.get(ip),
            )
            for ip, stats in top_attacker_rows
        ]
        response_timeline = [
            ResponseTimelineEntry.model_validate(row)
            for row in actions_result.rows[:50]
            if row.get("action_id") and row.get("action")
        ]

        return ReportSummary(
            generated_at=datetime.now(timezone.utc),
            timeframe=timeframe,
            monitoring_state=monitoring_state,
            interface=interface_name,
            session=session,
            classification_distribution=classification,
            severity_distribution=SeverityDistribution(
                low=severity_counts["low"],
                medium=severity_counts["medium"],
                high=severity_counts["high"],
                critical=severity_counts["critical"],
                unknown=severity_counts["unknown"],
            ),
            top_threat_types=[
                ThreatTypeSummary(threat_type=name, count=count)
                for name, count in threat_type_counts.most_common(5)
            ],
            top_attackers=top_attackers,
            recent_alerts=recent_alerts[:20],
            response_timeline=response_timeline,
            model_availability=model_availability,
            source_status=source_status,
            messages=list(dict.fromkeys(messages)),
        )

    @staticmethod
    def _higher_severity(current: Any, candidate: Any) -> Optional[str]:
        ranks = {
            "unknown": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        current_text = str(current or "unknown").lower()
        candidate_text = str(candidate or "unknown").lower()
        return (
            str(candidate).upper()
            if ranks.get(candidate_text, 0) >= ranks.get(current_text, 0)
            else (str(current).upper() if current else None)
        )

    async def create_snapshot(self, time_range: str) -> Optional[dict]:
        """Persist an explicitly requested normalized snapshot when available."""
        try:
            summary = await self.get_summary()
            snapshot = {
                "generated_at": summary.generated_at.isoformat(),
                "time_range": time_range,
                "total_threats": len(summary.recent_alerts),
                "critical_threats": summary.severity_distribution.critical,
                "blocked_ips": sum(
                    item.action.upper() == "BLOCK"
                    for item in summary.response_timeline
                ),
                "report_json": summary.model_dump(mode="json"),
            }
            result = (
                await self._db.table("report_snapshots")
                .insert(snapshot)
                .execute()
            )
            return result.data[0] if result.data else None
        except Exception as exc:
            logger.warning(
                "Report snapshot creation unavailable | type=%s",
                type(exc).__name__,
            )
            return None

    async def get_snapshots(self) -> list:
        try:
            result = await (
                self._db.table("report_snapshots")
                .select(
                    "id,generated_at,time_range,total_threats,"
                    "critical_threats,blocked_ips"
                )
                .order("generated_at", desc=True)
                .limit(50)
                .execute()
            )
            return result.data or []
        except Exception as exc:
            logger.warning(
                "Report snapshots unavailable | type=%s",
                type(exc).__name__,
            )
            return []
