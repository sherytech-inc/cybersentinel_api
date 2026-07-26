import logging
from datetime import datetime, timezone
from typing import Optional
from app.repositories.repositories import ThreatAlertRepository

logger = logging.getLogger("cybersentinel.services.alert_service")


ALERT_STORAGE_FIELDS = {
    "source_ip",
    "severity",
    "action",
    "threat_score",
    "summary",
    "explanation",
    "trace_id",
    "model1_score",
    "model2_score",
    "model3_score",
    "model1_classification",
    "model2_severity",
    "model3_severity",
}
ALERT_IDENTITY_FIELDS = (
    "flow_id",
    "session_id",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "analysis_status",
)


class AlertService:
    def __init__(self, repo: ThreatAlertRepository, duplicate_timeframe_minutes: int = 60) -> None:
        self.repo = repo
        self.duplicate_timeframe_minutes = duplicate_timeframe_minutes

    async def process_threat_alert(self, alert_data: dict) -> dict:
        """
        Process threat alerts with deduplication mitigation.
        Checks for active duplicate alerts (OPEN or INVESTIGATING) within the timeframe.
        If found, updates the existing record and increments occurrence count.
        If not found, inserts a new alert.
        """
        ip = alert_data.get("source_ip")
        if not ip:
            raise ValueError("Alert data must contain source_ip")

        identity = {
            key: alert_data.get(key)
            for key in ALERT_IDENTITY_FIELDS
            if alert_data.get(key) is not None
        }
        threat_type = str(
            alert_data.get("model1_classification") or "unknown"
        ).lower()
        timeframe_seconds = self.duplicate_timeframe_minutes * 60
        existing_alert = await self.repo.find_active_alert(
            source_ip=ip,
            threat_type=threat_type,
            flow_id=identity.get("flow_id"),
            session_id=identity.get("session_id"),
            timeframe_seconds=timeframe_seconds,
        )

        if existing_alert:
            alert_id = existing_alert["alert_id"]
            logger.info(
                "Matching alert occurrence found | alert_id=%s",
                alert_id,
            )
            
            updated_fields = {
                key: value
                for key, value in alert_data.items()
                if key in ALERT_STORAGE_FIELDS
            }
            
            result = await self.repo.increment_occurrence(
                alert_id,
                updated_fields,
                identity=identity,
            )
            
            if result:
                await self._broadcast_alert("alert_updated", result)

            return result or existing_alert

        else:
            logger.info("Creating a new genuine threat alert.")
            now_iso = datetime.now(timezone.utc).isoformat()
            
            initial_timeline = [
                {
                    "event": "CREATED",
                    "timestamp": now_iso,
                    "notes": (
                        "Threat detected. "
                        f"Severity: {alert_data['severity']}, "
                        f"Recommendation: {alert_data['action']}"
                    ),
                    "context": identity,
                }
            ]
            
            full_alert = {
                **{
                    key: value
                    for key, value in alert_data.items()
                    if key in ALERT_STORAGE_FIELDS
                },
                "status": "OPEN",
                "occurrence_count": 1,
                "timeline": initial_timeline,
                "context_ready": True,
                "created_at": now_iso,
                "updated_at": now_iso
            }
            
            result = await self.repo.insert_alert(full_alert)
            if not result:
                raise RuntimeError("Failed to insert alert into repository")

            await self._broadcast_alert("new_threat", result)

            return result

    @staticmethod
    def extract_identity(alert: dict) -> dict:
        """Return the latest supported flow/session evidence from timeline JSON."""
        timeline = alert.get("timeline")
        if not isinstance(timeline, list):
            return {}
        for event in reversed(timeline):
            if not isinstance(event, dict):
                continue
            context = event.get("context")
            if isinstance(context, dict):
                return {
                    key: context.get(key)
                    for key in ALERT_IDENTITY_FIELDS
                    if context.get(key) is not None
                }
        return {}

    async def _broadcast_alert(self, event_name: str, alert: dict) -> None:
        try:
            from app.services.websocket.connection_manager import (
                get_websocket_hub,
            )

            hub = get_websocket_hub()
            identity = self.extract_identity(alert)
            payload = {
                "alert_id": alert.get("alert_id"),
                "source_ip": alert.get("source_ip"),
                "severity": alert.get("severity"),
                "action": alert.get("action"),
                "status": alert.get("status"),
                "threat_score": alert.get("threat_score"),
                "summary": alert.get("summary"),
                "explanation": alert.get("explanation") or [],
                "model1_classification": alert.get("model1_classification"),
                "model1_score": alert.get("model1_score"),
                "model2_score": alert.get("model2_score"),
                "model3_score": alert.get("model3_score"),
                "occurrence_count": alert.get("occurrence_count", 1),
                "timeline": alert.get("timeline") or [],
                "created_at": alert.get("created_at"),
                "updated_at": alert.get("updated_at"),
                **identity,
            }
            await hub.broadcast(event_name, payload)
            await hub.broadcast("analytics_updated", {})
        except Exception as exc:
            logger.warning(
                "Alert event publication unavailable | type=%s",
                type(exc).__name__,
            )

    async def update_status(self, alert_id: str, new_status: str, notes: Optional[str] = None) -> Optional[dict]:
        """
        Updates the lifecycle status of an alert and logs the transition to the timeline.
        Valid statuses: OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE.
        """
        valid_statuses = ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
        status_upper = new_status.upper()
        if status_upper not in valid_statuses:
            raise ValueError(f"Invalid status: {new_status}. Must be one of {valid_statuses}")

        timeline_event = {
            "event": f"STATUS_CHANGE_TO_{status_upper}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "notes": notes or f"Status updated to {status_upper}"
        }

        updated = await self.repo.update_status(alert_id, status_upper, timeline_event)
        
        if updated:
            event_name = (
                "alert_resolved"
                if status_upper in ("RESOLVED", "FALSE_POSITIVE")
                else "alert_updated"
            )
            await self._broadcast_alert(event_name, updated)

        return updated
