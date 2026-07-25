import logging
from datetime import datetime, timezone
from typing import Optional
from app.repositories.repositories import ThreatAlertRepository

logger = logging.getLogger("cybersentinel.services.alert_service")

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

        timeframe_seconds = self.duplicate_timeframe_minutes * 60
        existing_alert = await self.repo.find_active_alert_by_ip(ip, timeframe_seconds)

        if existing_alert:
            alert_id = existing_alert["alert_id"]
            logger.info("Duplicate alert detected for IP %s. Merging into alert_id=%s", ip, alert_id)
            
            # Fields to update
            updated_fields = {
                "threat_score": alert_data["threat_score"],
                "severity": alert_data["severity"],
                "action": alert_data["action"],
                "summary": alert_data["summary"],
                "explanation": alert_data["explanation"],
                "trace_id": alert_data.get("trace_id"),
                "model1_score": alert_data.get("model1_score"),
                "model2_score": alert_data.get("model2_score"),
                "model3_score": alert_data.get("model3_score"),
                "model1_classification": alert_data.get("model1_classification"),
                "model2_severity": alert_data.get("model2_severity"),
                "model3_severity": alert_data.get("model3_severity"),
            }
            
            result = await self.repo.increment_occurrence(alert_id, updated_fields)
            
            if result:
                try:
                    from app.services.websocket.connection_manager import get_websocket_hub
                    hub = get_websocket_hub()
                    await hub.broadcast("alert_updated", {
                        "alert_id": result["alert_id"],
                        "source_ip": result["source_ip"],
                        "severity": result["severity"],
                        "action": result["action"],
                        "status": result["status"],
                        "threat_score": result["threat_score"],
                        "summary": result["summary"],
                        "explanation": result["explanation"],
                        "occurrence_count": result["occurrence_count"],
                        "timeline": result["timeline"],
                        "created_at": result["created_at"],
                        "updated_at": result["updated_at"]
                    })
                    # Send stats_update immediately
                    from app.services.threat_response.stats_service import get_full_dashboard_stats
                    stats = await get_full_dashboard_stats()
                    await hub.broadcast("stats_update", stats)
                    await hub.broadcast("analytics_updated", {})
                except Exception as ws_exc:
                    logger.error("Failed to broadcast alert_updated event: %s", ws_exc)

            return result or existing_alert

        else:
            # Create a fresh alert
            logger.info("No active alert found for IP %s. Inserting new alert.", ip)
            now_iso = datetime.now(timezone.utc).isoformat()
            
            initial_timeline = [
                {
                    "event": "CREATED",
                    "timestamp": now_iso,
                    "notes": f"Threat detected. Severity: {alert_data['severity']}, Recommendation: {alert_data['action']}"
                }
            ]
            
            full_alert = {
                **alert_data,
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

            try:
                from app.services.websocket.connection_manager import get_websocket_hub
                hub = get_websocket_hub()
                await hub.broadcast("new_threat", {
                    "alert_id": result["alert_id"],
                    "source_ip": result["source_ip"],
                    "severity": result["severity"],
                    "action": result["action"],
                    "status": result["status"],
                    "threat_score": result["threat_score"],
                    "summary": result["summary"],
                    "explanation": result["explanation"],
                    "occurrence_count": result["occurrence_count"],
                    "timeline": result["timeline"],
                    "created_at": result["created_at"],
                    "updated_at": result["updated_at"]
                })
                # Send stats_update immediately
                from app.services.threat_response.stats_service import get_full_dashboard_stats
                stats = await get_full_dashboard_stats()
                await hub.broadcast("stats_update", stats)
                await hub.broadcast("analytics_updated", {})
            except Exception as ws_exc:
                logger.error("Failed to broadcast new_threat event: %s", ws_exc)

            return result

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
            try:
                from app.services.websocket.connection_manager import get_websocket_hub
                hub = get_websocket_hub()
                
                event_name = "alert_resolved" if status_upper in ("RESOLVED", "FALSE_POSITIVE") else "alert_updated"
                await hub.broadcast(event_name, {
                    "alert_id": alert_id,
                    "status": status_upper,
                    "timeline": updated["timeline"],
                    "updated_at": updated["updated_at"]
                })
                # Send stats_update immediately
                from app.services.threat_response.stats_service import get_full_dashboard_stats
                stats = await get_full_dashboard_stats()
                await hub.broadcast("stats_update", stats)
                await hub.broadcast("analytics_updated", {})
            except Exception as ws_exc:
                logger.error("Failed to broadcast alert update status event: %s", ws_exc)

        return updated
