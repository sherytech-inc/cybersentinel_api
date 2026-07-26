import logging
from typing import Optional, Any
from app.services.threat_response.alert_service import AlertService

logger = logging.getLogger("cybersentinel.services.alert_generator")

class AlertGenerator:
    def __init__(self, alert_service: AlertService) -> None:
        self.alert_service = alert_service

    @staticmethod
    def generate_human_summary(severity: str, action: str, explanation: list[str]) -> str:
        """Generates a non-technical summary paragraph based on explanation items and severity."""
        if explanation:
            # Join multiple reasons with a space and ensure it's a nice sentence
            base_desc = " ".join([str(r).strip() for r in explanation])
            if not base_desc.endswith("."):
                base_desc += "."
        else:
            base_desc = "Suspicious activity was identified matching anomalous signatures."

        # Append recommendation recommendation
        if action == "BLOCK":
            recommendation = "CyberSentinel recommends blocking this address."
        elif action == "ALERT":
            recommendation = "CyberSentinel recommends blocking this address and raising an immediate alert."
        elif action == "INVESTIGATE":
            recommendation = "CyberSentinel recommends initiating an active investigation into this host."
        elif action == "MONITOR":
            recommendation = "CyberSentinel recommends continuous monitoring for this IP address."
        else:
            recommendation = "CyberSentinel recommends review by an analyst."

        return f"{base_desc} {recommendation}"

    async def generate_alert(self, decision_data: dict) -> Optional[dict]:
        """
        Generate an alert only from a reliable HIGH/CRITICAL decision.

        A partial result remains eligible when both local models completed and
        only optional intelligence is unavailable. Failed analysis, pending
        work, and partial results caused by a local-model failure are never
        promoted to an alert.
        """
        severity = str(decision_data.get("severity", "")).upper()
        if severity not in ["HIGH", "CRITICAL"]:
            logger.debug("Skipping alert generation for severity: %s", severity)
            return None
        analysis_status = str(
            decision_data.get("analysis_status") or "complete"
        ).lower()
        local_models_available = bool(
            decision_data.get("local_models_available", True)
        )
        if analysis_status not in {"complete", "partial"}:
            logger.info(
                "Skipping alert generation for non-terminal analysis | status=%s",
                analysis_status,
            )
            return None
        if analysis_status == "partial" and not local_models_available:
            logger.info(
                "Skipping alert generation for incomplete local-model evidence."
            )
            return None

        source_ip = decision_data.get("source_ip")
        if not source_ip:
            logger.warning("Cannot generate alert: source_ip is missing.")
            return None

        explanation = decision_data.get("explanation") or []
        if isinstance(explanation, str):
            explanation = [explanation]

        action = str(decision_data.get("action", "ALERT")).upper()
        summary = self.generate_human_summary(severity, action, explanation)

        alert_payload = {
            "source_ip": source_ip,
            "severity": severity,
            "action": action,
            "threat_score": float(decision_data.get("threat_score", 0.0)),
            "summary": summary,
            "explanation": explanation,
            "trace_id": decision_data.get("trace_id"),
            
            # Model scores
            "model1_score": decision_data.get("model1_score"),
            "model2_score": decision_data.get("model2_score"),
            "model3_score": decision_data.get("model3_score"),
            
            # Model details
            "model1_classification": decision_data.get("model1_classification"),
            "model2_severity": decision_data.get("model2_severity"),
            "model3_severity": decision_data.get("model3_severity"),
            "analysis_status": analysis_status,
            "flow_id": decision_data.get("flow_id"),
            "session_id": decision_data.get("session_id"),
            "destination_ip": decision_data.get("destination_ip"),
            "source_port": decision_data.get("source_port"),
            "destination_port": decision_data.get("destination_port"),
            "protocol": decision_data.get("protocol"),
        }

        return await self.alert_service.process_threat_alert(alert_payload)
