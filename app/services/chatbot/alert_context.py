from app.repositories.repositories import ThreatAlertRepository
from app.services.explainability.explanation_service import ExplanationService

class AlertContext:
    async def build_context(self, db, user_input: str) -> dict:
        repo = ThreatAlertRepository(db)
        alerts, _ = await repo.get_history(status="OPEN", page=1, page_size=5)
        
        explanation_service = ExplanationService(repo)
        enriched_alerts = []
        for alert in alerts:
            # Add explainability context to each alert
            explanation = await explanation_service.build_alert_explanation(alert["alert_id"])
            alert["explainability"] = {
                "score_breakdown": explanation.get("breakdown", {}),
                "recommendations": explanation.get("recommendations", [])
            }
            enriched_alerts.append(alert)
            
        return {"active_threats": enriched_alerts}
