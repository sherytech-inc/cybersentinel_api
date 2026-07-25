from app.services.explainability.decision_weights import DecisionWeights

class ExplanationService:
    def __init__(self, alert_repo=None):
        self.alert_repo = alert_repo

    async def build_alert_explanation(self, alert_id: str) -> dict:
        if not self.alert_repo:
            return {}
            
        alert = await self.alert_repo.get_by_id(alert_id)
        if not alert:
            return {}
            
        weights = DecisionWeights()
        
        # Extract raw scores
        context = alert.get("context", {})
        rf_raw = context.get("model1_score", alert.get("model1_score"))
        if_raw = context.get("model2_score", alert.get("model2_score"))
        intel_raw = context.get("model3_score", alert.get("model3_score"))
        
        # Calculate contributions
        rf_contrib = None if rf_raw is None else (rf_raw * weights.random_forest)
        if_contrib = None if if_raw is None else (if_raw * weights.isolation_forest)
        intel_contrib = None if intel_raw is None else (intel_raw * weights.threat_intelligence)
        
        calculated_score = sum(c for c in [rf_contrib, if_contrib, intel_contrib] if c is not None)
        stored_score = alert.get("threat_score", 0.0)
        
        score_matches = abs(calculated_score - stored_score) <= 0.1
        
        breakdown = {
            "random_forest": {
                "raw_score": rf_raw,
                "weight": weights.random_forest,
                "contribution": rf_contrib
            },
            "isolation_forest": {
                "raw_score": if_raw,
                "weight": weights.isolation_forest,
                "contribution": if_contrib
            },
            "threat_intelligence": {
                "raw_score": intel_raw,
                "weight": weights.threat_intelligence,
                "contribution": intel_contrib
            }
        }
            
        return {
            "alert_id": alert_id,
            "threat_score": stored_score,
            "calculated_score": calculated_score,
            "score_matches": score_matches,
            "model_version": "decision-engine-v1",
            "breakdown": breakdown,
            "recommendations": self.build_recommendations(alert)
        }

    def build_recommendations(self, alert: dict) -> list[str]:
        severity = alert.get("severity", "LOW").upper()
        recs = []
        if severity == "CRITICAL":
            recs.append("Immediately block the source IP.")
            recs.append("Investigate the endpoint for potential compromise.")
        elif severity == "HIGH":
            recs.append("Block the source IP.")
            recs.append("Monitor traffic for similar patterns.")
        else:
            recs.append("Monitor traffic.")
        return recs
