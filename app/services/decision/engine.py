"""
CyberSentinel — Model 4 Decision Engine Service
=================================================
Stateless orchestrator. Calls scoring → severity → action → explanation.
Applies SIEM override rules to prevent purely mathematical false negatives.
Returns DecisionResponse consumed by Flutter dashboard and Report Engine.
"""
import logging
from app.schemas.decision import (
    AnalyzeRequest, DecisionResponse,
    Model1Summary, Model2Summary, Model3Summary,
)
from app.scoring.threat_score import compute_threat_score
from app.scoring.severity import classify_severity, classify_action
from app.scoring.recommendations import build_explanation

logger = logging.getLogger(__name__)


def apply_security_rules(
    rf_prediction: str, 
    if_score: float, 
    intel_score: float, 
    base_score: float, 
    base_severity: any, 
    base_action: any
) -> tuple[float, str, str, str | None]:
    """
    Enterprise SIEM Override Layer with Multi-Model Consensus.
    Evaluates hard rules and overrides the weighted math if critical threats are detected.
    """
    # Extract string values for safe comparison (handles Enums if passed)
    action_str = getattr(base_action, 'value', str(base_action)).upper()

    # ── RULE 4: Multi-Model Consensus (The Strongest Signal) ─────────────
    if rf_prediction == "Malicious" and if_score >= 80 and intel_score >= 80:
        return 100.0, "Critical", "BLOCK", "SIEM OVERRIDE (Rule 4): Multi-Model Consensus triggered. All engines confirm active threat."
    
    # ── RULE 1: Signature Match (Fallback Block) ─────────────────────────
    if rf_prediction == "Malicious":
        return max(base_score, 91.0), "Critical", "BLOCK", "SIEM OVERRIDE (Rule 1): Known malicious signature detected by RF."
        
    # ── RULE 2: Zero-Day Anomaly ─────────────────────────────────────────
    if if_score >= 90 and action_str in ["ALLOW", "MONITOR"]:
        return max(base_score, 75.0), "High", "INVESTIGATE", f"SIEM OVERRIDE (Rule 2): Severe zero-day anomaly detected (IF={if_score})."
        
    # ── RULE 3: Critical Reputation ──────────────────────────────────────
    if intel_score >= 80 and action_str in ["ALLOW", "MONITOR"]:
        return max(base_score, 75.0), "High", "INVESTIGATE", f"SIEM OVERRIDE (Rule 3): Critical threat intelligence risk (Intel={intel_score})."

    # No rules triggered, return base math
    return base_score, base_severity, base_action, None


class DecisionEngineService:
    """Stateless — instantiate once, reuse for all requests."""

    def analyze(self, req: AnalyzeRequest) -> DecisionResponse:
        """Full Model 4 pipeline: score → rules → severity → action → explanation."""
        m3_available = req.model3 is not None

        # ── 1. Calculate Base Math ────────────────────────────────────────────
        result = compute_threat_score(req.model1, req.model2, req.model3)
        base_severity = classify_severity(result.final_score)
        base_action   = classify_action(result.final_score)

        # ── 2. Build Base Explanation ─────────────────────────────────────────
        explanation = build_explanation(
            req.model1, req.model2, req.model3,
            result.breakdown, base_severity, base_action,
        )

        # ── 3. Apply SIEM Rule Engine (The Gatekeeper) ────────────────────────
        intel_score = req.model3.intel_score if m3_available else 0.0
        
        final_score, final_severity, final_action, rule_explanation = apply_security_rules(
            rf_prediction=req.model1.prediction,
            if_score=req.model2.anomaly_score,
            intel_score=intel_score,
            base_score=result.final_score,
            base_severity=base_severity,
            base_action=base_action
        )

        # Prepend the rule explanation if an override occurred
        if rule_explanation:
            explanation.insert(0, rule_explanation)

        # Safely extract values for the logger (supports Enums or raw strings)
        sev_log = getattr(final_severity, 'value', final_severity)
        act_log = getattr(final_action, 'value', final_action)

        logger.info(
            "Decision | ip=%s score=%.2f severity=%s action=%s",
            req.source_ip or "unknown",
            final_score, sev_log, act_log,
        )

        # ── 4. Formatting ─────────────────────────────────────────────────────
        anomaly_sev = _anomaly_label(req.model2.anomaly_score)
        m3_summary = None
        if req.model3 is not None:
            m3_summary = Model3Summary(
                intel_score=req.model3.intel_score,
                severity=req.model3.intel_severity,
            )

        return DecisionResponse(
            ip=req.source_ip,
            model1=Model1Summary(
                classification=req.model1.prediction,
                confidence=req.model1.confidence,
            ),
            model2=Model2Summary(
                threat_score=req.model2.anomaly_score,
                severity=anomaly_sev,
            ),
            model3=m3_summary,
            final_score=final_score,
            final_severity=final_severity,
            recommended_action=final_action,
            explanation=explanation,
            score_breakdown=result.breakdown,
            model3_available=m3_available,
            session_id=req.session_id,
        )


def _anomaly_label(score: float) -> str:
    if score >= 76:
        return "Highly Anomalous"
    if score >= 51:
        return "Moderately Anomalous"
    if score >= 26:
        return "Slightly Anomalous"
    return "Normal"


decision_engine = DecisionEngineService()


def get_decision_engine() -> DecisionEngineService:
    """FastAPI dependency."""
    return decision_engine