"""
CyberSentinel — Model 4 Decision Engine Service
=================================================
Stateless orchestrator. Calls scoring → severity → action → explanation.
Applies SIEM override rules to prevent purely mathematical false negatives.
Returns DecisionResponse consumed by Flutter dashboard and Report Engine.
"""
import logging
import ipaddress
from typing import Optional
from app.core.config import get_settings
from app.schemas.decision import (
    AnalyzeRequest, DecisionResponse,
    Model1Summary, Model2Summary, Model3Summary,
)
from app.scoring.threat_score import compute_threat_score
from app.scoring.severity import classify_severity, classify_action
from app.scoring.recommendations import build_explanation

logger = logging.getLogger(__name__)


def is_private_ip(ip_str: Optional[str]) -> bool:
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def apply_security_rules(
    rf_prediction: str, 
    rf_confidence: float,
    if_score: float, 
    intel_score: float, 
    blacklisted: bool,
    base_score: float, 
    base_severity: any, 
    base_action: any,
    source_ip: Optional[str] = None
) -> tuple[float, str, str, str | None]:
    """
    Enterprise SIEM Override Layer with Multi-Model Consensus.
    Evaluates hard rules and overrides the weighted math if critical threats are detected.
    """
    # Extract string values for safe comparison (handles Enums if passed)
    action_str = getattr(base_action, 'value', str(base_action)).upper()
    rf_pred_str = getattr(rf_prediction, 'value', str(rf_prediction))

    # Evaluate canonical SIEM overrides (Rules 1 to 7)
    score, severity, action, reason = _evaluate_core_rules(
        rf_pred_str, rf_confidence, if_score, intel_score, blacklisted, base_score, base_severity, base_action
    )

    # ── RULE 0: Trusted Internal Traffic Override (RFC1918 Guard) ─────────
    # If the IP is private and there is no threat intel risk or blacklist, cap severity at Medium.
    if is_private_ip(source_ip) and intel_score == 0 and not blacklisted:
        if action in ["INVESTIGATE", "ALERT", "BLOCK"] or severity in ["High", "Critical"]:
            score = min(score, 55.0)
            severity = "Medium"
            action = "MONITOR"
            reason = "SIEM OVERRIDE (Rule 0): Capped at Medium/MONITOR for private internal IP (no external reputation risk present)."

    return score, severity, action, reason


def _evaluate_core_rules(
    rf_pred_str: str, 
    rf_confidence: float,
    if_score: float, 
    intel_score: float, 
    blacklisted: bool,
    base_score: float, 
    base_severity: any, 
    base_action: any
) -> tuple[float, str, str, str | None]:
    action_str = getattr(base_action, 'value', str(base_action)).upper()

    # ── RULE 1: Threat Intel Blacklist hard-override (The Highest Priority) ──
    if blacklisted:
        return 95.0, "Critical", "BLOCK", "SIEM OVERRIDE: IP present in threat intelligence blacklists."

    # ── RULE 2: Multi-Model Consensus (The Strongest Signal) ─────────────
    # RF Malicious + IF >= 90 + Intel >= 70
    if rf_pred_str == "Malicious" and if_score >= 90 and intel_score >= 70:
        return 100.0, "Critical", "BLOCK", "SIEM OVERRIDE (Rule 2): Multi-Model Consensus triggered. All engines confirm threat signature, anomaly, and reputation risk."
        
    # ── RULE 3: RF signature with confidence >= 95% ──────────────────────
    if rf_pred_str == "Malicious" and rf_confidence >= 0.95:
        return max(base_score, 75.0), "High", "INVESTIGATE", f"SIEM OVERRIDE (Rule 3): High-confidence attack signature detected by RF ({rf_confidence*100:.1f}%)."

    # ── RULE 4: Anomaly + Intel Correlation ──────────────────────────────
    if if_score >= 90 and intel_score >= 70 and action_str in ["ALLOW", "MONITOR"]:
        return max(base_score, 75.0), "High", "INVESTIGATE", f"SIEM OVERRIDE (Rule 4): Behavioral anomaly correlated with elevated reputation risk (IF={if_score}, Intel={intel_score})."

    # ── RULE 5: Anomaly + Signature Correlation ──────────────────────────
    if if_score >= 90 and rf_pred_str in ["Malicious", "Attack"] and action_str in ["ALLOW", "MONITOR"]:
        return max(base_score, 75.0), "High", "INVESTIGATE", f"SIEM OVERRIDE (Rule 5): Behavioral anomaly correlated with signature match (IF={if_score})."

    # ── RULE 6: Standalone severe reputation risk ────────────────────────
    if intel_score >= 90 and action_str in ["ALLOW", "MONITOR"]:
        return max(base_score, 65.0), "Medium", "MONITOR", f"SIEM OVERRIDE (Rule 6): Standalone severe reputation risk detected (Intel={intel_score})."

    # ── RULE 7: Standalone Behavioral Anomaly ────────────────────────────
    if if_score >= 90 and action_str in ["ALLOW", "MONITOR"]:
        return max(base_score, 55.0), "Medium", "MONITOR", f"SIEM OVERRIDE (Rule 7): Standalone behavioral anomaly detected (IF={if_score}). Weird does not mean malicious."

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

        # ── 2. Apply SIEM Rule Engine (The Gatekeeper) ────────────────────────
        intel_score = req.model3.intel_score if m3_available else 0.0
        blacklisted = False
        if m3_available and req.model3 is not None:
            settings = get_settings()
            blacklisted = (
                getattr(req.model3, "blacklisted", False) 
                or (req.model3.abuse_score >= settings.INTEL_BLACKLIST_ABUSE_THRESHOLD) 
                or (req.model3.vt_malicious >= settings.INTEL_BLACKLIST_VT_THRESHOLD)
            )
        
        final_score, final_severity, final_action, rule_explanation = apply_security_rules(
            rf_prediction=req.model1.prediction,
            rf_confidence=req.model1.confidence,
            if_score=req.model2.anomaly_score,
            intel_score=intel_score,
            blacklisted=blacklisted,
            base_score=result.final_score,
            base_severity=base_severity,
            base_action=base_action,
            source_ip=req.source_ip
        )

        # ── 3. Build Final Explanation ────────────────────────────────────────
        explanation = build_explanation(
            req.model1, req.model2, req.model3,
            result.breakdown, final_severity, final_action, final_score
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