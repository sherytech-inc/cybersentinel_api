"""
CyberSentinel — Model 4 Threat Score Calculator
=================================================
Pure arithmetic. No ML, no I/O, no side effects.
All weights and thresholds read from config — never hardcoded.

Formula:
    M1 raw = prediction_base × confidence   (base: Normal=0, Suspicious=50, Malicious=100)
    M2 raw = anomaly_score (0-100 direct)
    M3 raw = intel_score from Model 3       (pre-computed, or recomputed from raw fields)

    final = clamp(M1×w1 + M2×w2 + M3×w3, 0, 100)

Special override rules:
    - TOR exit node     → floor at 76  (always at least High)
    - Whitelisted IP    → cap at 10    (trust the whitelist)
    - All models agree on Malicious/Critical → bonus +5 (convergence boost)
"""
import logging
from dataclasses import dataclass
from app.core.config import get_settings
from app.schemas.decision import Model1Input, Model2Input, Model3Input, PredictionLabel, ScoreBreakdown

logger = logging.getLogger(__name__)
_cfg = get_settings()

_PREDICTION_BASE: dict[str, float] = {
    PredictionLabel.NORMAL.value: 0.0,
    PredictionLabel.SUSPICIOUS.value: 50.0,
    PredictionLabel.MALICIOUS.value: 100.0,
}


@dataclass(frozen=True)
class ScoringResult:
    final_score: float
    breakdown: ScoreBreakdown


from app.services.explainability.decision_weights import DecisionWeights

def compute_threat_score(
    model1: Model1Input,
    model2: Model2Input,
    model3: Model3Input | None,
) -> ScoringResult:
    """
    Compute the final CyberSentinel threat score.
    Returns ScoringResult with final_score (0-100) and full breakdown.
    """
    w1, w2, w3 = _resolve_weights(model3 is not None)

    m1_raw = _score_model1(model1)
    m2_raw = _score_model2(model2)
    m3_raw = _score_model3(model3)

    m1_contrib = round(m1_raw * w1, 4)
    # Apply Isolation Forest contribution cap to protect against calibration drift
    m2_contrib = min(_cfg.M4_MAX_IF_CONTRIBUTION, round(m2_raw * w2, 4))
    m3_contrib = round(m3_raw * w3, 4)

    raw_total = m1_contrib + m2_contrib + m3_contrib

    # ── Override rules ────────────────────────────────────────────────────────
    raw_total = _apply_overrides(raw_total, model1, model3)

    final_score = round(_clamp(raw_total), 2)

    logger.info(
        "ThreatScore | m1=%.1f(×%.2f=%.2f) m2=%.1f(×%.2f=%.2f) "
        "m3=%.1f(×%.2f=%.2f) → %.2f",
        m1_raw, w1, m1_contrib,
        m2_raw, w2, m2_contrib,
        m3_raw, w3, m3_contrib,
        final_score,
    )

    return ScoringResult(
        final_score=final_score,
        breakdown=ScoreBreakdown(
            model1_raw_score=round(m1_raw, 2),
            model2_raw_score=round(m2_raw, 2),
            model3_raw_score=round(m3_raw, 2),
            model1_contribution=m1_contrib,
            model2_contribution=m2_contrib,
            model3_contribution=m3_contrib,
            model1_weight=w1,
            model2_weight=w2,
            model3_weight=w3,
        ),
    )


def _score_model1(m: Model1Input) -> float:
    """Normal→0, Suspicious→50, Malicious→100, scaled by confidence."""
    base = _PREDICTION_BASE.get(m.prediction, 0.0)
    return _clamp(base * m.confidence)


def _score_model2(m: Model2Input) -> float:
    """Anomaly score is already 0-100."""
    return _clamp(m.anomaly_score)


def _score_model3(m: Model3Input | None) -> float:
    """
    Use Model 3's pre-computed intel_score if available (most accurate).
    Fall back to recomputing from raw AbuseIPDB + VirusTotal fields.
    """
    if m is None:
        return 0.0

    # If intel_score was pre-computed by Model 3, trust it directly
    if m.intel_score > 0:
        return _clamp(m.intel_score)

    # Recompute from raw fields
    abuse_part = _cfg.M4_W3_ABUSE * m.abuse_score
    if m.vt_total_engines > 0:
        vt_score = (m.vt_malicious / m.vt_total_engines) * 100.0
    else:
        vt_score = 0.0
    vt_part = _cfg.M4_W3_VT * vt_score
    return _clamp(abuse_part + vt_part)


def _apply_overrides(score: float, m1: Model1Input, m3: Model3Input | None) -> float:
    """Apply special case override rules."""
    if m3 is not None:
        if m3.is_tor:
            # TOR exit nodes always at least High regardless of other signals
            score = max(score, 76.0)
            logger.info("TOR override applied — floor at 76")
        if m3.is_whitelisted:
            # Explicitly whitelisted IPs capped at Safe
            score = min(score, 10.0)
            logger.info("Whitelist override applied — cap at 10")

    # Convergence boost: all three signals agree on malicious/critical
    if (
        m1.prediction == PredictionLabel.MALICIOUS
        and m3 is not None
        and m3.intel_severity in ("High", "Critical")
        and m3.abuse_score >= 70
    ):
        score = min(100.0, score + 5.0)
        logger.info("Convergence boost applied +5")

    return score


def _resolve_weights(model3_available: bool) -> tuple[float, float, float]:
    """
    Return (w1, w2, w3). If Model 3 absent, redistribute its weight
    proportionally between Model 1 and Model 2.
    """
    weights = DecisionWeights()
    w1_base = weights.random_forest
    w2_base = weights.isolation_forest
    w3_base = weights.threat_intelligence

    if model3_available:
        return w1_base, w2_base, w3_base

    total = w1_base + w2_base
    if total == 0:
        return 0.5, 0.5, 0.0
        
    w1 = round(w1_base / total, 6)
    w2 = round(w2_base / total, 6)
    logger.warning("Model 3 absent — weights redistributed w1=%.4f w2=%.4f", w1, w2)
    return w1, w2, 0.0


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, v))