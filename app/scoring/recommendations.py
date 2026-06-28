"""
CyberSentinel — Model 4 Explanation Builder
============================================
Builds a human-readable explanation list for every decision.
Covers all four edge cases from the architecture spec:

  Case 1: RF=Normal, IF=low,  Intel=0   → Allow     (clean traffic)
  Case 2: RF=Normal, IF=high, Intel=0   → Investigate (weird behaviour)
  Case 3: RF=Normal, IF=low,  Intel=95  → Alert     (known bad IP)
  Case 4: RF=Malicious, IF=high, Intel=95 → Block   (everything agrees)
"""
import logging
from typing import Optional
from app.schemas.decision import (
    Model1Input, Model2Input, Model3Input,
    PredictionLabel, ScoreBreakdown, ThreatSeverity, RecommendedAction,
)

logger = logging.getLogger(__name__)

_ABUSE_HIGH = 70.0
_ABUSE_MED  = 30.0
_VT_HIGH_RATIO = 0.30
_VT_MED_RATIO  = 0.10
_ANOMALY_HIGH  = 70.0
_ANOMALY_MED   = 40.0
_CONF_HIGH     = 0.80


def build_explanation(
    model1: Model1Input,
    model2: Model2Input,
    model3: Optional[Model3Input],
    breakdown: ScoreBreakdown,
    severity: ThreatSeverity,
    action: RecommendedAction,
) -> list[str]:
    """
    Return an ordered list of plain-English explanation strings.
    Most impactful signals appear first.
    Always ends with a summary line.
    """
    lines: list[str] = []
    conf_pct = round(model1.confidence * 100, 1)

    # ── Model 1 ───────────────────────────────────────────────────────────────
    if model1.prediction == PredictionLabel.MALICIOUS:
        lines.append(
            f"RF classified traffic as Malicious ({conf_pct}% confidence) "
            f"— contributing {breakdown.model1_contribution:.1f} pts."
        )
    elif model1.prediction == PredictionLabel.SUSPICIOUS:
        lines.append(
            f"RF flagged traffic as Suspicious ({conf_pct}% confidence) "
            f"— contributing {breakdown.model1_contribution:.1f} pts."
        )
    else:
        lines.append(
            f"RF classified traffic as Normal ({conf_pct}% confidence) "
            f"— no known attack pattern detected."
        )

    # ── Model 2 ───────────────────────────────────────────────────────────────
    sc = model2.anomaly_score
    if sc >= _ANOMALY_HIGH:
        lines.append(
            f"Behaviour is highly anomalous (IF score {sc:.0f}/100) — "
            f"significant deviation from baseline, contributing {breakdown.model2_contribution:.1f} pts."
        )
    elif sc >= _ANOMALY_MED:
        lines.append(
            f"Moderate behavioural anomaly detected (IF score {sc:.0f}/100) "
            f"— contributing {breakdown.model2_contribution:.1f} pts."
        )
    else:
        lines.append(
            f"Behaviour within normal range (IF score {sc:.0f}/100)."
        )

    # ── Model 3 ───────────────────────────────────────────────────────────────
    if model3 is None:
        lines.append("Threat intelligence unavailable — intel weight redistributed.")
    else:
        # AbuseIPDB
        if model3.abuse_score >= _ABUSE_HIGH:
            lines.append(
                f"AbuseIPDB confidence score is high ({model3.abuse_score:.0f}/100) "
                f"— IP widely reported for malicious activity "
                f"({model3.abuse_total_reports} reports, {model3.abuse_distinct_users} distinct users)."
            )
        elif model3.abuse_score >= _ABUSE_MED:
            lines.append(
                f"AbuseIPDB reports moderate abuse ({model3.abuse_score:.0f}/100)."
            )
        else:
            lines.append(
                f"AbuseIPDB abuse score low ({model3.abuse_score:.0f}/100)."
            )

        # VirusTotal
        if model3.vt_total_engines > 0:
            ratio = model3.vt_malicious / model3.vt_total_engines
            pct = round(ratio * 100, 1)
            if ratio >= _VT_HIGH_RATIO:
                lines.append(
                    f"VirusTotal: {model3.vt_malicious}/{model3.vt_total_engines} "
                    f"engines flagged as malicious ({pct}%)."
                )
            elif ratio >= _VT_MED_RATIO:
                lines.append(
                    f"VirusTotal: {model3.vt_malicious}/{model3.vt_total_engines} "
                    f"engines flagged ({pct}%) — moderate signal."
                )
            elif model3.vt_malicious > 0:
                lines.append(
                    f"VirusTotal: {model3.vt_malicious}/{model3.vt_total_engines} "
                    f"engines flagged — low signal."
                )
            else:
                lines.append(
                    f"VirusTotal: no engines flagged this IP "
                    f"({model3.vt_total_engines} checked)."
                )

        # Network context
        if model3.is_tor:
            lines.append("IP is a TOR exit node — automatic High floor applied.")
        if model3.is_proxy:
            lines.append("IP identified as a known proxy/VPN endpoint.")
        if model3.is_whitelisted:
            lines.append("IP is whitelisted — score capped at Safe.")
        if model3.country:
            org = f" ({model3.organization})" if model3.organization else ""
            lines.append(f"Geolocation: {model3.country}{org}.")

        # Intel score summary
        lines.append(
            f"Model 3 intel_score: {model3.intel_score:.0f}/100 "
            f"(severity: {model3.intel_severity}) — "
            f"contributing {breakdown.model3_contribution:.1f} pts."
        )

    # ── Case-specific summary ─────────────────────────────────────────────────
    lines.append(
        f"Final score {breakdown.model1_contribution + breakdown.model2_contribution + breakdown.model3_contribution:.1f}/100 "
        f"→ {severity.value} — recommended action: {action.value}."
    )

    return lines