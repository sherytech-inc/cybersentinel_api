"""
CyberSentinel — Explanation Engine
===================================
Produces ranked, impact-weighted, data-driven explanation lists
by parsing the structured outputs of Models 1, 2, and 3.

Explanations are ordered by their severity impact.
"""

from typing import Optional
from app.schemas.analyze import Model1Output, Model2Output, Model3Output


class ExplanationEngine:
    """
    Generates human-readable, data-driven security explanations.
    """

    @staticmethod
    def generate(
        m1: Model1Output,
        m2: Model2Output,
        m3: Optional[Model3Output],
        final_score: float,
        action: str
    ) -> list[str]:
        """
        Calculates ranked reasons based on impact weights:
            1. Blacklist / Threat Intel presence (Weight 10)
            2. RF signature detection confidence (Weight 9)
            3. IF anomaly strength (Weight 8)
            4. Geo-risk / Proxy routing (Weight 5)
            5. Overall threshold baseline (Weight 1)

        Returns the top 3 explanations sorted by impact.
        """
        reasons = []

        # 1. Threat Intel (High Impact) - Weight 10
        if m3 and m3.blacklisted:
            reasons.append((
                10,
                f"IP is present in threat intelligence blacklists (Reputation status: {m3.reputation})."
            ))

        # 2. RF signature classifier (High Impact) - Weight 9
        if m1.classification in ["malicious", "suspicious"]:
            prob_percent = m1.anomaly_probability * 100
            reasons.append((
                9,
                f"Random Forest classified packet flow as {m1.classification} with {prob_percent:.1f}% confidence."
            ))

        # 3. IF structural anomalies (Medium Impact) - Weight 8
        if m2.is_anomaly:
            reasons.append((
                8,
                f"Isolation Forest detected anomalous outlier behavior (Raw anomaly score: {m2.anomaly_score:.2f})."
            ))

        # 4. Geo-risk / Proxy (Low Impact) - Weight 5
        if m3 and (m3.geo_risk >= 0.5 or m3.asn_risk == "high"):
            reasons.append((
                5,
                "IP originates from a high-risk geo-location or anonymous hosting/proxy network."
            ))

        # 5. Fallback context - Weight 1
        reasons.append((
            1,
            f"Combined fusion risk score ({final_score:.1f}) triggers {action} action."
        ))

        # Sort descending by impact weight
        reasons.sort(key=lambda x: x[0], reverse=True)
        
        # Return top 3 explanations
        return [r[1] for r in reasons[:3]]
