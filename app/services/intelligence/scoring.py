"""
CyberSentinel — Model 3 Intelligence Scoring Engine
=====================================================
Computes intel_score (0-100) and intel_severity from AbuseIPDB, VirusTotal, GeoIP.
Uses M4_SAFE_MAX / M4_LOW_MAX / M4_HIGH_MAX thresholds from config (single source of truth).
"""
import logging
from typing import Optional
from app.core.config import get_settings
from app.schemas.intelligence import AbuseIPDBResult, GeoIPResult, IntelSeverity, VirusTotalResult

logger = logging.getLogger(__name__)
_s = get_settings()

_HIGH_RISK_COUNTRIES: frozenset[str] = frozenset({
    "CN","RU","KP","IR","SY","CU","VE","NG","PK","UA","BY","MM","LY","SD",
})
_HOSTING_HINTS: tuple[str,...] = (
    "digitalocean","linode","vultr","ovh","hetzner",
    "choopa","leaseweb","serverius","host1plus",
)


class ThreatScoringEngine:
    """Stateless — instantiate once, reuse forever."""

    def __init__(self) -> None:
        self._w_abuse = _s.SCORE_WEIGHT_ABUSEIPDB
        self._w_vt    = _s.SCORE_WEIGHT_VIRUSTOTAL
        self._w_geo   = _s.SCORE_WEIGHT_GEO
        # Use M4 thresholds — single source of truth in config.py
        self._safe_max = _s.M4_SAFE_MAX
        self._low_max  = _s.M4_LOW_MAX
        self._high_max = _s.M4_HIGH_MAX

    def compute(
        self,
        abuse: Optional[AbuseIPDBResult],
        vt: Optional[VirusTotalResult],
        geo: Optional[GeoIPResult],
    ) -> tuple[int, IntelSeverity]:
        abuse_n = self._score_abuse(abuse)
        vt_n    = self._score_virustotal(vt)
        geo_n   = self._score_geo(geo)

        raw = self._w_abuse * abuse_n + self._w_vt * vt_n + self._w_geo * geo_n

        if abuse and abuse.is_tor:
            raw = max(raw, 0.75)
        if abuse and abuse.is_whitelisted:
            raw = min(raw, 0.15)

        intel_score = min(100, max(0, round(raw * 100)))
        return intel_score, self._severity(intel_score)

    @staticmethod
    def _score_abuse(abuse: Optional[AbuseIPDBResult]) -> float:
        if abuse is None:
            return 0.30
        base = abuse.abuse_confidence_score / 100.0
        if abuse.num_distinct_users > 50:
            base = min(1.0, base + 0.05)
        if abuse.total_reports > 500:
            base = min(1.0, base + 0.03)
        return base

    @staticmethod
    def _score_virustotal(vt: Optional[VirusTotalResult]) -> float:
        if vt is None:
            return 0.30
        if vt.vt_total_engines == 0:
            return 0.10
        weighted = vt.vt_malicious + 0.5 * vt.vt_suspicious
        return min(1.0, weighted / vt.vt_total_engines)

    @staticmethod
    def _score_geo(geo: Optional[GeoIPResult]) -> float:
        if geo is None:
            return 0.20
        score = 0.0
        if geo.country_code.upper() in _HIGH_RISK_COUNTRIES:
            score += 0.40
        if geo.is_proxy:
            score += 0.30
        if geo.is_hosting:
            score += 0.20
        org = (geo.organization or "").lower()
        isp = (geo.isp or "").lower()
        if any(h in org or h in isp for h in _HOSTING_HINTS):
            score += 0.10
        return min(1.0, score)

    def _severity(self, score: int) -> IntelSeverity:
        if score <= self._safe_max:
            return IntelSeverity.SAFE
        if score <= self._low_max:
            return IntelSeverity.LOW
        if score <= self._high_max:
            return IntelSeverity.HIGH
        return IntelSeverity.CRITICAL


scoring_engine = ThreatScoringEngine()