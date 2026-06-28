"""
CyberSentinel — Model 4 Severity + Action Classifier
======================================================
Maps final_score → ThreatSeverity and RecommendedAction.
All thresholds read from config — never hardcoded here.

Severity:   0-25 Safe | 26-50 Low | 51-75 Medium | 76-90 High | 91-100 Critical
Action:     0-25 ALLOW | 26-50 MONITOR | 51-75 INVESTIGATE | 76-90 ALERT | 91-100 BLOCK
"""
import logging
from app.core.config import get_settings
from app.schemas.decision import ThreatSeverity, RecommendedAction

logger = logging.getLogger(__name__)
_cfg = get_settings()


def classify_severity(score: float) -> ThreatSeverity:
    """Map 0-100 score to ThreatSeverity band."""
    if score <= _cfg.M4_SAFE_MAX:
        return ThreatSeverity.SAFE
    if score <= _cfg.M4_LOW_MAX:
        return ThreatSeverity.LOW
    if score <= _cfg.M4_MEDIUM_MAX:
        return ThreatSeverity.MEDIUM
    if score <= _cfg.M4_HIGH_MAX:
        return ThreatSeverity.HIGH
    return ThreatSeverity.CRITICAL


def classify_action(score: float) -> RecommendedAction:
    """
    Map 0-100 score to RecommendedAction.
    Actions mirror severity but use the spec's exact labels:
        0-25   ALLOW
        26-50  MONITOR
        51-75  INVESTIGATE
        76-90  ALERT
        91-100 BLOCK
    """
    if score <= _cfg.M4_ACTION_ALLOW_MAX:
        return RecommendedAction.ALLOW
    if score <= _cfg.M4_ACTION_MONITOR_MAX:
        return RecommendedAction.MONITOR
    if score <= _cfg.M4_ACTION_INVESTIGATE_MAX:
        return RecommendedAction.INVESTIGATE
    if score <= _cfg.M4_ACTION_ALERT_MAX:
        return RecommendedAction.ALERT
    return RecommendedAction.BLOCK