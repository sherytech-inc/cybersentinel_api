"""
CyberSentinel — Model 4 Decision Engine API Routes
====================================================
Routes only: validate → call service → return response.
Zero business logic.

Endpoints:
  POST /api/v1/decision/analyze    — main decision
  GET  /api/v1/decision/health     — liveness
  GET  /api/v1/decision/weights    — scoring weight introspection
  GET  /api/v1/decision/thresholds — severity threshold introspection
"""
import logging
from fastapi import APIRouter, Depends, status
from app.core.config import Settings, get_settings
from app.schemas.decision import AnalyzeRequest, DecisionResponse
from app.services.decision.engine import DecisionEngineService, get_decision_engine

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/decision", tags=["Decision Engine — Model 4"])


@router.post(
    "/analyze",
    response_model=DecisionResponse,
    status_code=status.HTTP_200_OK,
    summary="Fuse Model 1+2+3 outputs into a final threat decision",
)
async def analyze(
    body: AnalyzeRequest,
    engine: DecisionEngineService = Depends(get_decision_engine),
) -> DecisionResponse:
    """
    **CyberSentinel Decision Engine** — Model 4.

    Accepts enriched outputs from all upstream models and returns:
    - final_score (0-100)
    - final_severity (Safe / Low / Medium / High / Critical)
    - recommended_action (ALLOW / MONITOR / INVESTIGATE / ALERT / BLOCK)
    - explanation (human-readable reasoning chain)

    Model 3 is optional — weights are redistributed automatically if absent.
    """
    logger.info(
        "POST /analyze ip=%s pred=%s anomaly=%.1f",
        body.source_ip or "?", body.model1.prediction, body.model2.anomaly_score,
    )
    return engine.analyze(body)


@router.get("/health", status_code=status.HTTP_200_OK, summary="Decision Engine health")
async def health() -> dict:
    return {
        "status": "ok",
        "service": "CyberSentinel Decision Engine",
        "model": "Model 4",
    }


@router.get("/weights", status_code=status.HTTP_200_OK, summary="Current scoring weights")
async def weights(s: Settings = Depends(get_settings)) -> dict:
    """Returns active weight config — useful for FYP documentation."""
    return {
        "model1_random_forest": {"weight": s.M4_WEIGHT_MODEL1, "description": "Packet Classifier"},
        "model2_isolation_forest": {"weight": s.M4_WEIGHT_MODEL2, "description": "Anomaly Detector"},
        "model3_threat_intel": {
            "weight": s.M4_WEIGHT_MODEL3,
            "description": "Threat Intelligence",
            "internal": {"abuseipdb": s.M4_W3_ABUSE, "virustotal": s.M4_W3_VT},
        },
    }


@router.get("/thresholds", status_code=status.HTTP_200_OK, summary="Severity & action thresholds")
async def thresholds(s: Settings = Depends(get_settings)) -> dict:
    """Returns all configurable thresholds from config.py."""
    return {
        "severity": {
            "Safe":     f"0 – {s.M4_SAFE_MAX}",
            "Low":      f"{s.M4_SAFE_MAX+1} – {s.M4_LOW_MAX}",
            "Medium":   f"{s.M4_LOW_MAX+1} – {s.M4_MEDIUM_MAX}",
            "High":     f"{s.M4_MEDIUM_MAX+1} – {s.M4_HIGH_MAX}",
            "Critical": f"{s.M4_HIGH_MAX+1} – 100",
        },
        "action": {
            "ALLOW":       f"0 – {s.M4_ACTION_ALLOW_MAX}",
            "MONITOR":     f"{s.M4_ACTION_ALLOW_MAX+1} – {s.M4_ACTION_MONITOR_MAX}",
            "INVESTIGATE": f"{s.M4_ACTION_MONITOR_MAX+1} – {s.M4_ACTION_INVESTIGATE_MAX}",
            "ALERT":       f"{s.M4_ACTION_INVESTIGATE_MAX+1} – {s.M4_ACTION_ALERT_MAX}",
            "BLOCK":       f"{s.M4_ACTION_ALERT_MAX+1} – 100",
        },
    }