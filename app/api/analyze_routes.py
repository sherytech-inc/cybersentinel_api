"""
CyberSentinel — Unified Analyze Router (Phase 5)
=================================================
Orchestrates parallel async threat analysis, handles fallbacks,
enforces strict rate-limiting, and persists decisions for auditing.
"""

import time
import uuid
import logging
import asyncio
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.config import get_settings
from app.schemas.analyze import (
    AnalyzeFlowRequest,
    UnifiedAnalyzeResponse,
    Model1Output,
    Model2Output,
    Model3Output,
)
from app.services.model_rf import RandomForestService
from app.services.model_if import IsolationForestService
from app.services.preprocessor import DataPreprocessor
from app.services.intelligence.enrichment import IntelligenceEnrichmentService
from app.services.intelligence import get_enrichment_service
from app.repositories import get_threat_score_repo, ThreatScoreRepository, ThreatAlertRepository
from app.services.decision.explanation import ExplanationEngine
from app.services.decision.engine import get_decision_engine
from app.schemas.decision import AnalyzeRequest, Model1Input, Model2Input, Model3Input
from app.services.threat_response.alert_service import AlertService
from app.services.threat_response.alert_generator import AlertGenerator

logger = logging.getLogger("cybersentinel.api.analyze")

router = APIRouter(prefix="/api/v1", tags=["Unified Analysis Engine — Phase 5"])

# Global singletons for local inference
_preprocessor = DataPreprocessor()
_model_rf = RandomForestService()
_model_if = IsolationForestService()

# ── IN-MEMORY RATE LIMITING (IP Throttling) ───────────────────────────────────
# Thread-safe sliding window mapping Client IP -> list of timestamps
_rate_limit_lock = asyncio.Lock()
_ip_request_history: dict[str, list[float]] = defaultdict(list)
_reported_runtime_diagnostics: set[str] = set()


async def check_rate_limit(client_ip: str, limit_max: int, limit_seconds: int):
    """Enforces sliding-window rate-limiting on the calling client IP."""
    async with _rate_limit_lock:
        now = time.time()
        # Filter out timestamps older than the rate limit window
        window_start = now - limit_seconds
        timestamps = [t for t in _ip_request_history[client_ip] if t > window_start]

        if len(timestamps) >= limit_max:
            logger.warning(
                "Rate limit exceeded | ip=%s requests=%d window=%ds",
                client_ip, len(timestamps), limit_seconds
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many requests. Limit is {limit_max} per {limit_seconds} seconds."
            )
            
        # Record new request timestamp
        timestamps.append(now)
        _ip_request_history[client_ip] = timestamps


# ── Unified Inference & Orchestration ─────────────────────────────────────────

@router.post(
    "/analyze",
    response_model=UnifiedAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Unified orchestrator for multi-model threat analysis",
)
async def analyze_flow(
    request: Request,
    body: AnalyzeFlowRequest,
    intel_service: IntelligenceEnrichmentService = Depends(get_enrichment_service),
    threat_repo: ThreatScoreRepository = Depends(get_threat_score_repo)
) -> UnifiedAnalyzeResponse:
    """
    **CyberSentinel Unified Analyze API**
    
    The single gateway for all threat classification. Parses flow, validates
    against training schema, runs parallel models, and fuses results:
    
    1. Enforces client-IP rate limiting (configurable via env).
    2. Runs feature parsing and normalization.
    3. Runs RF (supervised signature), IF (unsupervised anomaly), and Threat Intel in parallel.
    4. Applies M5 weighted score fusion and maps final severity/action.
    5. Feeds results to ranked Explanation Engine.
    6. Logs the complete decision to DB audit trail.
    """
    settings = get_settings()
    client_ip = request.client.host if request.client else "127.0.0.1"
    await check_rate_limit(
        client_ip=client_ip,
        limit_max=settings.ANALYZE_RATE_LIMIT_MAX_REQUESTS,
        limit_seconds=settings.ANALYZE_RATE_LIMIT_SECONDS
    )
    return await analyze_flow_internal(body, intel_service, threat_repo, client_ip)


async def analyze_flow_internal(
    body: AnalyzeFlowRequest,
    intel_service: IntelligenceEnrichmentService,
    threat_repo: Optional[ThreatScoreRepository] = None,
    client_ip: str = "127.0.0.1",
    *,
    persist_result: bool = True,
    intel_eligible: bool = True,
) -> UnifiedAnalyzeResponse:
    """Run model inference and decisioning, optionally persisting the result."""
    # Explicit timing wrapper start
    start_time = time.time()
    trace_id = str(uuid.uuid4())
    settings = get_settings()
    ip = body.ip
    flow_features = body.flow_features
    session_id = body.session_id or trace_id
    model_version = f"{settings.APP_VERSION}-rf-and-if"

    logger.info(
        "Request started | trace_id=%s client=%s target_ip=%s session=%s",
        trace_id, client_ip, ip, session_id
    )

    # ── 2. Run Feature Scaling / Preprocessing (CPU bound) ───────────────────
    preprocess_start = time.time()
    try:
        scaled_m1 = _preprocessor.process(flow_features)
    except Exception as exc:
        logger.error("Preprocessing failed | trace_id=%s: %s", trace_id, exc)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Preprocessing failed: {str(exc)}"
        )
    preprocess_latency = (time.time() - preprocess_start) * 1000

    # ── 3. Parallel Async Model Execution ────────────────────────────────────
    model_start = time.time()
    
    rf_task = asyncio.to_thread(_model_rf.predict, scaled_m1)
    if_task = asyncio.to_thread(_model_if.predict_raw, flow_features)
    intel_task = (
        intel_service.enrich(ip)
        if intel_eligible
        else asyncio.sleep(0, result=None)
    )

    rf_res, if_res, intel_res = await asyncio.gather(
        rf_task, if_task, intel_task, return_exceptions=True
    )
    model_latency = (time.time() - model_start) * 1000

    # ── 4. Process Model Outcomes & Fallback Logic ───────────────────────────
    rf_failed = isinstance(rf_res, Exception)
    if_failed = isinstance(if_res, Exception)
    intel_failed = isinstance(intel_res, Exception)
    degraded = rf_failed or if_failed or intel_failed

    if rf_failed:
        logger.error("Model 1 (RF) failed | trace_id=%s: %s", trace_id, rf_res)
    if if_failed:
        logger.error("Model 2 (IF) failed | trace_id=%s: %s", trace_id, if_res)
    if intel_failed:
        logger.error("Model 3 (Intel) failed | trace_id=%s: %s", trace_id, intel_res)

    # Hard stop if both local ML models fail
    if rf_failed and if_failed:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Fatal error: Both local ML detection engines failed."
        )

    # Map Model 1 (RF)
    rf_prob = 0.0
    rf_class = "Unavailable" if rf_failed else "Normal"
    if not rf_failed:
        # Cast to float to preserve type safety
        rf_prob = float(rf_res["confidence_scores"]["Malicious"]) * 100
        rf_class = str(rf_res["classification"])

    # Map Model 2 (IF)
    if_raw_score = 0.0
    is_anomaly = False
    if_norm = 0.0
    if not if_failed:
        if_raw_score = float(if_res["anomaly_score"])
        is_anomaly = bool(if_res["is_anomaly"])
        if_norm = float(if_res["normalized_score"])

    # Map Model 3 from the current nested intelligence contract.
    model3_block = None
    intel_score = 0.0
    intel_avail = False
    intel_severity = "N/A"
    abuse_score = 0.0
    vt_malicious = 0
    if not intel_failed and intel_res is not None:
        try:
            status_value = getattr(intel_res.status, "value", intel_res.status)
            intel_avail = (
                status_value in ("completed", "partial")
                and intel_res.intel_score is not None
            )
            if not intel_avail:
                diagnostic_key = f"model3:{status_value}"
                if diagnostic_key not in _reported_runtime_diagnostics:
                    _reported_runtime_diagnostics.add(diagnostic_key)
                    logger.info("Model 3 unavailable | status=%s", status_value)
            abuse = intel_res.abuseipdb
            vt = intel_res.virustotal
            geo = intel_res.geoip
            intel_score = float(intel_res.intel_score) if intel_avail else 0.0
            abuse_score = float(abuse.abuse_confidence_score or 0)
            abuse_total_reports = int(abuse.total_reports or 0)
            abuse_distinct_users = int(abuse.num_distinct_users or 0)
            is_tor = bool(abuse.is_tor) if abuse.is_tor is not None else False
            is_whitelisted = (
                bool(abuse.is_whitelisted)
                if abuse.is_whitelisted is not None else False
            )
            vt_malicious = int(vt.malicious or 0)
            vt_suspicious = int(vt.suspicious or 0)
            vt_harmless = int(vt.harmless or 0)
            vt_total_engines = int(vt.total_engines or 0)
            intel_severity = str(intel_res.severity or "N/A")
            country = str(geo.country or "Unknown")
            country_code = str(geo.country_code or "XX")
            asn = str(geo.asn or "Unknown")
            organization = str(geo.organization or "Unknown")
            is_proxy = bool(geo.is_proxy) if geo.is_proxy is not None else False
            is_hosting = bool(geo.is_hosting) if geo.is_hosting is not None else False

            blacklisted = (abuse_score >= settings.INTEL_BLACKLIST_ABUSE_THRESHOLD) or (vt_malicious >= settings.INTEL_BLACKLIST_VT_THRESHOLD)
            
            reputation = "clean"
            if abuse_score > 50 or vt_malicious > 3:
                reputation = "malicious"
            elif abuse_score > 20:
                reputation = "suspicious"

            # Determine Geo risk
            geo_risk = 0.0
            if country in ["Russia", "China", "North Korea", "Iran"]:
                geo_risk = 0.8
            elif is_proxy:
                geo_risk = 0.5

            asn_risk = "high" if (is_proxy or is_hosting) else "low"

            model3_block = Model3Output(
                reputation=reputation,
                geo_risk=geo_risk,
                blacklisted=blacklisted,
                asn_risk=asn_risk
            )
        except Exception as mapping_exc:
            logger.error(
                "Model 3 parsing failed | trace_id=%s type=%s",
                trace_id,
                type(mapping_exc).__name__,
            )
            intel_avail = False
            degraded = True

    if not intel_avail:
        model3_block = None
        degraded = True

    # Map predictions to strict enum formats expected by the Decision Engine
    rf_pred_formatted = rf_class.capitalize()  # e.g., "Normal", "Suspicious", "Malicious"
    if rf_pred_formatted not in ["Normal", "Suspicious", "Malicious", "Unavailable"]:
        rf_pred_formatted = "Normal"

    m1_input = Model1Input(
        prediction=rf_pred_formatted,
        confidence=rf_prob / 100.0
    )
    m2_input = Model2Input(
        anomaly_score=if_norm
    )
    m3_input = None
    if intel_avail and intel_res is not None:
        m3_input = Model3Input(
            abuse_score=abuse_score,
            abuse_total_reports=abuse_total_reports,
            abuse_distinct_users=abuse_distinct_users,
            is_tor=is_tor,
            is_whitelisted=is_whitelisted,
            vt_malicious=vt_malicious,
            vt_suspicious=vt_suspicious,
            vt_harmless=vt_harmless,
            vt_total_engines=vt_total_engines,
            intel_score=intel_score,
            intel_severity=intel_severity,
            country=country,
            country_code=country_code,
            asn=asn,
            organization=organization,
            is_proxy=is_proxy,
            is_hosting=is_hosting,
            blacklisted=blacklisted,
        )

    decision_req = AnalyzeRequest(
        model1=m1_input,
        model2=m2_input,
        model3=m3_input,
        source_ip=ip,
        session_id=session_id
    )

    decision_res = get_decision_engine().analyze(decision_req)
    final_score = decision_res.final_score
    severity = decision_res.final_severity.upper()
    action = decision_res.recommended_action.upper()
    explanation = decision_res.explanation

    local_model_failed = rf_failed or if_failed
    analysis_status = "partial" if degraded else "complete"
    if local_model_failed and severity in ["SAFE", "NORMAL", "BENIGN", "LOW"]:
        severity = "UNKNOWN"
        action = "MONITOR"
        explanation.insert(0, "Analysis incomplete: a local detection model failed.")

    # Ensure no automatic firewall blocks
    if action == "BLOCK":
        explanation.insert(0, "Automatic firewall blocking is disabled by configuration. Manual intervention required.")

    # Construct Pydantic outputs for the response
    m1_output = Model1Output(anomaly_probability=round(rf_prob / 100.0, 4), classification=rf_class.lower())
    m2_output = Model2Output(anomaly_score=if_raw_score, is_anomaly=is_anomaly)

    # ── 6. Logging & DB Audit Trail ──────────────────────────────────────────
    if persist_result and threat_repo is not None:
        try:
            stored_score = await threat_repo.insert({
                "session_id": session_id,
                "source_ip": ip,
                "model1_prediction": rf_class,
                "model1_confidence": rf_prob / 100.0,
                "model2_anomaly_score": if_norm,
                "model3_intel_score": intel_score if intel_avail else None,
                "model1_contribution": (
                    decision_res.score_breakdown.model1_contribution
                ),
                "model2_contribution": (
                    decision_res.score_breakdown.model2_contribution
                ),
                "model3_contribution": (
                    decision_res.score_breakdown.model3_contribution
                ),
                "threat_score": final_score,
                "severity": severity,
                "recommendation": action,
                "reasoning": explanation,
                "model3_available": intel_avail,
            })
            if stored_score is None:
                diagnostic_key = "threat_score:not_persisted"
                if diagnostic_key not in _reported_runtime_diagnostics:
                    _reported_runtime_diagnostics.add(diagnostic_key)
                    logger.warning("Threat score was not persisted.")
        except Exception as db_exc:
            logger.error(
                "Audit log DB insert failed | trace_id=%s type=%s",
                trace_id,
                type(db_exc).__name__,
            )

    # ── 7. Phase 7 — Alert Generator Hook ─────────────────────────────────────
    if (
        persist_result
        and threat_repo is not None
        and severity in ("HIGH", "CRITICAL")
    ):
        try:
            alert_repo = ThreatAlertRepository(threat_repo._db)
            alert_service = AlertService(alert_repo)
            alert_gen = AlertGenerator(alert_service)
            
            alert_decision_data = {
                "source_ip": ip,
                "severity": severity,
                "action": action,
                "threat_score": final_score,
                "explanation": explanation,
                "trace_id": trace_id,
                "model1_score": rf_prob,
                "model2_score": if_norm,
                "model3_score": intel_score if intel_avail else 0.0,
                "model1_classification": rf_class,
                "model2_severity": "HIGH" if is_anomaly else "NORMAL",
                "model3_severity": intel_severity.upper() if intel_avail else "SAFE",
            }
            await alert_gen.generate_alert(alert_decision_data)
            logger.info("Threat alert generated/updated successfully for IP %s", ip)
        except Exception as alert_exc:
            logger.exception("Failed to generate/update threat alert: %s", alert_exc)

    # Explicit timing wrapper end
    latency_ms = (time.time() - start_time) * 1000
    
    logger.info(
        "Request finished | trace_id=%s target=%s score=%.2f action=%s latency=%.1fms (preprocess=%.1fms models=%.1fms)",
        trace_id, ip, final_score, action, latency_ms, preprocess_latency, model_latency
    )

    return UnifiedAnalyzeResponse(
        ip=ip,
        trace_id=trace_id,
        model_version=model_version,
        model1=m1_output,
        model2=m2_output,
        model3=model3_block,
        model3_available=intel_avail,
        model3_intelligence_score=intel_score if intel_avail else None,
        final_score=round(final_score, 2),
        severity=severity,
        action=action,
        explanation=explanation,
        degraded_mode=degraded,
        analysis_status=analysis_status,
        latency_ms=round(latency_ms, 2)
    )
