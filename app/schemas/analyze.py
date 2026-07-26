"""
CyberSentinel — Unified Analyze API Schemas
============================================
Defines request and response contracts for the single orchestrator endpoint.
Enforces strict 11-field schema and protocol checks.
"""

from typing import Any, Literal, Optional
from pydantic import BaseModel, Field, field_validator


class AnalyzeFlowRequest(BaseModel):
    """
    Accepts IP + 11 strict network flow features from client.
    """
    ip: str = Field(..., examples=["185.220.101.45"], description="Target IP to analyze")
    flow_features: dict[str, Any] = Field(..., description="Must contain exactly 11 features matching training schema")
    session_id: Optional[str] = Field(None, description="Optional session or trace ID mapping")

    @field_validator("flow_features")
    @classmethod
    def validate_features(cls, v: dict[str, Any]) -> dict[str, Any]:
        # Enforce exact feature keys and order matching training
        from app.services.model2_tools.encoder import FEATURE_COLUMNS
        
        expected = set(FEATURE_COLUMNS)
        actual = set(v.keys())
        if expected != actual:
            missing = expected - actual
            extra = actual - expected
            err_msg = "Feature validation failed."
            if missing:
                err_msg += f" Missing fields: {list(missing)}."
            if extra:
                err_msg += f" Extra fields: {list(extra)}."
            raise ValueError(err_msg)
            
        v = v.copy()
        # Enforce protocol constraint
        if str(v["protocol"]).upper() not in ["TCP", "UDP", "ICMP", "OTHER"]:
            raise ValueError("Protocol must be one of: TCP, UDP, ICMP, OTHER")
            
        # Ensure correct datatypes
        for key in FEATURE_COLUMNS:
            if key == "protocol":
                v[key] = str(v[key]).upper()
            elif key == "destination_port":
                v[key] = int(float(v[key]))
            else:
                v[key] = float(v[key])
                
        return v


class Model1Output(BaseModel):
    name: str = "Random Forest"
    anomaly_probability: float = Field(..., description="Probability of malicious behavior (0-1)")
    classification: str = Field(..., description="benign | suspicious | malicious")


class Model2Output(BaseModel):
    name: str = "Isolation Forest"
    anomaly_score: float = Field(..., description="Raw decision function anomaly score")
    is_anomaly: bool = Field(..., description="Outlier detection flag (True if predict == -1)")


class Model3Output(BaseModel):
    name: str = "Threat Intelligence"
    reputation: str = Field(..., description="malicious | suspicious | clean")
    geo_risk: float = Field(..., ge=0.0, le=1.0, description="Risk indicator from IP location (0-1)")
    blacklisted: bool = Field(..., description="True if IP is present in third-party database logs")
    asn_risk: str = Field(..., description="high | low")


class UnifiedAnalyzeResponse(BaseModel):
    ip: str = Field(..., examples=["185.220.101.45"])
    trace_id: str = Field(..., description="Correlated trace ID for security audit tracing")
    model_version: str = Field(..., description="Release version mapping of loaded ML classifiers")
    model1: Model1Output
    model2: Model2Output
    model3: Optional[Model3Output] = None
    model3_available: bool = Field(..., description="True if external threat intelligence enrichment was reachable")
    model3_intelligence_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=100.0,
        description="Normalized intelligence score when Model 3 is available",
    )
    final_score: float = Field(..., ge=0.0, le=100.0, description="Weighted composite risk score")
    severity: str = Field(..., description="LOW | MEDIUM | HIGH | CRITICAL")
    action: str = Field(..., description="ALLOW | MONITOR | ALERT | BLOCK")
    explanation: list[str] = Field(..., description="Impact-ranked list of dynamic explanations")
    degraded_mode: bool = Field(False, description="True if any backend module failed, forcing fallback logic")
    analysis_status: Literal["complete", "partial", "failed"] = "complete"
    latency_ms: float = Field(..., description="Total execution time in milliseconds")
