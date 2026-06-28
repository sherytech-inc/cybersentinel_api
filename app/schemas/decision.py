"""
CyberSentinel — Model 4 Decision Engine Schemas
================================================
Stable I/O contract. Flutter dashboard + Report Engine consume DecisionResponse.

Key upgrade from original spec:
  Model3Input now accepts the FULL rich response from Model 3
  (abuse_score, vt_malicious, vt_suspicious, vt_total_engines, intel_score,
   intel_severity, country, asn, organization, is_tor, is_proxy)
  so the Decision Engine can make nuanced case-by-case judgements.
"""
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class PredictionLabel(str, Enum):
    NORMAL = "Normal"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"


class ThreatSeverity(str, Enum):
    SAFE = "Safe"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class RecommendedAction(str, Enum):
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    INVESTIGATE = "INVESTIGATE"
    ALERT = "ALERT"
    BLOCK = "BLOCK"


# ── Input sub-schemas ─────────────────────────────────────────────────────────

class Model1Input(BaseModel):
    """Random Forest Packet Classifier output."""
    prediction: PredictionLabel = Field(..., examples=["Malicious"])
    confidence: float = Field(..., examples=[0.94])

    @field_validator("confidence", mode="before")
    @classmethod
    def clamp_confidence(cls, v: object) -> float:
        try:
            v = float(v)
        except (TypeError, ValueError):
            raise ValueError("confidence must be a number")
        return round(max(0.0, min(1.0, v)), 4)


class Model2Input(BaseModel):
    """Isolation Forest Anomaly Detector output."""
    anomaly_score: float = Field(..., examples=[87.0])

    @field_validator("anomaly_score", mode="before")
    @classmethod
    def clamp_anomaly_score(cls, v: object) -> float:
        try:
            v = float(v)
        except (TypeError, ValueError):
            raise ValueError("anomaly_score must be a number")
        return round(max(0.0, min(100.0, v)), 4)


class Model3Input(BaseModel):
    """
    Full rich output from Model 3 Threat Intelligence Engine.
    All fields from IntelligenceResponse that affect scoring are included.
    """
    # AbuseIPDB
    abuse_score: float = Field(0.0, ge=0, le=100, description="AbuseIPDB confidence 0-100")
    abuse_total_reports: int = Field(0, ge=0)
    abuse_distinct_users: int = Field(0, ge=0)
    is_tor: bool = False
    is_whitelisted: bool = False

    # VirusTotal
    vt_malicious: int = Field(0, ge=0)
    vt_suspicious: int = Field(0, ge=0)
    vt_harmless: int = Field(0, ge=0)
    vt_total_engines: int = Field(0, ge=0)

    # Model 3 computed score (pre-computed intel score from Model 3)
    intel_score: float = Field(0.0, ge=0, le=100)
    intel_severity: str = "Safe"

    # GeoIP / network context
    country: Optional[str] = None
    country_code: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    is_proxy: bool = False
    is_hosting: bool = False


class AnalyzeRequest(BaseModel):
    """POST /api/v1/decision/analyze — full pipeline input."""
    model1: Model1Input
    model2: Model2Input
    model3: Optional[Model3Input] = None
    source_ip: Optional[str] = Field(None, examples=["185.220.101.45"])
    session_id: Optional[str] = None

    model_config = {
        "json_schema_extra": {
            "examples": [{
                "model1": {"prediction": "Malicious", "confidence": 0.96},
                "model2": {"anomaly_score": 89},
                "model3": {
                    "abuse_score": 91, "abuse_total_reports": 125,
                    "vt_malicious": 23, "vt_suspicious": 3,
                    "vt_total_engines": 70, "intel_score": 91,
                    "intel_severity": "Critical", "country": "Russia",
                    "is_tor": False, "is_proxy": True,
                },
                "source_ip": "185.220.101.45",
            }]
        }
    }


# ── Response schemas ──────────────────────────────────────────────────────────

class Model1Summary(BaseModel):
    classification: str
    confidence: float


class Model2Summary(BaseModel):
    threat_score: float
    severity: str


class Model3Summary(BaseModel):
    intel_score: float
    severity: str


class ScoreBreakdown(BaseModel):
    model1_raw_score: float
    model2_raw_score: float
    model3_raw_score: float
    model1_contribution: float
    model2_contribution: float
    model3_contribution: float
    model1_weight: float
    model2_weight: float
    model3_weight: float


class DecisionResponse(BaseModel):
    """
    Final output consumed by Flutter dashboard, Response Center, Report Engine.
    Schema matches the updated architecture spec exactly.
    """
    ip: Optional[str] = None

    # Per-model summaries (dashboard model breakdown panel)
    model1: Model1Summary
    model2: Model2Summary
    model3: Optional[Model3Summary] = None

    # Final verdict
    final_score: float = Field(..., ge=0, le=100)
    final_severity: ThreatSeverity
    recommended_action: RecommendedAction
    explanation: list[str]

    # Detailed breakdown for transparency panel
    score_breakdown: ScoreBreakdown
    model3_available: bool
    session_id: Optional[str] = None

    model_config = {"use_enum_values": True}