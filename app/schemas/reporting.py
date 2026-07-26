"""Stable contracts for the local Reports & Intelligence API."""

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


SourceAvailability = Literal["available", "unavailable"]
ReportTimeframe = Literal[
    "current_session",
    "last_session",
    "recent_history",
    "unavailable",
]
MonitoringState = Literal["running", "stopping", "stopped", "inactive"]


class ReportSessionSummary(BaseModel):
    captured: int = Field(0, ge=0)
    analyzed: int = Field(0, ge=0)
    pending: int = Field(0, ge=0)
    complete: int = Field(0, ge=0)
    partial: int = Field(0, ge=0)
    failed: int = Field(0, ge=0)
    deferred: int = Field(0, ge=0)
    not_analyzed: int = Field(0, ge=0)
    completion_percentage: float = Field(0.0, ge=0.0, le=100.0)
    threat_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    highest_severity: Optional[str] = None


class ClassificationDistribution(BaseModel):
    normal: int = Field(0, ge=0)
    suspicious: int = Field(0, ge=0)
    malicious: int = Field(0, ge=0)
    unknown: int = Field(0, ge=0)


class SeverityDistribution(BaseModel):
    low: int = Field(0, ge=0)
    medium: int = Field(0, ge=0)
    high: int = Field(0, ge=0)
    critical: int = Field(0, ge=0)
    unknown: int = Field(0, ge=0)


class ThreatTypeSummary(BaseModel):
    threat_type: str
    count: int = Field(ge=1)


class AttackerSummary(BaseModel):
    source_ip: str
    count: int = Field(ge=1)
    highest_severity: Optional[str] = None
    country: Optional[str] = None


class RecentAlertSummary(BaseModel):
    alert_id: str
    timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    threat_type: Optional[str] = None
    severity: Optional[str] = None
    score: Optional[float] = None
    status: Optional[str] = None
    action: Optional[str] = None
    summary: Optional[str] = None


class ResponseTimelineEntry(BaseModel):
    action_id: str
    timestamp: Optional[str] = None
    target: Optional[str] = None
    action: str
    status: Optional[str] = None
    analyst: Optional[str] = None
    related_alert: Optional[str] = None
    result: Optional[str] = None
    platform: Optional[str] = None


class ModelAvailability(BaseModel):
    model1_evaluated: int = Field(0, ge=0)
    model2_evaluated: int = Field(0, ge=0)
    model3_available: Optional[int] = Field(None, ge=0)
    partial_analysis: int = Field(0, ge=0)
    failed_analysis: int = Field(0, ge=0)


class ReportSourceStatus(BaseModel):
    capture: SourceAvailability = "unavailable"
    alerts: SourceAvailability = "unavailable"
    actions: SourceAvailability = "unavailable"
    intelligence: SourceAvailability = "unavailable"


class ReportSummary(BaseModel):
    generated_at: datetime
    timeframe: ReportTimeframe
    monitoring_state: MonitoringState
    interface: Optional[str] = None
    session: ReportSessionSummary
    classification_distribution: ClassificationDistribution
    severity_distribution: SeverityDistribution
    top_threat_types: list[ThreatTypeSummary] = Field(default_factory=list)
    top_attackers: list[AttackerSummary] = Field(default_factory=list)
    recent_alerts: list[RecentAlertSummary] = Field(default_factory=list)
    response_timeline: list[ResponseTimelineEntry] = Field(default_factory=list)
    model_availability: ModelAvailability
    source_status: ReportSourceStatus
    messages: list[str] = Field(default_factory=list)
