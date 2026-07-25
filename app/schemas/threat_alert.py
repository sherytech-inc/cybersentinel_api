from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field

class ThreatAlertResponse(BaseModel):
    alert_id: str
    source_ip: str
    severity: str
    action: str
    status: str
    threat_score: float
    summary: str
    explanation: list[str]  # JSONB array
    trace_id: Optional[str] = None
    
    # Model scores
    model1_score: Optional[float] = None
    model2_score: Optional[float] = None
    model3_score: Optional[float] = None
    
    # Model details
    model1_classification: Optional[str] = None
    model2_severity: Optional[str] = None
    model3_severity: Optional[str] = None
    
    occurrence_count: int
    timeline: list[dict[str, Any]]
    context_ready: bool
    created_at: datetime
    updated_at: datetime

class ThreatAlertListResponse(BaseModel):
    items: list[ThreatAlertResponse]
    total: int
    page: int
    page_size: int

class ThreatAlertStatsResponse(BaseModel):
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    open_alerts: int
    investigating_alerts: int
    blocked_alerts: int
    resolved_alerts: int
    active_investigations: int
    false_positives: int

class ThreatAlertStatusUpdate(BaseModel):
    status: str = Field(..., description="Lifecycle status: OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE")
    notes: Optional[str] = Field(None, description="Optional notes explaining status change")
