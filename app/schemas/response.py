"""
CyberSentinel — Response Center API Schemas
=============================================
Request and response contracts for Threat Response endpoints.
"""

from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator
import json


class ResponseOverviewStats(BaseModel):
    active_threats: int
    blocked_ips: int
    total_actions: int


class ThreatQueueItem(BaseModel):
    alert_id: str
    source_ip: str
    severity: str
    action: str
    status: str
    threat_score: float
    summary: str
    explanation: list[str]
    model1_score: Optional[float] = None
    model2_score: Optional[float] = None
    model3_score: Optional[float] = None
    model1_classification: Optional[str] = None
    model2_severity: Optional[str] = None
    model3_severity: Optional[str] = None
    flow_id: Optional[str] = None
    session_id: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    analysis_status: Optional[str] = None
    occurrence_count: int
    created_at: datetime
    updated_at: datetime

    @field_validator('explanation', mode='before')
    @classmethod
    def parse_explanation(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                if isinstance(parsed, dict) and "reason" in parsed:
                    return [parsed["reason"]]
                if isinstance(parsed, list):
                    return [str(item) for item in parsed]
                return [str(parsed)]
            except json.JSONDecodeError:
                return [v]
        elif isinstance(v, dict) and "reason" in v:
            return [v["reason"]]
        return v



class ThreatQueueResponse(BaseModel):
    items: list[ThreatQueueItem]
    total: int
    page: int
    page_size: int


class ResponseBlockRequest(BaseModel):
    ip: str = Field(..., examples=["185.220.101.45"])
    reason: Optional[str] = Field(None, examples=["Malicious activity detected"])
    alert_id: Optional[str] = None


class ResponseActionResult(BaseModel):
    id: str
    ip: str
    action: str
    reason: Optional[str] = None
    analyst_name: Optional[str] = None
    note: Optional[str] = None
    related_alert: Optional[str] = None
    status: str
    created_at: datetime
    recorded: bool = True
    enforced: bool = False
    message: Optional[str] = "Action recorded but not enforced at OS level."


class ActionHistoryResponse(BaseModel):
    items: list[ResponseActionResult]
    total: int
    page: int
    page_size: int


class AuditLogEntry(BaseModel):
    id: str
    action: str
    target_ip: str
    reason: Optional[str] = None
    user_name: str
    details: Optional[dict] = None
    created_at: datetime


class AuditLogResponse(BaseModel):
    items: list[AuditLogEntry]
    total: int
    page: int
    page_size: int
