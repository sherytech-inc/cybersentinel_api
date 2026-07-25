"""
CyberSentinel — Copilot Context Schema
========================================
Payload contract for the AI Copilot context endpoint.
Designed for future RAG + LLM integration.
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class AlertSummary(BaseModel):
    ip: str
    severity: str
    action: str
    reasons: list[str] = []


class AttackTypeSummary(BaseModel):
    type: str
    count: int


class SystemHealthSummary(BaseModel):
    status: str = "operational"
    capture_state: str = "idle"
    packets_captured: int = 0


class CopilotContextResponse(BaseModel):
    latest_alerts: list[AlertSummary] = []
    critical_threats: list[AlertSummary] = []
    blocked_ips: list[str] = []
    top_attack_types: list[AttackTypeSummary] = []
    system_health: SystemHealthSummary = SystemHealthSummary()


class CopilotChatRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=4000)


class CopilotContextUsed(BaseModel):
    capture_state: str
    has_live_context: bool


class CopilotChatResponse(BaseModel):
    session_id: str
    intent: str
    response: str
    context_used: CopilotContextUsed
    timestamp: datetime
    available: bool
