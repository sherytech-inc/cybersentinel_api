"""
CyberSentinel — Remaining API Schemas
=======================================
Virus Scanner, Response Actions, Reports, Copilot.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


# ─────────────────────────────────────────────────────────────────────────────
# Virus Scanner
# ─────────────────────────────────────────────────────────────────────────────

class VirusScanRequest(BaseModel):
    scan_target: str = Field(..., description="File hash (SHA-256), URL, or IP address.")
    scan_type: str = Field(..., examples=["file", "url", "ip"])
    file_name: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    file_size_bytes: Optional[int] = None


class VirusScanResponse(BaseModel):
    id: UUID
    scan_target: str
    scan_type: str
    file_name: Optional[str] = None
    vt_malicious: int
    vt_suspicious: int
    vt_harmless: int
    vt_total_engines: int
    vt_permalink: Optional[str] = None
    threat_level: Optional[str] = None
    threat_score: Optional[float] = None
    status: str
    scanned_at: Optional[datetime] = None


# ─────────────────────────────────────────────────────────────────────────────
# Response Actions
# ─────────────────────────────────────────────────────────────────────────────

class ResponseActionRequest(BaseModel):
    source_ip: Optional[str] = None
    threat_score_id: Optional[UUID] = None
    action_type: str = Field(..., examples=["block", "monitor", "investigate"])
    notes: Optional[str] = None


class ResponseActionResponse(BaseModel):
    id: UUID
    source_ip: Optional[str] = None
    action_type: str
    action_status: str
    triggered_by: str
    notes: Optional[str] = None
    executed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


# ─────────────────────────────────────────────────────────────────────────────
# Reports
# ─────────────────────────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    report_type: str = Field(..., examples=["daily", "weekly", "incident", "custom"])
    title: Optional[str] = None
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None


class ReportResponse(BaseModel):
    id: UUID
    report_type: str
    title: str
    status: str
    file_path: Optional[str] = None
    file_size_bytes: Optional[int] = None
    generated_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


# ─────────────────────────────────────────────────────────────────────────────
# Copilot
# ─────────────────────────────────────────────────────────────────────────────

class CopilotRequest(BaseModel):
    """User query to the CyberSentinel Security Copilot."""
    message: str = Field(
        ...,
        min_length=3,
        max_length=2000,
        examples=["Why was 185.220.101.45 flagged as critical?"],
    )
    session_id: Optional[str] = Field(
        default=None,
        description="Conversation session ID for multi-turn context.",
    )
    context_ip: Optional[str] = Field(
        default=None,
        description="Source IP to load as context for RAG retrieval.",
    )


class CopilotResponse(BaseModel):
    """Full copilot response with RAG context metadata."""
    response: str
    session_id: str
    context_sources: list[str] = Field(
        default_factory=list,
        description="Which data sources were used for RAG context.",
    )
    tokens_used: int = 0
    model_used: str = ""
