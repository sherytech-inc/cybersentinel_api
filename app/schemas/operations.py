"""
CyberSentinel — Remaining API Schemas
=======================================
Virus Scanner, Response Actions, Reports, Copilot.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from enum import Enum
from pydantic import BaseModel, Field


# ─────────────────────────────────────────────────────────────────────────────
# Virus Scanner
# ─────────────────────────────────────────────────────────────────────────────

class ScanStatus(str, Enum):
    complete = "complete"
    completed = "complete"
    pending = "pending"
    not_found = "not_found"
    not_configured = "not_configured"
    quota_exceeded = "quota_exceeded"
    unavailable = "unavailable"
    invalid_target = "invalid_target"
    failed = "failed"
    file_too_large = "file_too_large"


class VirusScanRequest(BaseModel):
    scan_target: str = Field(..., description="File hash (SHA-256), URL, or IP address.")
    scan_type: str = Field(..., examples=["hash", "url", "ip"])


class URLScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)


class HashScanRequest(BaseModel):
    hash: str = Field(min_length=1, max_length=64)


class VirusScanResponse(BaseModel):
    scan_id: Optional[UUID] = None
    target: str
    scan_type: str
    status: ScanStatus
    verdict: str = "unknown"
    provider: str = "VIRUSTOTAL"
    provider_contacted: bool = False
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    analysis_id: Optional[str] = None
    message: Optional[str] = None
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
