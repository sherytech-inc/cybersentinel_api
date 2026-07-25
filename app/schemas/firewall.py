"""
CyberSentinel — Firewall Log API Schemas
==========================================
Request and response contracts for the Firewall Log endpoints.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class FirewallLogIngestRequest(BaseModel):
    """Single firewall log line ingest."""
    source_ip: str = Field(..., examples=["10.0.0.5"])
    destination_ip: Optional[str] = None
    source_port: Optional[int] = Field(None, ge=0, le=65535)
    destination_port: Optional[int] = Field(None, ge=0, le=65535)
    protocol: Optional[str] = None
    action: str = Field(..., examples=["BLOCK"])   # ALLOW | BLOCK | DROP
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    interface: Optional[str] = None
    direction: Optional[str] = None               # inbound | outbound
    logged_at: Optional[datetime] = None
    import_id: Optional[UUID] = None
    source_line_number: Optional[int] = None


class FirewallLogBulkRequest(BaseModel):
    """Bulk ingest — up to 500 log lines per call."""
    logs: list[FirewallLogIngestRequest] = Field(..., min_length=1, max_length=500)


class FirewallLogResponse(BaseModel):
    id: UUID
    source_ip: str
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    action: str
    rule_name: Optional[str] = None
    anomaly_score: Optional[float] = None
    is_anomalous: bool
    logged_at: Optional[datetime] = None


class FirewallLogListResponse(BaseModel):
    items: list[FirewallLogResponse]
    total: int
    page: int
    page_size: int


class FirewallStatsResponse(BaseModel):
    total_logs: int
    blocked_count: int
    allowed_count: int
    anomalous_count: int
    top_blocked_ips: list[dict]
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
