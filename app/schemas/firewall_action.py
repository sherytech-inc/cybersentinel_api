"""
CyberSentinel — Firewall Action API Schemas
=============================================
Request and response contracts for Firewall Action endpoints.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class FirewallActionRequest(BaseModel):
    """Request to perform a firewall action on an IP."""
    ip: str = Field(..., examples=["185.220.101.45"])
    reason: Optional[str] = Field(None, examples=["DDoS Threat"])


class FirewallActionResponse(BaseModel):
    """Response after a firewall action is performed."""
    id: UUID
    ip: str
    action: str  # BLOCK | UNBLOCK | WHITELIST
    reason: Optional[str] = None
    source: str = "USER"  # USER | CHATBOT | AUTO
    created_at: datetime


class FirewallActionListResponse(BaseModel):
    items: list[FirewallActionResponse]
    total: int
    page: int
    page_size: int
