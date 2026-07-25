"""
CyberSentinel — Threat Intelligence Schemas
Stable contract consumed by Model 4 (Decision Engine).
"""
import re
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, field_validator

class IntelSeverity(str, Enum):
    SAFE = "Safe"
    LOW = "Low"
    HIGH = "High"
    CRITICAL = "Critical"

class IntelStatus(str, Enum):
    completed = "completed"
    partial = "partial"
    not_configured = "not_configured"
    not_found = "not_found"
    quota_exceeded = "quota_exceeded"
    unavailable = "unavailable"
    invalid_target = "invalid_target"
    failed = "failed"

class IntelProviderStatus(str, Enum):
    completed = "completed"
    not_configured = "not_configured"
    not_found = "not_found"
    quota_exceeded = "quota_exceeded"
    unavailable = "unavailable"

_IPV4_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_PRIVATE_PREFIXES = (
    "10.", "192.168.", "127.", "172.16.", "172.17.",
    "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
    "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "169.254.", "0.",
)

class IPLookupRequest(BaseModel):
    ip: str = Field(..., examples=["8.8.8.8"])

class BulkIPLookupRequest(BaseModel):
    ips: list[str] = Field(
        ..., 
        min_length=1, 
        max_length=50, 
        examples=[["8.8.8.8", "1.1.1.1"]]
    )

class ProviderState(BaseModel):
    status: IntelProviderStatus
    message: Optional[str] = None

class VirusTotalIntelResult(ProviderState):
    malicious: Optional[int] = None
    suspicious: Optional[int] = None
    harmless: Optional[int] = None
    undetected: Optional[int] = None
    total_engines: Optional[int] = None
    last_analysis_date: Optional[str] = None

class AbuseIpDbIntelResult(ProviderState):
    abuse_confidence_score: Optional[int] = None
    total_reports: Optional[int] = None
    num_distinct_users: Optional[int] = None
    is_whitelisted: Optional[bool] = None
    is_tor: Optional[bool] = None

class GeoIpIntelResult(ProviderState):
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    isp: Optional[str] = None
    is_proxy: Optional[bool] = None
    is_hosting: Optional[bool] = None

class IntelligenceResponse(BaseModel):
    ip: str
    status: IntelStatus

    intel_score: Optional[int] = None
    severity: Optional[str] = None
    score_confidence: Optional[str] = None
    providers_used: list[str] = Field(default_factory=list)
    providers_queried: list[str] = Field(default_factory=list)
    providers_available: list[str] = Field(default_factory=list)
    analysis_status: Optional[str] = None

    virustotal: VirusTotalIntelResult
    abuseipdb: AbuseIpDbIntelResult
    geoip: GeoIpIntelResult

    message: str
    looked_up_at: datetime
    
    cached: bool = False

    model_config = {"use_enum_values": True}

class BulkIntelligenceResponse(BaseModel):
    results: dict[str, IntelligenceResponse] = Field(default_factory=dict)
    responses: list[IntelligenceResponse] = Field(default_factory=list)

class HealthResponse(BaseModel):
    status: str = "online"
    message: Optional[str] = None
    version: Optional[str] = None
    
    model_config = {"extra": "allow"}
