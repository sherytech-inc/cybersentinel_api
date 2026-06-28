"""
CyberSentinel — Threat Intelligence Schemas
Stable contract consumed by Model 4 (Decision Engine).
"""
import re
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, field_validator

class IntelSeverity(str, Enum):
    SAFE = "Safe"
    LOW = "Low"
    HIGH = "High"
    CRITICAL = "Critical"

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

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        v = v.strip()
        if not _IPV4_RE.match(v):
            raise ValueError(f"'{v}' is not a valid IPv4 address.")
        if any(v.startswith(p) for p in _PRIVATE_PREFIXES):
            raise ValueError(f"'{v}' is a private/reserved address.")
        return v

class BulkIPLookupRequest(BaseModel):
    ips: list[str] = Field(
        ..., 
        min_length=1, 
        max_length=50, 
        examples=[["8.8.8.8", "1.1.1.1"]]
    )

    @field_validator("ips")
    @classmethod
    def validate_bulk_ips(cls, v: list[str]) -> list[str]:
        valid_ips = []
        for ip in v:
            valid_ips.append(IPLookupRequest.validate_ip(ip))
        return valid_ips

class AbuseIPDBResult(BaseModel):
    abuse_confidence_score: int = Field(0, ge=0, le=100)
    total_reports: int = 0
    num_distinct_users: int = 0
    is_whitelisted: bool = False
    is_tor: bool = False

class VirusTotalResult(BaseModel):
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_harmless: int = 0
    vt_undetected: int = 0
    vt_total_engines: int = 0
    last_analysis_date: Optional[str] = None

class GeoIPResult(BaseModel):
    country: str = "Unknown"
    country_code: str = "XX"
    city: Optional[str] = None
    asn: str = "Unknown"
    organization: str = "Unknown"
    isp: Optional[str] = None
    is_proxy: bool = False
    is_hosting: bool = False

class IntelligenceResponse(BaseModel):
    ip: str
    abuse_score: int = 0
    abuse_total_reports: int = 0
    abuse_distinct_users: int = 0
    is_tor: bool = False
    is_whitelisted: bool = False
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_harmless: int = 0
    vt_total_engines: int = 0
    vt_last_analysis_date: Optional[str] = None
    country: str = "Unknown"
    country_code: str = "XX"
    city: Optional[str] = None
    asn: str = "Unknown"
    organization: str = "Unknown"
    isp: Optional[str] = None
    is_proxy: bool = False
    is_hosting: bool = False
    intel_score: int = Field(0, ge=0, le=100)
    intel_severity: IntelSeverity = IntelSeverity.SAFE
    cached: bool = False
    providers_available: list[str] = []
    providers_failed: list[str] = []

    model_config = {"use_enum_values": True}

class BulkIntelligenceResponse(BaseModel):
    results: dict[str, IntelligenceResponse] = Field(default_factory=dict)
    responses: list[IntelligenceResponse] = Field(default_factory=list)

class HealthResponse(BaseModel):
    status: str = "online"
    message: Optional[str] = None
    version: Optional[str] = None
    
    model_config = {"extra": "allow"}