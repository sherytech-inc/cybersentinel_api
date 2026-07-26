"""Read-only firewall log analysis contracts."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


FirewallAction = Literal["allow", "deny", "drop", "reject", "unknown"]
FirewallDirection = Literal["inbound", "outbound", "unknown"]
ParseStatus = Literal["complete", "partial", "failed"]


class FirewallNormalizedEvent(BaseModel):
    event_id: str
    timestamp: datetime | None = None
    action: FirewallAction = "unknown"
    direction: FirewallDirection = "unknown"
    interface: str | None = None
    protocol: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    packet_size: int | None = Field(default=None, ge=0)
    flags: str | None = None
    rule: str | None = None
    raw_line_number: int = Field(ge=1)
    parse_status: ParseStatus
    messages: list[str] = Field(default_factory=list)


class FirewallCountEntry(BaseModel):
    value: str
    count: int = Field(ge=1)


class FirewallPortCountEntry(BaseModel):
    port: int = Field(ge=0, le=65535)
    count: int = Field(ge=1)


class FirewallAnalysisLimits(BaseModel):
    max_upload_bytes: int
    max_lines: int
    max_line_length: int
    max_events_returned: int
    max_warning_samples: int


class FirewallAnalysisSummary(BaseModel):
    detected_format: str
    total_lines: int = Field(ge=0)
    parsed_events: int = Field(ge=0)
    complete_events: int = Field(ge=0)
    partial_events: int = Field(ge=0)
    failed_lines: int = Field(ge=0)
    allowed_count: int = Field(ge=0)
    denied_dropped_count: int = Field(ge=0)
    inbound_count: int = Field(ge=0)
    outbound_count: int = Field(ge=0)
    protocol_distribution: list[FirewallCountEntry] = Field(default_factory=list)
    top_source_ips: list[FirewallCountEntry] = Field(default_factory=list)
    top_destination_ips: list[FirewallCountEntry] = Field(default_factory=list)
    top_destination_ports: list[FirewallPortCountEntry] = Field(default_factory=list)
    first_timestamp: datetime | None = None
    last_timestamp: datetime | None = None
    malformed_line_count: int = Field(ge=0)
    warnings: list[str] = Field(default_factory=list)


class FirewallAnalysisResponse(BaseModel):
    status: Literal["complete", "partial"]
    filename: str
    summary: FirewallAnalysisSummary
    events: list[FirewallNormalizedEvent]
    limits: FirewallAnalysisLimits
    events_truncated: bool = False


class FirewallAnalysisError(BaseModel):
    status: Literal[
        "unsupported_format",
        "invalid_file",
        "file_too_large",
        "unavailable",
    ]
    message: str
