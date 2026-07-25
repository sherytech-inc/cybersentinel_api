"""
CyberSentinel — Flow & Parsed Packet Schemas
=============================================
Pydantic models for the packet capture → flow aggregation pipeline.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class ParsedPacket(BaseModel):
    """A single parsed packet extracted from PyShark capture."""
    timestamp: float = Field(..., description="Unix timestamp with microsecond precision")
    src_ip: str = Field(..., description="Source IP address")
    dst_ip: str = Field(..., description="Destination IP address")
    src_port: int = Field(0, ge=0, le=65535, description="Source port (0 for ICMP)")
    dst_port: int = Field(0, ge=0, le=65535, description="Destination port (0 for ICMP)")
    protocol: str = Field(..., description="TCP, UDP, ICMP, or OTHER")
    packet_length: int = Field(..., ge=0, description="Total packet length in bytes")


class FlowKey(BaseModel):
    """Canonical bidirectional flow identifier."""
    ip_a: str
    ip_b: str
    port_a: int
    port_b: int
    protocol: str

    def __hash__(self):
        return hash((self.ip_a, self.ip_b, self.port_a, self.port_b, self.protocol))

    def __eq__(self, other):
        if not isinstance(other, FlowKey):
            return False
        return (
            self.ip_a == other.ip_a
            and self.ip_b == other.ip_b
            and self.port_a == other.port_a
            and self.port_b == other.port_b
            and self.protocol == other.protocol
        )


class FlowStateResponse(BaseModel):
    """Active flow state — returned by /flows/active endpoint."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    fwd_packets: int = Field(..., description="Packets from initiator → responder")
    bwd_packets: int = Field(..., description="Packets from responder → initiator")
    fwd_bytes: int
    bwd_bytes: int
    total_packets: int
    total_bytes: int
    duration_seconds: float
    started_at: str
    last_activity: str
    external_ip: Optional[str] = Field(None, description="External IP in this flow (if any)")
    is_internal_only: bool = Field(False, description="True if both IPs are private/reserved")


class CompletedFlowResponse(BaseModel):
    """Finalized flow — returned by /flows/recent endpoint."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    fwd_packets: int
    bwd_packets: int
    fwd_bytes: int
    bwd_bytes: int
    total_packets: int
    total_bytes: int
    duration_seconds: float
    started_at: str
    ended_at: str
    finalized_reason: str = Field(..., description="timeout | max_age | manual_stop")
    external_ip: Optional[str] = None
    is_internal_only: bool = False
