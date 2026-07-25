"""
CyberSentinel — Packet API Schemas
====================================
Request and response contracts for the Packet Tracing endpoints.
Separate from domain models — these define the HTTP API surface.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field
from enum import Enum


class CaptureDaemonState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    REPLAY = "replay"
    STOPPING = "stopping"
    ERROR = "error"


class CaptureStatusResponse(BaseModel):
    state: CaptureDaemonState
    interface: Optional[str] = None
    started_at: Optional[datetime] = None
    error: Optional[str] = None
    session_id: Optional[str] = None
    
    # Optional fields for backward compatibility with existing stats
    packets_captured: Optional[int] = None
    parser: Optional[dict] = None
    flows: Optional[dict] = None
    features: Optional[dict] = None
    config: Optional[dict] = None
    analysis: Optional[dict] = None


class PacketIngestRequest(BaseModel):
    """Ingest a single captured packet for ML classification."""
    session_id: Optional[str] = None
    source_ip: str = Field(..., examples=["192.168.1.100"])
    destination_ip: Optional[str] = None
    source_port: Optional[int] = Field(None, ge=0, le=65535)
    destination_port: Optional[int] = Field(None, ge=0, le=65535)
    protocol: Optional[str] = None
    packet_size: Optional[int] = Field(None, ge=0)
    flow_duration: Optional[float] = Field(None, ge=0)
    fwd_packet_length_mean: Optional[float] = None
    bwd_packet_length_mean: Optional[float] = None
    flow_bytes_per_sec: Optional[float] = None
    flow_packets_per_sec: Optional[float] = None


class PacketResponse(BaseModel):
    id: UUID
    session_id: Optional[str] = None
    source_ip: str
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    packet_size: Optional[int] = None
    ml_prediction: Optional[str] = None
    ml_confidence: Optional[float] = None
    anomaly_score: Optional[float] = None
    threat_score: Optional[float] = None
    severity: Optional[str] = None
    flow_features: Optional[dict] = None
    captured_at: Optional[datetime] = None


class PacketListResponse(BaseModel):
    items: list[PacketResponse]
    total: int
    page: int
    page_size: int


class PacketStatsResponse(BaseModel):
    total_packets: int
    normal_count: int
    suspicious_count: int
    malicious_count: int
    average_threat_score: float
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
