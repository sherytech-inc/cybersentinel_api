"""
CyberSentinel — Domain Models
==============================
Pydantic models for:
  - Packets
  - Firewall Logs
  - Virus Scans
  - Response Actions
  - Reports

These are the database row representations — used by repositories
to deserialise Supabase responses into typed Python objects.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


# ─────────────────────────────────────────────────────────────────────────────
# Packet
# ─────────────────────────────────────────────────────────────────────────────

class PacketModel(BaseModel):
    id: Optional[UUID] = None
    session_id: Optional[str] = None
    source_ip: str
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    packet_size: Optional[int] = None
    flow_duration: Optional[float] = None
    fwd_packet_length_mean: Optional[float] = None
    bwd_packet_length_mean: Optional[float] = None
    flow_bytes_per_sec: Optional[float] = None
    flow_packets_per_sec: Optional[float] = None
    ml_prediction: Optional[str] = None
    ml_confidence: Optional[float] = None
    anomaly_score: Optional[float] = None
    threat_score: Optional[float] = None
    severity: Optional[str] = None
    captured_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


# ─────────────────────────────────────────────────────────────────────────────
# Firewall Log
# ─────────────────────────────────────────────────────────────────────────────

class FirewallLogModel(BaseModel):
    id: Optional[UUID] = None
    source_ip: str
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    action: str                         # ALLOW | BLOCK | DROP
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    anomaly_score: Optional[float] = None
    is_anomalous: bool = False
    interface: Optional[str] = None
    direction: Optional[str] = None
    logged_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


# ─────────────────────────────────────────────────────────────────────────────
# Virus Scan
# ─────────────────────────────────────────────────────────────────────────────

class VirusScanModel(BaseModel):
    id: Optional[UUID] = None
    scan_target: str
    scan_type: str                      # file | url | ip
    file_name: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    file_size_bytes: Optional[int] = None
    vt_scan_id: Optional[str] = None
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_harmless: int = 0
    vt_undetected: int = 0
    vt_total_engines: int = 0
    vt_permalink: Optional[str] = None
    threat_level: Optional[str] = None
    threat_score: Optional[float] = None
    status: str = "pending"
    scanned_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


# ─────────────────────────────────────────────────────────────────────────────
# Response Action
# ─────────────────────────────────────────────────────────────────────────────

class ResponseActionModel(BaseModel):
    id: Optional[UUID] = None
    threat_score_id: Optional[UUID] = None
    source_ip: Optional[str] = None
    action_type: str                    # block | monitor | allow | investigate
    action_status: str = "pending"
    triggered_by: str = "system"
    executed_by: Optional[UUID] = None
    notes: Optional[str] = None
    executed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


# ─────────────────────────────────────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────────────────────────────────────

class ReportModel(BaseModel):
    id: Optional[UUID] = None
    report_type: str                    # daily | weekly | incident | custom
    title: str
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    generated_by: Optional[UUID] = None
    file_path: Optional[str] = None
    file_size_bytes: Optional[int] = None
    status: str = "generating"
    metadata: dict = Field(default_factory=dict)
    generated_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
