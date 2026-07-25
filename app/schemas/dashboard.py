"""
CyberSentinel — Dashboard Stats Schema
========================================
"""

from typing import Optional

from pydantic import BaseModel


class PacketClassification(BaseModel):
    normal: int = 0
    suspicious: int = 0
    malicious: int = 0


class MaliciousIPEntry(BaseModel):
    ip: str
    country: str = "Unknown"
    requests: int = 0
    threat_level: str = "High"


class DashboardSnapshot(BaseModel):
    active_threats: int = 0
    currently_blocked_ips: int = 0
    capture_diagnostics: dict = {}

class DashboardPeriod(BaseModel):
    time_range: str = "24h"
    total_threats: int = 0
    critical_threats: int = 0
    response_actions: int = 0
    recorded_blocks: int = 0

class DashboardStatsResponse(BaseModel):
    threat_score: int = 0
    snapshot: DashboardSnapshot = DashboardSnapshot()
    period: DashboardPeriod = DashboardPeriod()
    total_packets_count: int = 0
    suspicious_ips_count: int = 0
    packet_classification: PacketClassification = PacketClassification()
    malicious_ips: list[MaliciousIPEntry] = []
