"""CyberSentinel — Repositories package with FastAPI DI factories."""
from fastapi import Depends
from supabase import AsyncClient

from app.database.client import get_db_client
from app.repositories.repositories import (
    PacketRepository,
    FirewallLogRepository,
    VirusScanRepository,
    IPIntelligenceRepository,
    ThreatScoreRepository,
    ResponseActionRepository,
    ReportRepository,
    CopilotConversationRepository,
    FirewallActionRepository,
    ThreatAlertRepository,
    AnalystNoteRepository,
)


def get_packet_repo(db: AsyncClient = Depends(get_db_client)) -> PacketRepository:
    return PacketRepository(db)

def get_firewall_repo(db: AsyncClient = Depends(get_db_client)) -> FirewallLogRepository:
    return FirewallLogRepository(db)

def get_virus_repo(db: AsyncClient = Depends(get_db_client)) -> VirusScanRepository:
    return VirusScanRepository(db)

def get_ip_intel_repo(db: AsyncClient = Depends(get_db_client)) -> IPIntelligenceRepository:
    return IPIntelligenceRepository(db)

def get_threat_score_repo(db: AsyncClient = Depends(get_db_client)) -> ThreatScoreRepository:
    return ThreatScoreRepository(db)

def get_response_repo(db: AsyncClient = Depends(get_db_client)) -> ResponseActionRepository:
    return ResponseActionRepository(db)

def get_report_repo(db: AsyncClient = Depends(get_db_client)) -> ReportRepository:
    return ReportRepository(db)

def get_copilot_repo(db: AsyncClient = Depends(get_db_client)) -> CopilotConversationRepository:
    return CopilotConversationRepository(db)

def get_firewall_action_repo(db: AsyncClient = Depends(get_db_client)) -> FirewallActionRepository:
    return FirewallActionRepository(db)

def get_threat_alert_repo(db: AsyncClient = Depends(get_db_client)) -> ThreatAlertRepository:
    return ThreatAlertRepository(db)

def get_analyst_note_repo(db: AsyncClient = Depends(get_db_client)) -> AnalystNoteRepository:
    return AnalystNoteRepository(db)


__all__ = [
    "PacketRepository", "FirewallLogRepository", "VirusScanRepository",
    "IPIntelligenceRepository", "ThreatScoreRepository",
    "ResponseActionRepository", "ReportRepository",
    "CopilotConversationRepository", "FirewallActionRepository",
    "ThreatAlertRepository", "AnalystNoteRepository",
    "get_packet_repo", "get_firewall_repo", "get_virus_repo",
    "get_ip_intel_repo", "get_threat_score_repo", "get_response_repo",
    "get_report_repo", "get_copilot_repo", "get_firewall_action_repo",
    "get_threat_alert_repo", "get_analyst_note_repo",
]
