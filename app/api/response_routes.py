"""
CyberSentinel — Threat Response API Routes
============================================
REST API for SOC actions and threat queue management (Phase 8).
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.repositories import get_firewall_action_repo, get_threat_alert_repo
from app.repositories.repositories import FirewallActionRepository, ThreatAlertRepository
from app.schemas.response import (
    ActionHistoryResponse,
    AuditLogResponse,
    ResponseActionResult,
    ResponseBlockRequest,
    ResponseOverviewStats,
    ThreatQueueResponse,
)
from app.services.threat_response.alert_service import AlertService
from app.services.threat_response.response_service import ResponseService
from app.services.explainability.explanation_service import ExplanationService
from app.database.client import get_db_client
from app.api.auth_dependencies import get_current_analyst, AnalystIdentity
import uuid

async def get_analyst_note_repo(db=Depends(get_db_client)):
    from app.repositories.repositories import AnalystNoteRepository
    return AnalystNoteRepository(db)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/response", tags=["Threat Response Center — Phase 8"])


class ThreatActionNotes(BaseModel):
    notes: Optional[str] = None


def get_response_service(
    firewall_action_repo: FirewallActionRepository = Depends(get_firewall_action_repo),
    threat_alert_repo: ThreatAlertRepository = Depends(get_threat_alert_repo),
) -> ResponseService:
    alert_service = AlertService(threat_alert_repo)
    return ResponseService(firewall_action_repo, threat_alert_repo, alert_service)


@router.get("/overview", response_model=ResponseOverviewStats)
async def get_overview(
    service: ResponseService = Depends(get_response_service)
):
    stats = await service.get_overview_stats()
    return stats


@router.get("/threats", response_model=ThreatQueueResponse)
async def get_threats(
    page: int = 1,
    page_size: int = 50,
    service: ResponseService = Depends(get_response_service)
):
    items, total = await service.get_threat_queue(page, page_size)
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size
    }


@router.post("/threats/{alert_id}/investigate", response_model=dict)
async def investigate_threat(
    alert_id: str,
    service: ResponseService = Depends(get_response_service)
):
    updated = await service.investigate_threat(alert_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "success", "alert_id": alert_id}


@router.get("/threats/{alert_id}/explanation", response_model=dict)
async def get_threat_explanation(
    alert_id: str,
    threat_alert_repo: ThreatAlertRepository = Depends(get_threat_alert_repo)
):
    explanation_service = ExplanationService(threat_alert_repo)
    explanation = await explanation_service.build_alert_explanation(alert_id)
    if not explanation:
        raise HTTPException(status_code=404, detail="Alert not found")
    return explanation

class CreateNoteRequest(BaseModel):
    note: str

@router.get("/threats/{alert_id}/notes", response_model=list[dict])
async def get_threat_notes(
    alert_id: str,
    note_repo = Depends(get_analyst_note_repo)
):
    notes = await note_repo.get_by_alert(alert_id)
    return notes

@router.post("/threats/{alert_id}/notes", response_model=dict)
async def create_threat_note(
    alert_id: str,
    body: CreateNoteRequest,
    analyst: AnalystIdentity = Depends(get_current_analyst),
    threat_alert_repo: ThreatAlertRepository = Depends(get_threat_alert_repo),
    note_repo = Depends(get_analyst_note_repo)
):
    content = body.note.strip()
    if not (1 <= len(content) <= 1000):
        raise HTTPException(status_code=400, detail="Note content must be between 1 and 1000 characters.")

    # Check if alert exists
    alert = await threat_alert_repo.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    note_id = str(uuid.uuid4())
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    
    await note_repo.create({
        "id": note_id,
        "alert_id": alert_id,
        "analyst_id": str(analyst.user_id),
        "content": content,
        "created_at": now,
        "updated_at": now
    })
    
    # Audit log
    audit_data = {
        "action": "ADD_NOTE",
        "resource": "RESPONSE",
        "resource_id": alert_id,
        "user_id": str(analyst.user_id),
        "payload": {"note_id": note_id},
        "created_at": now
    }
    await threat_alert_repo._db.table("audit_logs").insert(audit_data).execute()
    
    return {"status": "success", "id": note_id}


@router.post("/threats/{alert_id}/resolve", response_model=dict)
async def resolve_threat(
    alert_id: str,
    body: ThreatActionNotes,
    analyst: AnalystIdentity = Depends(get_current_analyst),
    service: ResponseService = Depends(get_response_service)
):
    updated = await service.resolve_threat(alert_id, analyst.user_id, body.notes)
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "success", "alert_id": alert_id}


@router.post("/threats/{alert_id}/ignore", response_model=dict)
async def ignore_threat(
    alert_id: str,
    body: ThreatActionNotes,
    analyst: AnalystIdentity = Depends(get_current_analyst),
    service: ResponseService = Depends(get_response_service)
):
    updated = await service.ignore_threat(alert_id, analyst.user_id, body.notes)
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "success", "alert_id": alert_id}


@router.post("/block", response_model=ResponseActionResult)
async def block_ip(
    request: ResponseBlockRequest,
    analyst: AnalystIdentity = Depends(get_current_analyst),
    service: ResponseService = Depends(get_response_service)
):
    action = await service.block_ip(request.ip, analyst.user_id, request.reason)
    if not action:
        raise HTTPException(status_code=500, detail="Failed to block IP")
    
    return {
        "id": action.get("id", ""),
        "ip": action.get("ip", ""),
        "action": action.get("action", ""),
        "reason": action.get("reason"),
        "status": action.get("status", "SUCCESS"),
        "created_at": action.get("created_at"),
        "recorded": True,
        "enforced": False,
        "message": "Action recorded but not enforced at OS level."
    }


@router.post("/unblock", response_model=ResponseActionResult)
async def unblock_ip(
    request: ResponseBlockRequest,
    analyst: AnalystIdentity = Depends(get_current_analyst),
    service: ResponseService = Depends(get_response_service)
):
    action = await service.unblock_ip(request.ip, analyst.user_id, request.reason)
    if not action:
        raise HTTPException(status_code=500, detail="Failed to unblock IP")
    
    return {
        "id": action.get("id", ""),
        "ip": action.get("ip", ""),
        "action": action.get("action", ""),
        "reason": action.get("reason"),
        "status": action.get("status", "SUCCESS"),
        "created_at": action.get("created_at"),
        "recorded": True,
        "enforced": False,
        "message": "Action recorded but not enforced at OS level."
    }


@router.get("/history", response_model=ActionHistoryResponse)
async def get_history(
    page: int = 1,
    page_size: int = 50,
    service: ResponseService = Depends(get_response_service)
):
    items, total = await service.get_action_history(page, page_size)
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size
    }


@router.get("/audit-log", response_model=AuditLogResponse)
async def get_audit_log(
    page: int = 1,
    page_size: int = 50,
    service: ResponseService = Depends(get_response_service)
):
    items, total = await service.get_audit_log(page, page_size)
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size
    }
