"""
CyberSentinel — Packet Capture API Routes
==========================================
REST endpoints for the real-time packet capture, flow inspection,
and feature extraction engine.

Phase 4.5: Capture → Parse → Flow → Feature → JSON
No model inference here — that's Phase 5 (Unified Analyze API).
"""

import logging
from uuid import uuid4
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.services.packet_capture.capture_service import (
    CaptureService,
    get_capture_service,
)
from app.schemas.packet import CaptureStatusResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Packet Capture Engine"])


# ── Request Schemas ───────────────────────────────────────────────────────────

class StartCaptureRequest(BaseModel):
    interface: Optional[str] = Field(None, examples=["en0"], description="Network interface (default from config)")


class ReplayPcapRequest(BaseModel):
    file_path: str = Field(..., examples=["/path/to/attack.pcap"], description="Absolute path to .pcap file")


# ── Capture Control ──────────────────────────────────────────────────────────

@router.get(
    "/capture/status", 
    summary="Capture engine status",
    response_model=CaptureStatusResponse
)
async def capture_status(
    service: CaptureService = Depends(get_capture_service),
) -> CaptureStatusResponse:
    """
    Returns the current state of the capture engine including:
    - State (idle/capturing/replaying/stopping/error)
    - Packets captured count
    - Parser stats (parsed/skipped)
    - Flow stats (active/finalized)
    - Feature stats (extracted/failed)
    """
    return service.get_status()


from fastapi import APIRouter, Depends, HTTPException, Query, Request
from app.api.auth_dependencies import AnalystIdentity, get_current_analyst

@router.post("/capture/start", summary="Start live packet capture")
async def capture_start(
    request: Request,
    body: StartCaptureRequest = StartCaptureRequest(),
    service: CaptureService = Depends(get_capture_service),
    analyst: AnalystIdentity = Depends(get_current_analyst),
):
    """
    Start live packet capture on the specified network interface.
    """
    token = request.headers.get("Authorization")
    if token:
        token = token.replace("Bearer ", "").strip()

    session_id = str(uuid4())
    try:
        await service.start_live(
            body.interface, jwt_token=token,
            session_id=session_id,
        )
        return {
            "status": "started",
            "session_id": session_id,
            "interface": body.interface or service._settings.CAPTURE_INTERFACE,
            "message": "Live capture started. Monitor via GET /capture/status",
        }
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.post("/capture/stop", summary="Stop capture")
async def capture_stop(
    service: CaptureService = Depends(get_capture_service),
):
    """
    Stop the current capture/replay session.
    All active flows are finalized and features extracted.
    """
    await service.stop()
    return {
        "status": "stopped",
        "message": "Capture stopped. All active flows finalized.",
        "final_stats": service.get_status(),
    }


@router.post("/capture/replay", summary="Replay a PCAP file")
async def capture_replay(
    request: Request,
    body: ReplayPcapRequest,
    service: CaptureService = Depends(get_capture_service),
    analyst: AnalystIdentity = Depends(get_current_analyst),
):
    """
    Replay packets from a .pcap file for analysis.

    **No sudo required** — ideal for FYP demos and testing.
    """
    token = request.headers.get("Authorization")
    if token:
        token = token.replace("Bearer ", "").strip()

    session_id = str(uuid4())
    try:
        await service.start_pcap(
            body.file_path, jwt_token=token,
            session_id=session_id,
        )
        return {
            "status": "replaying",
            "session_id": session_id,
            "file": body.file_path,
            "message": "PCAP replay started. Monitor via GET /capture/status",
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"PCAP file not found: {body.file_path}")
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))


# ── Flow Inspection ──────────────────────────────────────────────────────────

@router.get("/flows/active", summary="List active flows")
async def flows_active(
    service: CaptureService = Depends(get_capture_service),
):
    """
    Returns all currently open (not yet finalized) network flows.
    Each flow shows packet counts, byte counts, duration, and external IP metadata.
    """
    flows = service.flow_manager.get_active_flows()
    return {
        "items": [f.model_dump() for f in flows],
        "total": len(flows),
    }


@router.get("/flows/recent", summary="List recently finalized flows")
async def flows_recent(
    limit: int = Query(50, ge=1, le=500, description="Max flows to return"),
    service: CaptureService = Depends(get_capture_service),
):
    """
    Returns recently finalized flows (newest first).
    Includes finalization reason (timeout/max_age/manual_stop).
    """
    flows = service.flow_manager.get_recent_completed(limit)
    return {
        "items": [f.model_dump() for f in flows],
        "total": len(flows),
    }


# ── Feature Retrieval ────────────────────────────────────────────────────────

@router.get("/features/latest", summary="Latest extracted features")
async def features_latest(
    limit: int = Query(20, ge=1, le=200, description="Max features to return"),
    service: CaptureService = Depends(get_capture_service),
):
    """
    Returns the most recently extracted feature vectors (newest first).

    Each result contains:
    - flow_id, src_ip, dst_ip
    - external_ip (for future Model 3 integration)
    - is_internal_only flag
    - features: the 11-field vector matching Model 1+2 training schema

    The features dict can be passed directly to:
        ensemble.evaluate_packet(result["features"])
    """
    results = service.feature_extractor.get_recent(limit)
    return {
        "items": [r.model_dump() for r in results],
        "total": len(results),
    }
