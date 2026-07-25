from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from typing import Dict, Any

from app.api.auth_dependencies import get_current_analyst, verify_local_token
from app.models.capture_capability import CaptureCapabilityResult
from app.services.capture_capability_service import CaptureCapabilityService
from app.services.packet_capture.capture_service import get_capture_service
import shutil
import tempfile
import os
from fastapi import UploadFile, File

router = APIRouter(
    prefix="/api/v1/capture",
    tags=["capture"],
    dependencies=[Depends(verify_local_token), Depends(get_current_analyst)]
)

_service = CaptureCapabilityService()

class ProbeRequest(BaseModel):
    interface_id: str

class StartCaptureRequest(BaseModel):
    interface: str

@router.get("/capabilities", response_model=CaptureCapabilityResult)
async def get_capabilities():
    """Returns the latest complete capability result."""
    return _service.get_capabilities()

@router.post("/capabilities/refresh", response_model=CaptureCapabilityResult)
async def refresh_capabilities():
    """Performs a new dependency, interface and permission check."""
    return _service.refresh_capabilities()

@router.post("/probe", response_model=CaptureCapabilityResult)
async def run_probe(request: ProbeRequest):
    """Request a bounded capture probe on a specific interface."""
    return _service.run_probe(request.interface_id)

@router.post("/remediation/status", response_model=Dict[str, Any])
async def check_remediation_status():
    """Returns whether the required platform helper/dependency is now available (executes remediation on macOS)."""
    success = _service.execute_remediation()
    return {"success": success, "capabilities": _service.get_capabilities().dict()}

@router.post("/start", response_model=Dict[str, Any])
async def start_capture(body: StartCaptureRequest, request: Request):
    """Start live packet capture on a specific interface."""
    cap_service = get_capture_service()
    try:
        authorization = request.headers.get("authorization", "")
        scheme, _, access_token = authorization.partition(" ")
        await cap_service.start_live(
            interface=body.interface,
            jwt_token=access_token if scheme.lower() == "bearer" else None,
        )
        return {"status": "success", "message": "Live capture started."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/replay", response_model=Dict[str, Any])
async def replay_pcap(file: UploadFile = File(...)):
    """Upload a PCAP/PCAPNG file for replay analysis."""
    if not file.filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Only PCAP and PCAPNG files are supported.")

    cap_service = get_capture_service()
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".pcap")
        with os.fdopen(fd, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        await cap_service.start_pcap(file_path=tmp_path)
        return {"status": "success", "message": "Replay started."}
    except Exception as e:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/stop", response_model=Dict[str, Any])
async def stop_capture():
    """Stop the active capture or replay session."""
    cap_service = get_capture_service()
    try:
        await cap_service.stop()
        return {"status": "success", "message": "Capture stopped."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
