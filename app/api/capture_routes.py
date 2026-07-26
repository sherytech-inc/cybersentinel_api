from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Dict, Any

from app.api.auth_dependencies import get_current_analyst, verify_local_token
from app.models.capture_capability import CaptureCapabilityResult
from app.services.capture_capability_service import CaptureCapabilityService

router = APIRouter(
    prefix="/api/v1/capture",
    tags=["capture"],
    dependencies=[Depends(verify_local_token), Depends(get_current_analyst)]
)

_service = CaptureCapabilityService()

class ProbeRequest(BaseModel):
    interface_id: str

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
