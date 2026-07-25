from fastapi import APIRouter, status
from app.services.websocket.connection_manager import get_websocket_hub

router = APIRouter(prefix="/api/v1/system", tags=["System Diagnostics"])

@router.get("/ws-stats", status_code=status.HTTP_200_OK, summary="Retrieve real-time WebSocket connection bus metrics")
async def get_websocket_metrics() -> dict:
    """Returns active connections count, packets throughput, and last broadcast timestamp."""
    hub = get_websocket_hub()
    return hub.get_metrics()
