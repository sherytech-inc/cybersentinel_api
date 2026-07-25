import pytest
from httpx import AsyncClient
from app.main import app
from unittest.mock import MagicMock

@pytest.mark.asyncio
async def test_packet_capture_status_schema():
    """Verify backend status endpoint reports daemon truth and follows the exact schema."""
    from app.services.packet_capture.capture_service import get_capture_service
    
    mock_service = MagicMock()
    mock_service.get_status.return_value = {
        "state": "stopped",
        "error": None,
        "interface": "en0",
        "started_at": None,
        "packets_captured": 0,
        "parser": {},
        "flows": {},
        "features": {},
        "config": {}
    }
    app.dependency_overrides[get_capture_service] = lambda: mock_service

    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get("/api/v1/capture/status")
    
    assert response.status_code == 200
    data = response.json()
    assert "state" in data
    assert data["state"] == "stopped"
    assert "started_at" in data and data["started_at"] is None

    # Test running state
    mock_service.get_status.return_value["state"] = "running"
    mock_service.get_status.return_value["started_at"] = "2026-07-19T10:20:00Z"

    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get("/api/v1/capture/status")
    
    data = response.json()
    assert data["state"] == "running"
    assert data["started_at"] == "2026-07-19T10:20:00Z"
    
    # Test error state
    mock_service.get_status.return_value["state"] = "error"
    mock_service.get_status.return_value["error"] = "TShark executable was not found."

    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get("/api/v1/capture/status")
    
    data = response.json()
    assert data["state"] == "error"
    assert data["error"] == "TShark executable was not found."
    
    # Test starting state
    mock_service.get_status.return_value["state"] = "starting"
    mock_service.get_status.return_value["error"] = None

    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get("/api/v1/capture/status")
    
    data = response.json()
    assert data["state"] == "starting"
    
    # Test stopping state
    mock_service.get_status.return_value["state"] = "stopping"

    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get("/api/v1/capture/status")
    
    data = response.json()
    assert data["state"] == "stopping"

    # Test invalid enum mapping failure
    from fastapi.exceptions import ResponseValidationError
    import pytest
    
    mock_service.get_status.return_value["state"] = "invalid_state"
    with pytest.raises(ResponseValidationError):
        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.get("/api/v1/capture/status")

    app.dependency_overrides.clear()
