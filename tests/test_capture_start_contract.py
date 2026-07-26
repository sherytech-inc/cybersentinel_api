from unittest.mock import AsyncMock
from types import SimpleNamespace

import pytest

from app.api.packet_routes import (
    StartCaptureRequest as ApiStartCaptureRequest,
    capture_start as api_capture_start,
)
from app.main import app


def test_capture_control_paths_have_one_canonical_handler_each():
    control_paths = {
        "/api/v1/capture/start",
        "/api/v1/capture/stop",
        "/api/v1/capture/replay",
    }
    registered = [
        route.path
        for route in app.routes
        if route.path in control_paths and "POST" in (route.methods or set())
    ]
    assert sorted(registered) == sorted(control_paths)


@pytest.mark.asyncio
async def test_api_start_uses_ephemeral_session_without_workspace():
    capture_service = AsyncMock()
    capture_service._settings = SimpleNamespace(CAPTURE_INTERFACE="en0")

    response = await api_capture_start(
        request=SimpleNamespace(headers={"Authorization": "Bearer verified-jwt"}),
        body=ApiStartCaptureRequest(interface="en0"),
        service=capture_service,
        analyst=object(),
    )

    kwargs = capture_service.start_live.await_args.kwargs
    assert kwargs["jwt_token"] == "verified-jwt"
    assert kwargs["session_id"]
    assert "workspace_id" not in kwargs
    assert "session_history_persisted" not in response
    assert response["status"] == "started"
