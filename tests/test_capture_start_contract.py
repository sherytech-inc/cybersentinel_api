from unittest.mock import AsyncMock, patch
from types import SimpleNamespace

import pytest

from app.api.capture_routes import StartCaptureRequest, start_capture
from app.api.packet_routes import (
    StartCaptureRequest as ApiStartCaptureRequest,
    capture_start as api_capture_start,
)


@pytest.mark.asyncio
async def test_start_capture_accepts_interface_contract():
    capture_service = AsyncMock()

    with patch(
        "app.api.capture_routes.get_capture_service",
        return_value=capture_service,
    ):
        response = await start_capture(
            StartCaptureRequest(interface="en0"),
            SimpleNamespace(headers={"authorization": "Bearer verified-jwt"}),
        )

    capture_service.start_live.assert_awaited_once_with(
        interface="en0",
        jwt_token="verified-jwt",
    )
    assert response["status"] == "success"


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
