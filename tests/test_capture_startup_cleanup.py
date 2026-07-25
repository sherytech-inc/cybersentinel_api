from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.packet_capture.capture_service import CaptureService, CaptureState


@pytest.mark.asyncio
async def test_startup_failure_returns_to_stopped_and_allows_retry():
    service = CaptureService()
    capabilities = MagicMock(capture_supported=True)

    with patch(
        "app.services.capture_capability_service.CaptureCapabilityService.get_capabilities",
        return_value=capabilities,
    ), patch(
        "app.services.packet_capture.capture_service.resolve_capture_executable",
        side_effect=RuntimeError("tshark executable was not found"),
    ):
        with pytest.raises(RuntimeError, match="tshark executable was not found"):
            await service.start_live("en0")

    assert service.state == CaptureState.STOPPED
    assert service._thread is None
    assert service._consumer_task is None

    service._state = CaptureState.STARTING
    service._thread = None
    service._consumer_task = None
    with patch(
        "app.services.capture_capability_service.CaptureCapabilityService.get_capabilities",
        side_effect=RuntimeError("retry reached capability check"),
    ):
        with pytest.raises(RuntimeError, match="retry reached capability check"):
            await service.start_live("en0")
    assert service.state == CaptureState.STOPPED
