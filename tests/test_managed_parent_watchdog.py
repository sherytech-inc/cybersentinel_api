import asyncio
from unittest.mock import patch

import pytest

from app.main import monitor_managed_parent


@pytest.mark.asyncio
async def test_watchdog_terminates_only_this_sidecar_when_parent_is_gone():
    calls = []

    def fake_kill(pid, signal_value):
        calls.append((pid, signal_value))
        if signal_value == 0:
            raise ProcessLookupError

    with patch("app.main.os.kill", side_effect=fake_kill), patch(
        "app.main.os.getpid", return_value=4321
    ):
        await monitor_managed_parent(1234, interval=0)

    assert calls[0] == (1234, 0)
    assert calls[1][0] == 4321
    assert len(calls) == 2
