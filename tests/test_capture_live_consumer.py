import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.services.packet_capture.capture_service import CaptureService, CaptureState
from app.schemas.flow import ParsedPacket


@pytest.mark.asyncio
async def test_live_readiness_requires_consumer_and_subprocess():
    service = CaptureService()
    service._consumer_ready = asyncio.Event()
    service._subprocess_ready = asyncio.Event()
    service._thread = MagicMock(is_alive=MagicMock(return_value=True))

    service._consumer_ready.set()
    service._subprocess_ready.set()
    await service._wait_until_live_ready(timeout=0.1)


@pytest.mark.asyncio
async def test_malformed_packet_does_not_stop_consumer():
    service = CaptureService()
    service._queue = asyncio.Queue()
    service._consumer_ready = asyncio.Event()
    service._flow_manager.add_packet = MagicMock(
        side_effect=[ValueError("malformed"), None]
    )
    await service._queue.put(object())
    await service._queue.put(object())

    task = asyncio.create_task(service._packet_consumer_loop())
    await asyncio.wait_for(service._queue.join(), timeout=1)
    task.cancel()
    await task

    assert service._flow_manager.add_packet.call_count == 2
    assert service._packets_captured == 1


@pytest.mark.asyncio
async def test_unexpected_pyshark_failure_resets_capture(monkeypatch):
    service = CaptureService()
    service._state = CaptureState.RUNNING
    service._queue = asyncio.Queue()
    service._loop = asyncio.get_running_loop()
    service._consumer_ready = asyncio.Event()
    service._first_packet_received = asyncio.Event()

    class BrokenCapture:
        def __init__(self, **kwargs):
            pass

        def sniff_continuously(self):
            raise RuntimeError("decoder failed")

        def close(self):
            pass

    monkeypatch.setitem(
        __import__("sys").modules,
        "pyshark",
        SimpleNamespace(LiveCapture=BrokenCapture),
    )
    service._thread = threading.Thread(
        target=service._live_sniff_thread,
        args=("en0", "tcp", service._loop),
    )
    service._thread.start()
    service._thread.join(timeout=1)
    await asyncio.sleep(0.05)

    assert service.state == CaptureState.STOPPED
    assert service._thread is None
    assert "RuntimeError: decoder failed" in service._error_message


@pytest.mark.asyncio
async def test_parsed_packet_is_queued_before_analysis_or_storage(monkeypatch):
    service = CaptureService()
    service._queue = asyncio.Queue()
    service._consumer_ready = asyncio.Event()
    service._flow_manager.add_packet = MagicMock()
    queued = []

    class Hub:
        async def queue_packet(self, packet):
            queued.append(packet)

    monkeypatch.setattr(
        "app.services.websocket.connection_manager.get_websocket_hub",
        lambda: Hub(),
    )
    await service._queue.put(ParsedPacket(
        timestamp=1784589472.0,
        src_ip="192.168.0.7",
        dst_ip="17.248.213.67",
        src_port=5353,
        dst_port=443,
        protocol="UDP",
        packet_length=128,
    ))

    task = asyncio.create_task(service._packet_consumer_loop())
    await asyncio.wait_for(service._queue.join(), timeout=1)
    task.cancel()
    await task

    assert service._packets_captured == 1
    assert queued[0]["ml_prediction"] == "Pending"
    assert queued[0]["analysis_status"] == "pending"
    assert queued[0]["packet_size"] == 128
    assert queued[0]["packet_id"] == queued[0]["id"]
    assert queued[0]["flow_id"]
