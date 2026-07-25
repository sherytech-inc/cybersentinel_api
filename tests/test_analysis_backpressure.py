import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.packet_capture.flow_manager import FlowManager
from app.schemas.flow import ParsedPacket


@pytest.mark.asyncio
async def test_analysis_queue_is_bounded_and_concurrency_is_limited():
    manager = FlowManager(MagicMock())
    manager._analysis_queue = asyncio.Queue(maxsize=2)
    manager._accepting_analysis = True
    manager._publish_analysis_update = AsyncMock()

    gate = asyncio.Event()

    async def slow_analysis(*_args):
        await gate.wait()

    manager._analyze_and_save_flow = slow_analysis
    manager._analysis_workers = [
        asyncio.create_task(manager._analysis_worker(index)) for index in range(2)
    ]

    for index in range(10):
        manager._enqueue_analysis(
            object(), {}, [f"packet-{index}"], f"flow-{index}"
        )

    await asyncio.sleep(0)
    assert manager.stats["analysis_queue_depth"] <= 2
    assert manager.stats["analysis_active"] <= 2
    assert manager.stats["analysis_dropped"] >= 6

    gate.set()
    await asyncio.wait_for(manager._analysis_queue.join(), timeout=1)
    for worker in manager._analysis_workers:
        worker.cancel()
    await asyncio.gather(*manager._analysis_workers, return_exceptions=True)

    assert manager.stats["analysis_max_concurrency"] == 2


@pytest.mark.asyncio
async def test_stop_cancels_analysis_backlog_without_waiting_for_jobs():
    manager = FlowManager(MagicMock())
    manager._analysis_queue = asyncio.Queue(maxsize=8)
    manager._running = True
    manager._accepting_analysis = True
    manager._publish_analysis_update = AsyncMock()
    async def blocked_analysis(*_args):
        await asyncio.sleep(60)

    manager._analyze_and_save_flow = blocked_analysis
    manager._analysis_workers = [
        asyncio.create_task(manager._analysis_worker(0))
    ]
    for index in range(5):
        manager._enqueue_analysis(
            object(), {}, [f"packet-{index}"], f"flow-{index}"
        )

    await asyncio.wait_for(manager.stop_cleanup_loop(), timeout=1)

    assert manager.stats["analysis_queue_depth"] == 0
    assert manager.stats["analysis_workers"] == 0


def test_live_flow_becomes_eligible_before_inactivity_or_stop():
    manager = FlowManager(MagicMock())
    manager._queue_flow_analysis = MagicMock()
    packet = ParsedPacket(
        timestamp=time.time() - 2.1,
        src_ip="192.168.1.4",
        dst_ip="1.1.1.1",
        src_port=53000,
        dst_port=443,
        protocol="TCP",
        packet_length=128,
    )
    flow_id = manager.add_packet(packet, packet_id="packet-1")

    manager._cleanup_expired()

    assert flow_id
    manager._queue_flow_analysis.assert_called_once()


@pytest.mark.asyncio
async def test_ephemeral_session_analysis_does_not_require_workspace(monkeypatch):
    manager = FlowManager(MagicMock())
    manager.set_jwt_token("validated-user-token")
    manager.set_session_context("ephemeral-session")
    manager._publish_analysis_update = AsyncMock()

    class _Repository:
        def __init__(self, db):
            self.db = db

        async def insert(self, payload):
            return None

    async def get_db_client(*, access_token):
        assert access_token == "validated-user-token"
        return object()

    model1 = SimpleNamespace(
        classification="normal",
        anomaly_probability=0.04,
        model_dump=lambda: {"classification": "normal"},
    )
    model2 = SimpleNamespace(
        anomaly_score=0.12,
        model_dump=lambda: {"anomaly_score": 0.12},
    )
    analysis = SimpleNamespace(
        model1=model1,
        model2=model2,
        model3=None,
        model3_available=False,
        final_score=8.0,
        action="ALLOW",
        severity="LOW",
        analysis_status="partial",
    )

    async def analyze_flow_internal(**kwargs):
        body = kwargs["body"]
        assert body.session_id == "ephemeral-session"
        assert not hasattr(body, "workspace_id")
        return analysis

    monkeypatch.setattr("app.database.client.get_db_client", get_db_client)
    monkeypatch.setattr("app.repositories.ThreatScoreRepository", _Repository)
    monkeypatch.setattr("app.repositories.PacketRepository", _Repository)
    monkeypatch.setattr(
        "app.services.intelligence.get_enrichment_service", lambda: object()
    )
    monkeypatch.setattr(
        "app.api.analyze_routes.analyze_flow_internal", analyze_flow_internal
    )

    result = SimpleNamespace(
        src_ip="192.168.1.10",
        dst_ip="1.1.1.1",
        features=SimpleNamespace(
            flow_duration=1.0,
            model_dump=lambda: {
                "flow_duration": 1.0,
                "src_pkts": 1.0,
                "dst_pkts": 1.0,
                "src_bytes": 64.0,
                "dst_bytes": 64.0,
                "pkt_len_mean": 64.0,
                "pkt_len_std": 0.0,
                "iat_mean": 0.5,
                "iat_std": 0.0,
                "src_port": 50000,
                "protocol": "TCP",
            },
        ),
    )
    flow_state = {
        "src_port": 50000,
        "dst_port": 443,
        "protocol": "TCP",
        "all_packet_lengths": [64, 64],
        "fwd_packet_lengths": [64],
        "bwd_packet_lengths": [64],
    }

    await manager._analyze_and_save_flow(
        result, flow_state, ["packet-1"], "flow-1"
    )

    manager._publish_analysis_update.assert_awaited_once()
    assert manager._publish_analysis_update.await_args.kwargs[
        "analysis_status"
    ] == "partial"
