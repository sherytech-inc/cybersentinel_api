import asyncio
import time
from datetime import datetime, timezone

import pytest

from app.schemas.flow import ParsedPacket
from app.schemas.intelligence import (
    AbuseIpDbIntelResult,
    GeoIpIntelResult,
    IntelligenceResponse,
    IntelProviderStatus,
    IntelStatus,
    VirusTotalIntelResult,
)
from app.services.packet_capture.feature_extractor import FeatureExtractor
from app.services.packet_capture.flow_manager import FlowManager


class _EventHub:
    def __init__(self):
        self.events: list[tuple[str, dict]] = []

    async def broadcast(self, event_type: str, payload: dict):
        self.events.append((event_type, payload))


class _DeterministicIntel:
    def __init__(self, *, available: bool):
        self.available = available
        self.calls: list[str] = []

    async def enrich(self, ip: str) -> IntelligenceResponse:
        self.calls.append(ip)
        provider_status = (
            IntelProviderStatus.completed
            if self.available
            else IntelProviderStatus.unavailable
        )
        return IntelligenceResponse(
            ip=ip,
            status=(
                IntelStatus.completed
                if self.available
                else IntelStatus.unavailable
            ),
            intel_score=14 if self.available else None,
            severity="Low" if self.available else "N/A",
            score_confidence="FULL" if self.available else None,
            providers_used=(
                ["VIRUSTOTAL", "ABUSEIPDB"] if self.available else []
            ),
            providers_queried=["VIRUSTOTAL", "ABUSEIPDB", "GEOIP"],
            providers_available=(
                ["VIRUSTOTAL", "ABUSEIPDB", "GEOIP"]
                if self.available else []
            ),
            virustotal=VirusTotalIntelResult(
                status=provider_status,
                malicious=0 if self.available else None,
                suspicious=0 if self.available else None,
                harmless=72 if self.available else None,
                total_engines=72 if self.available else None,
            ),
            abuseipdb=AbuseIpDbIntelResult(
                status=provider_status,
                abuse_confidence_score=4 if self.available else None,
                total_reports=1 if self.available else None,
                num_distinct_users=1 if self.available else None,
                is_tor=False if self.available else None,
                is_whitelisted=False if self.available else None,
            ),
            geoip=GeoIpIntelResult(
                status=provider_status,
                country="United States" if self.available else None,
                country_code="US" if self.available else None,
                asn="AS15169" if self.available else None,
                organization="Fixture network" if self.available else None,
                is_proxy=False if self.available else None,
                is_hosting=False if self.available else None,
            ),
            message=(
                "Deterministic provider result."
                if self.available
                else "Providers unavailable."
            ),
            looked_up_at=datetime.now(timezone.utc),
        )


def _add_eligible_flow(
    manager: FlowManager,
    *,
    dst_ip: str = "8.8.8.8",
) -> str:
    timestamp = time.time()
    flow_id = ""
    for index in range(5):
        flow_id = manager.add_packet(
            ParsedPacket(
                timestamp=timestamp + (index * 0.02),
                src_ip="192.168.1.20",
                dst_ip=dst_ip,
                src_port=52100,
                dst_port=443,
                protocol="TCP",
                packet_length=120 + index,
            ),
            packet_id=f"packet-{index}",
        )
    return flow_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("intel_available", "expected_status"),
    [(True, "complete"), (False, "partial")],
)
async def test_real_worker_executes_models_and_emits_terminal_event(
    monkeypatch,
    intel_available,
    expected_status,
):
    hub = _EventHub()
    intel = _DeterministicIntel(available=intel_available)
    monkeypatch.setattr(
        "app.services.websocket.connection_manager.get_websocket_hub",
        lambda: hub,
    )
    monkeypatch.setattr(
        "app.services.intelligence.get_enrichment_service",
        lambda: intel,
    )

    manager = FlowManager(FeatureExtractor())
    manager.set_session_context("ephemeral-test-session")
    manager._accepting_analysis = True
    manager._analysis_workers = [
        asyncio.create_task(manager._analysis_worker(index))
        for index in range(2)
    ]

    flow_id = _add_eligible_flow(manager)
    flow = next(iter(manager._active_flows.values()))
    manager._queue_flow_analysis(flow)
    await asyncio.wait_for(manager._analysis_queue.join(), timeout=10)

    for worker in manager._analysis_workers:
        worker.cancel()
    await asyncio.gather(*manager._analysis_workers, return_exceptions=True)

    updates = [
        payload
        for event_type, payload in hub.events
        if event_type == "packet_analysis_update"
    ]
    assert len(updates) == 1
    update = updates[0]
    assert update["flow_id"] == flow_id
    assert update["packet_ids"] == [f"packet-{index}" for index in range(5)]
    assert update["analysis_status"] == expected_status
    assert update["model_results"]["model1"]["classification"]
    assert 0 <= update["model_results"]["model1"]["anomaly_probability"] <= 1
    assert isinstance(update["model_results"]["model2"]["anomaly_score"], float)
    assert update["model3_available"] is intel_available
    assert update["model3_intelligence_score"] == (
        14 if intel_available else None
    )
    assert 0 <= update["threat_score"] <= 100
    assert update["severity"]
    assert update["action"]
    assert manager.stats["analysis_completed"] == 1
    assert manager.stats["analysis_failed"] == 0
    assert manager.stats["analyzed_packets"] == 5
    assert intel.calls == ["8.8.8.8"]


@pytest.mark.asyncio
async def test_worker_survives_malformed_job_and_processes_next_real_job(
    monkeypatch,
):
    hub = _EventHub()
    intel = _DeterministicIntel(available=False)
    monkeypatch.setattr(
        "app.services.websocket.connection_manager.get_websocket_hub",
        lambda: hub,
    )
    monkeypatch.setattr(
        "app.services.intelligence.get_enrichment_service",
        lambda: intel,
    )

    manager = FlowManager(FeatureExtractor())
    manager.set_session_context("ephemeral-test-session")
    manager._accepting_analysis = True
    worker = asyncio.create_task(manager._analysis_worker(0))
    manager._analysis_workers = [worker]

    manager._enqueue_analysis(
        object(),
        {},
        ["malformed-packet"],
        "malformed-flow",
    )
    _add_eligible_flow(manager)
    valid_flow = next(iter(manager._active_flows.values()))
    manager._queue_flow_analysis(valid_flow)
    await asyncio.wait_for(manager._analysis_queue.join(), timeout=10)

    worker.cancel()
    await asyncio.gather(worker, return_exceptions=True)

    updates = {
        payload["flow_id"]: payload
        for event_type, payload in hub.events
        if event_type == "packet_analysis_update"
    }
    assert updates["malformed-flow"]["analysis_status"] == "failed"
    assert updates[valid_flow.flow_id]["analysis_status"] == "partial"
    assert manager.stats["analysis_failed"] == 1
    assert manager.stats["analysis_completed"] == 1


@pytest.mark.asyncio
async def test_internal_flow_skips_model3_provider_invocation(monkeypatch):
    hub = _EventHub()
    intel = _DeterministicIntel(available=True)
    monkeypatch.setattr(
        "app.services.websocket.connection_manager.get_websocket_hub",
        lambda: hub,
    )
    monkeypatch.setattr(
        "app.services.intelligence.get_enrichment_service",
        lambda: intel,
    )
    manager = FlowManager(FeatureExtractor())
    manager.set_session_context("ephemeral-test-session")
    manager._accepting_analysis = True
    worker = asyncio.create_task(manager._analysis_worker(0))
    manager._analysis_workers = [worker]

    _add_eligible_flow(manager, dst_ip="192.168.1.21")
    flow = next(iter(manager._active_flows.values()))
    manager._queue_flow_analysis(flow)
    await asyncio.wait_for(manager._analysis_queue.join(), timeout=10)

    worker.cancel()
    await asyncio.gather(worker, return_exceptions=True)

    update = next(
        payload
        for event_type, payload in hub.events
        if event_type == "packet_analysis_update"
    )
    assert intel.calls == []
    assert update["model3_available"] is False
    assert update["analysis_status"] == "partial"


@pytest.mark.asyncio
async def test_persistence_failure_does_not_suppress_live_terminal_result(
    monkeypatch,
):
    hub = _EventHub()
    intel = _DeterministicIntel(available=False)
    monkeypatch.setattr(
        "app.services.websocket.connection_manager.get_websocket_hub",
        lambda: hub,
    )
    monkeypatch.setattr(
        "app.services.intelligence.get_enrichment_service",
        lambda: intel,
    )
    manager = FlowManager(FeatureExtractor())

    async def fail_persistence(**_kwargs):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr(manager, "_persist_flow_analysis", fail_persistence)
    manager.set_session_context("ephemeral-test-session")
    manager._accepting_analysis = True
    worker = asyncio.create_task(manager._analysis_worker(0))
    manager._analysis_workers = [worker]

    _add_eligible_flow(manager)
    flow = next(iter(manager._active_flows.values()))
    manager._queue_flow_analysis(flow)
    await asyncio.wait_for(manager._analysis_queue.join(), timeout=10)

    worker.cancel()
    await asyncio.gather(worker, return_exceptions=True)
    update = next(
        payload
        for event_type, payload in hub.events
        if event_type == "packet_analysis_update"
    )
    assert update["analysis_status"] == "partial"
    assert manager.stats["analysis_completed"] == 1
    assert manager.stats["analysis_failed"] == 0


@pytest.mark.asyncio
async def test_duplicate_terminal_update_does_not_double_count(monkeypatch):
    hub = _EventHub()
    monkeypatch.setattr(
        "app.services.websocket.connection_manager.get_websocket_hub",
        lambda: hub,
    )
    manager = FlowManager(FeatureExtractor())

    await manager._publish_analysis_update(
        "flow-1",
        ["packet-1", "packet-2"],
        analysis_status="failed",
        severity="Analysis incomplete",
    )
    await manager._publish_analysis_update(
        "flow-1",
        ["packet-1", "packet-2"],
        analysis_status="failed",
        severity="Analysis incomplete",
    )

    assert manager.stats["failed_packets"] == 2
    assert manager.stats["terminal_packets"] == 2
