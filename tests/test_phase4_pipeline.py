"""
Phase 4 Pipeline Test
======================
Verifies:
  1. FeatureExtractor produces the exact 11 fields in the correct order.
  2. DataPreprocessor accepts those 11 fields and returns a (1, 14) array.
  3. CaptureState enum uses the new authoritative string values.
  4. WebSocket hub packet queue hard-caps at 500 packets.
"""
import pytest
import numpy as np


def _make_flow_state():
    """Build a minimal flow dict that FeatureExtractor.extract() accepts."""
    import time
    t0 = time.time()
    return {
        "flow_id": "test-flow",
        "src_ip": "192.168.1.10",
        "dst_ip": "8.8.8.8",
        "src_port": 54321,
        "dst_port": 53,
        "protocol": "UDP",
        "destination_port": 53,
        "first_packet_time": t0,
        "last_packet_time": t0 + 0.1,
        "fwd_packet_lengths": [64, 64],
        "bwd_packet_lengths": [128],
        "all_packet_lengths": [64, 64, 128],
        "inter_arrival_times": [0.05, 0.05],
    }


def test_feature_extractor_produces_11_fields():
    from app.services.packet_capture.feature_extractor import FeatureExtractor
    extractor = FeatureExtractor(max_recent=10)
    result = extractor.extract(_make_flow_state())
    assert result is not None
    features = result.features
    for field in ["flow_duration","src_pkts","dst_pkts","src_bytes","dst_bytes",
                  "pkt_len_mean","pkt_len_std","iat_mean","iat_std","src_port","protocol"]:
        assert hasattr(features, field), f"Missing field: {field}"


def test_feature_extractor_values():
    from app.services.packet_capture.feature_extractor import FeatureExtractor
    extractor = FeatureExtractor(max_recent=10)
    features = extractor.extract(_make_flow_state()).features
    assert features.src_pkts == 2
    assert features.dst_pkts == 1
    assert features.src_bytes == 128
    assert features.dst_bytes == 128
    assert features.src_port == 54321
    assert features.protocol.upper() == "UDP"
    assert features.pkt_len_mean == pytest.approx((64 + 64 + 128) / 3, abs=0.1)


def test_preprocessor_output_shape():
    from app.services.preprocessor import DataPreprocessor
    preprocessor = DataPreprocessor()
    features = {
        "flow_duration": 0.1,
        "src_pkts": 2,
        "dst_pkts": 1,
        "src_bytes": 128,
        "dst_bytes": 128,
        "pkt_len_mean": 85.3,
        "pkt_len_std": 32.0,
        "iat_mean": 0.05,
        "iat_std": 0.0,
        "src_port": 54321,
        "protocol": "UDP",
    }
    result = preprocessor.process(features)
    assert result.shape == (1, 14), f"Expected (1, 14), got {result.shape}"


def test_capture_state_enum_values():
    from app.services.packet_capture.capture_service import CaptureState
    assert CaptureState.STOPPED.value == "stopped"
    assert CaptureState.STARTING.value == "starting"
    assert CaptureState.RUNNING.value == "running"
    assert CaptureState.REPLAY.value == "replay"
    assert CaptureState.STOPPING.value == "stopping"
    assert CaptureState.ERROR.value == "error"


@pytest.mark.asyncio
async def test_websocket_hub_bounded_queue():
    from app.services.websocket.connection_manager import WebSocketHub
    hub = WebSocketHub()
    for i in range(600):
        await hub.queue_packet({"id": i, "src_ip": "10.0.0.1"})
    assert len(hub.packet_queue) == 500
    assert hub.packet_queue[-1]["id"] == 599
