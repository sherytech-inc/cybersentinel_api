import math

from app.services.model_if import IsolationForestService


def test_real_isolation_forest_artifact_returns_anomaly_score():
    service = IsolationForestService()
    features = {
        "flow_duration": 1.25, "src_pkts": 5, "dst_pkts": 3,
        "src_bytes": 640, "dst_bytes": 384, "pkt_len_mean": 128.0,
        "pkt_len_std": 16.0, "iat_mean": 0.12, "iat_std": 0.03,
        "src_port": 443, "protocol": "TCP",
    }

    frame = service._prepare_inference_frame(features)
    result = service.predict_raw(features)

    assert frame.columns.tolist() == (
        service.TRAINED_NUMERIC_FEATURES + service.TRAINED_PROTOCOL_FEATURES
    )
    assert frame.shape == (1, 14)
    assert math.isfinite(result["anomaly_score"])
    assert 0 <= result["normalized_score"] <= 100
