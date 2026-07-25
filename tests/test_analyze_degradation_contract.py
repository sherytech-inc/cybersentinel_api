from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.api.analyze_routes import analyze_flow_internal
from app.schemas.analyze import AnalyzeFlowRequest
from app.schemas.intelligence import (
    AbuseIpDbIntelResult,
    GeoIpIntelResult,
    IntelligenceResponse,
    VirusTotalIntelResult,
)


FEATURES = {
    "flow_duration": 0.1, "src_pkts": 2, "dst_pkts": 1,
    "src_bytes": 128, "dst_bytes": 64, "pkt_len_mean": 64.0,
    "pkt_len_std": 0.0, "iat_mean": 0.05, "iat_std": 0.0,
    "src_port": 443, "protocol": "TCP",
}


def _intel(status, score=None):
    return IntelligenceResponse(
        ip="8.8.8.8",
        status=status,
        intel_score=score,
        severity="Safe" if score is not None else "N/A",
        virustotal=VirusTotalIntelResult(status=status),
        abuseipdb=AbuseIpDbIntelResult(status=status),
        geoip=GeoIpIntelResult(status=status),
        message="test",
        looked_up_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_local_model_failure_never_reports_safe_allow():
    intel_service = AsyncMock()
    intel_service.enrich.return_value = _intel("completed", 0)
    repo = AsyncMock()
    repo.insert.return_value = None

    with patch("app.api.analyze_routes._model_rf.predict", return_value={
        "classification": "Normal",
        "confidence_scores": {"Normal": 0.99, "Suspicious": 0.0, "Malicious": 0.01},
    }), patch(
        "app.api.analyze_routes._model_if.predict_raw",
        side_effect=RuntimeError("model unavailable"),
    ):
        result = await analyze_flow_internal(
            AnalyzeFlowRequest(ip="8.8.8.8", flow_features=FEATURES),
            intel_service,
            repo,
        )

    assert result.analysis_status == "partial"
    assert result.severity == "UNKNOWN"
    assert result.action == "MONITOR"


@pytest.mark.asyncio
async def test_unavailable_intelligence_preserves_none_semantics():
    intel_service = AsyncMock()
    intel_service.enrich.return_value = _intel("unavailable", None)
    repo = AsyncMock()
    repo.insert.return_value = None

    with patch("app.api.analyze_routes._model_rf.predict", return_value={
        "classification": "Normal",
        "confidence_scores": {"Normal": 0.99, "Suspicious": 0.0, "Malicious": 0.01},
    }), patch("app.api.analyze_routes._model_if.predict_raw", return_value={
        "anomaly_score": -0.3, "is_anomaly": False, "normalized_score": 10.0,
    }):
        result = await analyze_flow_internal(
            AnalyzeFlowRequest(ip="8.8.8.8", flow_features=FEATURES),
            intel_service,
            repo,
        )

    assert result.analysis_status == "partial"
    assert result.model3_available is False
    assert result.model3 is None
