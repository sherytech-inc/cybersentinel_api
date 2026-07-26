import io
import uuid

import pytest
from fastapi import HTTPException, UploadFile

from app.api import firewall_log_routes
from app.api.auth_dependencies import AnalystIdentity, get_current_analyst
from app.main import app
from app.services.firewall_log_analysis import (
    MAX_LINES,
    MAX_UPLOAD_BYTES,
    MAX_WARNING_SAMPLES,
    FirewallFormat,
    parse_firewall_text,
)


WINDOWS_LOG = b"""#Software: Microsoft Windows Firewall
#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags path
2026-07-27 12:00:00 ALLOW TCP 10.0.0.2 1.1.1.1 52000 443 60 S RECEIVE
2026-07-27 12:00:01 DROP UDP 10.0.0.3 8.8.8.8 53000 53 74 - RECEIVE
"""
UFW_LOG = (
    "Jul 27 12:00:00 host kernel: [UFW BLOCK] IN=en0 OUT= "
    "SRC=10.0.0.2 DST=1.1.1.1 LEN=60 PROTO=TCP SPT=52000 DPT=443 SYN"
)
IPTABLES_LOG = (
    "Jul 27 12:00:00 host kernel: ACTION=DROP IN=en0 OUT= "
    "SRC=10.0.0.2 DST=1.1.1.1 LEN=60 PROTO=UDP SPT=52000 DPT=53"
)
PF_LOG = (
    "2026-07-27 12:00:00 rule 1/(match): block in on en0: "
    "10.0.0.2.52000 > 1.1.1.1.443: TCP"
)


def _analyst() -> AnalystIdentity:
    return AnalystIdentity(
        user_id=uuid.uuid4(),
        email="analyst@example.com",
        display_name="Analyst",
        role="analyst",
    )


def test_windows_detection_and_normalized_fields():
    result = parse_firewall_text(WINDOWS_LOG.decode())
    assert result.detected_format == FirewallFormat.windows_firewall
    assert len(result.events) == 2
    first = result.events[0]
    assert first.timestamp is not None
    assert first.packet_size == 60
    assert first.flags == "S"
    assert first.direction == "inbound"


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (UFW_LOG, FirewallFormat.ufw),
        (IPTABLES_LOG, FirewallFormat.iptables),
        (PF_LOG, FirewallFormat.macos_pf),
    ],
)
def test_supported_unix_formats(content, expected):
    result = parse_firewall_text(content)
    assert result.detected_format == expected
    assert len(result.events) == 1
    assert result.events[0].source_ip == "10.0.0.2"
    assert result.events[0].destination_ip == "1.1.1.1"


def test_deterministic_generic_csv_and_partial_event():
    result = parse_firewall_text(
        "action,protocol,source_ip,destination_ip,destination_port\n"
        "allow,tcp,10.0.0.2,1.1.1.1,443\n"
        ",udp,10.0.0.3,8.8.8.8,53\n"
    )
    assert result.detected_format == FirewallFormat.generic_csv
    assert [event.parse_status for event in result.events] == ["complete", "partial"]


def test_unsupported_and_mixed_malformed_lines_are_isolated():
    assert parse_firewall_text("ordinary application text").detected_format == FirewallFormat.unsupported
    result = parse_firewall_text(f"{UFW_LOG}\nnot a firewall entry")
    assert len(result.events) == 1
    assert result.failed_lines == 1
    assert all("not a firewall entry" not in warning for warning in result.warnings)


def test_bounds_line_count_and_warning_samples():
    text = "\n".join(["broken"] * (MAX_LINES + 30))
    result = parse_firewall_text(text)
    assert result.total_lines == MAX_LINES + 30
    assert result.failed_lines >= 30
    assert len(result.warnings) <= MAX_WARNING_SAMPLES


@pytest.mark.asyncio
async def test_route_summary_invariants_and_stream_cleanup():
    upload = UploadFile(filename="../sample.log", file=io.BytesIO(WINDOWS_LOG))
    response = await firewall_log_routes.analyze_firewall_log(upload, _analyst())
    summary = response.summary
    assert summary.parsed_events == summary.complete_events + summary.partial_events
    assert summary.total_lines >= summary.parsed_events + summary.failed_lines
    assert response.filename == "sample.log"
    assert upload.file.closed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("content", "expected_status", "expected_code"),
    [
        (b"", "invalid_file", 400),
        (b"\x00\x01", "invalid_file", 400),
        (b"unsupported text", "unsupported_format", 422),
        (b"x" * (MAX_UPLOAD_BYTES + 1), "file_too_large", 413),
    ],
    ids=["empty", "binary", "unsupported", "oversized"],
)
async def test_route_rejects_invalid_inputs_and_closes_stream(
    content, expected_status, expected_code
):
    upload = UploadFile(filename="sample.log", file=io.BytesIO(content))
    with pytest.raises(HTTPException) as captured:
        await firewall_log_routes.analyze_firewall_log(upload, _analyst())
    assert captured.value.status_code == expected_code
    assert captured.value.detail["status"] == expected_status
    assert upload.file.closed


@pytest.mark.asyncio
async def test_parser_exception_is_sanitized(monkeypatch):
    def explode(_text):
        raise RuntimeError("secret raw parser detail")

    monkeypatch.setattr(firewall_log_routes, "parse_firewall_text", explode)
    upload = UploadFile(filename="sample.log", file=io.BytesIO(WINDOWS_LOG))
    with pytest.raises(HTTPException) as captured:
        await firewall_log_routes.analyze_firewall_log(upload, _analyst())
    assert captured.value.status_code == 503
    assert "secret" not in captured.value.detail["message"]
    assert upload.file.closed


@pytest.mark.asyncio
async def test_route_requires_active_analyst(async_client):
    app.dependency_overrides.pop(get_current_analyst, None)
    response = await async_client.post(
        "/api/v1/firewall-logs/analyze",
        files={"file": ("sample.log", WINDOWS_LOG, "text/plain")},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_route_requires_local_sidecar_token(async_client, monkeypatch):
    monkeypatch.setenv("CYBERSENTINEL_LOCAL_TOKEN", "firewall-local-token")
    response = await async_client.post(
        "/api/v1/firewall-logs/analyze",
        files={"file": ("sample.log", WINDOWS_LOG, "text/plain")},
    )
    assert response.status_code == 403

    accepted = await async_client.post(
        "/api/v1/firewall-logs/analyze",
        files={"file": ("sample.log", WINDOWS_LOG, "text/plain")},
        headers={"X-CyberSentinel-Local-Token": "firewall-local-token"},
    )
    assert accepted.status_code == 200


@pytest.mark.asyncio
async def test_disabled_analyst_is_rejected(async_client):
    def disabled():
        raise HTTPException(status_code=403, detail="Account is disabled.")

    app.dependency_overrides[get_current_analyst] = disabled
    response = await async_client.post(
        "/api/v1/firewall-logs/analyze",
        files={"file": ("sample.log", WINDOWS_LOG, "text/plain")},
    )
    assert response.status_code == 403
