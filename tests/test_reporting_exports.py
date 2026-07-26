import csv
import io
import json
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest
from fastapi import Depends, FastAPI

from app.api import reporting_routes
from app.api.auth_dependencies import AnalystIdentity, verify_local_token
from app.schemas.reporting import ReportSummary
from app.services.reporting.analytics_service import ReportRows
from app.services.reporting.export_service import (
    ACTION_CSV_HEADERS,
    ALERT_CSV_HEADERS,
)
from app.services.reporting.report_service import ReportService


class FakeCapture:
    def __init__(self, status):
        self.status = status

    def get_status(self):
        return self.status


class FakeAnalytics:
    def __init__(
        self,
        *,
        alerts=None,
        actions=None,
        countries=None,
    ):
        self.alerts = alerts or ReportRows()
        self.actions = actions or ReportRows()
        self.countries = countries or ReportRows()

    async def get_report_alerts(self, *args, **kwargs):
        return self.alerts

    async def get_report_actions(self, *args, **kwargs):
        return self.actions

    async def enrich_attacker_countries(self, source_ips):
        return self.countries


def capture_status(state="running", *, session_id="session-1"):
    return {
        "state": state,
        "session_id": session_id,
        "interface": "en0",
        "packets_captured": 10,
        "analysis": {
            "completed_packets": 4,
            "partial_packets": 2,
            "failed_packets": 1,
            "deferred_packets": 1,
            "cancelled_packets": 0,
            "pending_packets": 2,
        },
        "flows": {
            "normal_packets": 3,
            "suspicious_packets": 2,
            "malicious_packets": 0,
            "unknown_packets": 1,
            "last_reliable_score": 42.5,
            "highest_severity": "MEDIUM",
        },
    }


def service_for(status, analytics=None):
    return ReportService(
        SimpleNamespace(),
        analytics=analytics or FakeAnalytics(),
        capture_service=FakeCapture(status),
    )


@pytest.mark.asyncio
async def test_summary_with_active_capture_diagnostics():
    summary = await service_for(capture_status()).get_summary()

    assert summary.timeframe == "current_session"
    assert summary.monitoring_state == "running"
    assert summary.interface == "en0"
    assert summary.session.captured == 10
    assert summary.session.analyzed == 6
    assert summary.session.pending == 2
    assert summary.session.not_analyzed == 0
    assert summary.session.threat_score == 42.5
    assert summary.classification_distribution.model_dump() == {
        "normal": 3,
        "suspicious": 2,
        "malicious": 0,
        "unknown": 1,
    }


@pytest.mark.asyncio
async def test_summary_with_stopped_retained_diagnostics_terminalizes_pending():
    summary = await service_for(capture_status("stopped")).get_summary()

    assert summary.timeframe == "last_session"
    assert summary.monitoring_state == "stopped"
    assert summary.session.pending == 0
    assert summary.session.not_analyzed == 2
    assert (
        summary.session.captured
        == summary.session.complete
        + summary.session.partial
        + summary.session.failed
        + summary.session.deferred
        + summary.session.not_analyzed
        + summary.session.pending
    )


@pytest.mark.asyncio
async def test_summary_before_any_session_is_truthfully_unavailable():
    summary = await service_for(
        {
            "state": "stopped",
            "session_id": None,
            "packets_captured": 0,
            "analysis": {},
            "flows": {},
        }
    ).get_summary()

    assert summary.timeframe == "unavailable"
    assert summary.monitoring_state == "inactive"
    assert summary.session.threat_score is None
    assert "No capture session data is available yet." in summary.messages


@pytest.mark.asyncio
async def test_optional_alert_failure_preserves_capture_summary():
    analytics = FakeAnalytics(
        alerts=ReportRows(
            available=False,
            message="Recent alert data is temporarily unavailable.",
        )
    )
    summary = await service_for(capture_status(), analytics).get_summary()

    assert summary.session.captured == 10
    assert summary.source_status.alerts == "unavailable"
    assert summary.source_status.capture == "available"
    assert summary.recent_alerts == []
    assert "Recent alert data is temporarily unavailable." in summary.messages


def populated_analytics():
    return FakeAnalytics(
        alerts=ReportRows(
            rows=[
                {
                    "alert_id": "alert-1",
                    "created_at": "2026-07-26T10:00:00Z",
                    "source_ip": "203.0.113.5",
                    "model1_classification": "Port Scan",
                    "severity": "HIGH",
                    "threat_score": 78.0,
                    "status": "OPEN",
                    "action": "MONITOR",
                    "summary": "Observed scan behavior",
                }
            ]
        ),
        actions=ReportRows(
            rows=[
                {
                    "action_id": "action-1",
                    "timestamp": "2026-07-26T10:05:00Z",
                    "target": "203.0.113.5",
                    "action": "INVESTIGATE",
                    "status": "RECORDED",
                    "analyst": "Analyst",
                    "related_alert": "alert-1",
                    "result": "Investigation started",
                    "platform": None,
                }
            ]
        ),
        countries=ReportRows(
            rows=[{"ip_address": "203.0.113.5", "country": "Example"}]
        ),
    )


@pytest.mark.asyncio
async def test_summary_with_repository_data():
    summary = await service_for(capture_status(), populated_analytics()).get_summary()

    assert summary.severity_distribution.high == 1
    assert summary.top_threat_types[0].threat_type == "Port Scan"
    assert summary.top_attackers[0].source_ip == "203.0.113.5"
    assert summary.recent_alerts[0].alert_id == "alert-1"
    assert summary.response_timeline[0].action == "INVESTIGATE"


def analyst():
    return AnalystIdentity(
        user_id=uuid.uuid4(),
        email="analyst@example.com",
        display_name="Analyst",
        role="analyst",
    )


def reporting_app(service, *, override_analyst=True):
    app = FastAPI()
    app.include_router(
        reporting_routes.router,
        dependencies=[Depends(verify_local_token)],
    )
    app.dependency_overrides[reporting_routes.get_report_service] = lambda: service
    if override_analyst:
        from app.api.auth_dependencies import get_current_analyst

        app.dependency_overrides[get_current_analyst] = analyst
    return app


@pytest.mark.asyncio
async def test_reporting_routes_require_local_token_and_bearer_jwt(monkeypatch):
    monkeypatch.setenv("CYBERSENTINEL_LOCAL_TOKEN", "report-local-token")
    app = reporting_app(
        service_for(capture_status()),
        override_analyst=False,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        missing_local = await client.get("/api/v1/reporting/summary")
        missing_jwt = await client.get(
            "/api/v1/reporting/summary",
            headers={"X-CyberSentinel-Local-Token": "report-local-token"},
        )

    assert missing_local.status_code == 403
    assert missing_jwt.status_code == 401


@pytest.mark.asyncio
async def test_disabled_or_unauthorized_analyst_is_rejected(monkeypatch):
    from app.api.auth_dependencies import get_current_analyst
    from fastapi import HTTPException

    monkeypatch.setenv("CYBERSENTINEL_LOCAL_TOKEN", "report-local-token")
    app = reporting_app(service_for(capture_status()))

    def disabled():
        raise HTTPException(status_code=403, detail="account_disabled")

    app.dependency_overrides[get_current_analyst] = disabled
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/api/v1/reporting/summary",
            headers={"X-CyberSentinel-Local-Token": "report-local-token"},
        )

    assert response.status_code == 403
    assert response.json() == {"detail": "account_disabled"}


@pytest.mark.asyncio
async def test_pdf_and_json_exports_have_stable_contracts(monkeypatch):
    monkeypatch.setenv("CYBERSENTINEL_LOCAL_TOKEN", "report-local-token")
    service = service_for(capture_status("stopped"), populated_analytics())
    app = reporting_app(service)
    headers = {"X-CyberSentinel-Local-Token": "report-local-token"}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        pdf_response = await client.get(
            "/api/v1/reporting/export/pdf", headers=headers
        )
        json_response = await client.get(
            "/api/v1/reporting/export/json", headers=headers
        )

    assert pdf_response.status_code == 200
    assert pdf_response.headers["content-type"] == "application/pdf"
    assert "cybersentinel-report-" in pdf_response.headers["content-disposition"]
    assert pdf_response.content.startswith(b"%PDF-")
    assert pdf_response.content.rstrip().endswith(b"%%EOF")
    assert len(pdf_response.content) > 1000

    assert json_response.status_code == 200
    assert json_response.headers["content-type"].startswith("application/json")
    parsed = json.loads(json_response.content.decode("utf-8"))
    ReportSummary.model_validate(parsed)
    assert parsed["session"]["captured"] == 10


@pytest.mark.asyncio
async def test_alerts_csv_fixed_headers_with_data_and_when_empty():
    populated = service_for(capture_status(), populated_analytics())
    content, available = await populated.export.generate_alerts_csv()
    rows = list(csv.DictReader(io.StringIO(content.decode("utf-8"))))
    assert available is True
    assert list(rows[0].keys()) == ALERT_CSV_HEADERS
    assert rows[0]["alert_id"] == "alert-1"
    assert rows[0]["destination_ip"] == ""
    assert rows[0]["analysis_status"] == ""

    empty = service_for(capture_status(), FakeAnalytics())
    content, available = await empty.export.generate_alerts_csv()
    assert available is True
    assert content.decode("utf-8").strip() == ",".join(ALERT_CSV_HEADERS)


@pytest.mark.asyncio
async def test_actions_csv_fixed_headers_with_data_and_when_empty():
    populated = service_for(capture_status(), populated_analytics())
    content, available = await populated.export.generate_actions_csv()
    rows = list(csv.DictReader(io.StringIO(content.decode("utf-8"))))
    assert available is True
    assert list(rows[0].keys()) == ACTION_CSV_HEADERS
    assert rows[0]["action_id"] == "action-1"

    empty = service_for(capture_status(), FakeAnalytics())
    content, available = await empty.export.generate_actions_csv()
    assert available is True
    assert content.decode("utf-8").strip() == ",".join(ACTION_CSV_HEADERS)


@pytest.mark.asyncio
async def test_csv_routes_use_explicit_paths_and_download_headers(monkeypatch):
    monkeypatch.setenv("CYBERSENTINEL_LOCAL_TOKEN", "report-local-token")
    app = reporting_app(
        service_for(capture_status("stopped"), populated_analytics())
    )
    headers = {"X-CyberSentinel-Local-Token": "report-local-token"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        alerts = await client.get(
            "/api/v1/reporting/export/alerts.csv",
            headers=headers,
        )
        actions = await client.get(
            "/api/v1/reporting/export/actions.csv",
            headers=headers,
        )

    assert alerts.status_code == 200
    assert alerts.headers["content-type"].startswith("text/csv")
    assert "cybersentinel-alerts-" in alerts.headers["content-disposition"]
    assert alerts.text.splitlines()[0] == ",".join(ALERT_CSV_HEADERS)
    assert actions.status_code == 200
    assert actions.headers["content-type"].startswith("text/csv")
    assert "cybersentinel-actions-" in actions.headers["content-disposition"]
    assert actions.text.splitlines()[0] == ",".join(ACTION_CSV_HEADERS)


def test_route_inventory_contains_each_canonical_route_once():
    canonical = {
        "/api/v1/reporting/summary",
        "/api/v1/reporting/export/pdf",
        "/api/v1/reporting/export/json",
        "/api/v1/reporting/export/alerts.csv",
        "/api/v1/reporting/export/actions.csv",
    }
    paths = [route.path for route in reporting_routes.router.routes]
    for path in canonical:
        assert paths.count(path) == 1
    assert "/api/v1/reporting/dashboard" not in paths
    assert "/api/v1/reporting/export/csv" not in paths
