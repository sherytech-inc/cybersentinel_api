from datetime import datetime, timezone
from uuid import uuid4

import httpx
import pytest
from fastapi import Depends, FastAPI

from app.api.auth_dependencies import verify_local_token
from app.api.response_routes import router as response_router
from app.services.threat_response.response_service import ResponseService


class Result:
    def __init__(self, data=None, count=None):
        self.data = data or []
        self.count = count


class AuditQuery:
    def __init__(self, repo, table):
        self.repo = repo
        self.table = table
        self.inserted = None

    def insert(self, data):
        self.inserted = data
        return self

    def select(self, *_args, **_kwargs):
        return self

    def eq(self, *_args, **_kwargs):
        return self

    def order(self, *_args, **_kwargs):
        return self

    def range(self, *_args, **_kwargs):
        return self

    def limit(self, *_args, **_kwargs):
        return self

    async def execute(self):
        if self.inserted is not None:
            record = {
                "id": str(uuid4()),
                **self.inserted,
            }
            self.repo.audits.append(record)
            return Result([record], 1)
        return Result(list(self.repo.audits), len(self.repo.audits))


class FakeDB:
    def __init__(self, repo):
        self.repo = repo

    def table(self, name):
        return AuditQuery(self.repo, name)


class FakeFirewallRepo:
    _table = "firewall_actions"

    def __init__(self, *, fail_insert=False):
        self.actions = []
        self.audits = []
        self.fail_insert = fail_insert
        self._db = FakeDB(self)

    async def get_actions_for_ip(self, ip, limit=20):
        return [
            action for action in reversed(self.actions) if action["ip"] == ip
        ][:limit]

    async def insert(self, data):
        if self.fail_insert:
            return None
        record = {
            "id": str(uuid4()),
            **data,
        }
        self.actions.append(record)
        return record


class FakeThreatRepo:
    async def get_stats(self, include_demo=False):
        return {
            "open_alerts": 1,
            "investigating_alerts": 0,
        }


class FakeAlertService:
    def __init__(self):
        self.statuses = []

    async def update_status(self, alert_id, status, notes=None):
        self.statuses.append((alert_id, status, notes))
        return {
            "alert_id": alert_id,
            "source_ip": "198.51.100.8",
            "status": status,
            "timeline": [],
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }


class FakeHub:
    def __init__(self):
        self.events = []

    async def broadcast(self, event, payload):
        self.events.append((event, payload))


def service(*, fail_insert=False):
    firewall = FakeFirewallRepo(fail_insert=fail_insert)
    alert_service = FakeAlertService()
    response = ResponseService(firewall, FakeThreatRepo(), alert_service)
    response.hub = FakeHub()
    return response, firewall, alert_service


@pytest.mark.asyncio
async def test_block_is_recorded_but_never_claimed_as_enforced():
    response, firewall, _ = service()
    result = await response.block_ip(
        "198.51.100.8",
        uuid4(),
        "High-risk alert",
        "alert-1",
    )
    assert result["status"] == "RECORDED_ONLY"
    assert result["recorded"] is True
    assert result["enforced"] is False
    assert "No operating-system firewall change" in result["message"]
    assert firewall.audits[0]["resource_id"] == "alert-1"
    assert firewall.audits[0]["payload"]["enforced"] is False


@pytest.mark.asyncio
async def test_block_storage_failure_is_not_reported_as_success():
    response, _, _ = service(fail_insert=True)
    result = await response.block_ip("198.51.100.8", uuid4(), None, "alert-1")
    assert result is None


@pytest.mark.asyncio
async def test_unblock_and_whitelist_are_truthful_recorded_actions():
    response, firewall, _ = service()
    unblock = await response.unblock_ip(
        "198.51.100.8", uuid4(), "Review", "alert-1"
    )
    whitelist = await response.whitelist_ip(
        "203.0.113.9", uuid4(), "Approved host", "alert-2"
    )
    assert unblock["action"] == "UNBLOCK"
    assert whitelist["action"] == "WHITELIST"
    assert unblock["enforced"] is False
    assert whitelist["enforced"] is False
    assert [item["action"] for item in firewall.actions] == [
        "UNBLOCK",
        "WHITELIST",
    ]


@pytest.mark.asyncio
async def test_investigate_ignore_and_resolve_preserve_alert_evidence():
    response, firewall, alerts = service()
    investigated = await response.investigate_threat("alert-1", uuid4())
    ignored = await response.ignore_threat("alert-1", uuid4(), "Not relevant")
    resolved = await response.resolve_threat("alert-2", uuid4(), "Handled")
    assert investigated["status"] == "INVESTIGATING"
    assert ignored["status"] == "FALSE_POSITIVE"
    assert resolved["status"] == "RESOLVED"
    assert [status for _, status, _ in alerts.statuses] == [
        "INVESTIGATING",
        "FALSE_POSITIVE",
        "RESOLVED",
    ]
    assert [item["action"] for item in firewall.audits] == [
        "INVESTIGATE",
        "IGNORE",
        "RESOLVE",
    ]


@pytest.mark.asyncio
async def test_response_routes_reject_missing_user_jwt(monkeypatch):
    test_app = FastAPI()
    test_app.include_router(
        response_router,
        dependencies=[Depends(verify_local_token)],
    )
    monkeypatch.setenv("CYBERSENTINEL_LOCAL_TOKEN", "local-test-token")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=test_app),
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/api/v1/response/threats",
            headers={
                "X-CyberSentinel-Local-Token": "local-test-token",
            },
        )
    assert response.status_code == 401
