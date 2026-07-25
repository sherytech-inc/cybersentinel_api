"""
CyberSentinel — Phase 6 Integration Test Suite
================================================
Mocks database repositories and tests all query, action, and copilot endpoints.
"""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from uuid import uuid4

from app.main import app
from app.repositories import (
    get_packet_repo,
    get_firewall_repo,
    get_threat_score_repo,
    get_firewall_action_repo,
    get_threat_alert_repo,
)


# ── Mock Repositories ─────────────────────────────────────────────────────────

class MockThreatAlertRepository:
    def __init__(self):
        self._db = self

    async def get_all(self, page=1, page_size=50):
        items = [
            {
                "alert_id": "alert-1",
                "source_ip": "185.220.101.45",
                "severity": "HIGH",
                "action": "MONITOR",
                "status": "OPEN",
                "threat_score": 85.0,
                "summary": "Known suspicious source",
                "explanation": ["Known suspicious source"],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "occurrence_count": 1,
                "timeline": [],
                "context_ready": True
            }
        ]
        return items, len(items)

    async def get_by_severity(self, severities, page=1, page_size=50):
        items = [
            {
                "alert_id": "alert-1",
                "source_ip": "185.220.101.45",
                "severity": "CRITICAL" if "CRITICAL" in severities and "HIGH" not in severities else "HIGH",
                "action": "MONITOR",
                "status": "OPEN",
                "threat_score": 95.0 if "CRITICAL" in severities and "HIGH" not in severities else 85.0,
                "summary": "Known suspicious source",
                "explanation": ["Known suspicious source"],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "occurrence_count": 1,
                "timeline": [],
                "context_ready": True
            }
        ]
        return items, len(items)

    async def get_history(self, *args, **kwargs):
        return await self.get_all()

    async def get_stats(self):
        return {
            "total_alerts": 1,
            "critical_alerts": 0,
            "high_alerts": 1,
            "open_alerts": 1,
            "investigating_alerts": 0,
            "blocked_alerts": 0,
            "resolved_alerts": 0,
            "active_investigations": 0,
            "false_positives": 0
        }


class MockPacketRepository:
    async def list(self, order_by="captured_at", descending=True, page=1, page_size=50):
        items = [
            {
                "id": str(uuid4()),
                "session_id": "session-1",
                "source_ip": "192.168.1.45",
                "destination_ip": "185.220.101.45",
                "source_port": 50123,
                "destination_port": 443,
                "protocol": "TCP",
                "packet_size": 1200,
                "ml_prediction": "Normal",
                "ml_confidence": 0.98,
                "anomaly_score": 0.15,
                "threat_score": 12.0,
                "severity": "NORMAL",
                "flow_features": {"feature_1": 0.5},
                "captured_at": datetime.now(timezone.utc).isoformat(),
            }
        ]
        return items, len(items)

    async def get_stats(self, since=None):
        return {"Normal": 10, "Suspicious": 2, "Malicious": 1}


class MockFirewallLogRepository:
    async def list(self, order_by="logged_at", descending=True, page=1, page_size=50):
        items = [
            {
                "id": str(uuid4()),
                "source_ip": "185.220.101.45",
                "destination_ip": "10.0.0.5",
                "source_port": 22,
                "destination_port": 22,
                "protocol": "TCP",
                "action": "BLOCK",
                "rule_name": "SSH-BRUTE-FORCE",
                "bytes_sent": 500,
                "bytes_received": 1200,
                "anomaly_score": 95.0,
                "is_anomalous": True,
                "interface": "en0",
                "direction": "inbound",
                "logged_at": datetime.now(timezone.utc).isoformat(),
            }
        ]
        return items, len(items)


class MockThreatScoreRepository:
    def __init__(self):
        self._db = self

    class TableMock:
        def select(self, *args, **kwargs):
            return self
        def gte(self, *args, **kwargs):
            return self
        def lte(self, *args, **kwargs):
            return self
        def gt(self, *args, **kwargs):
            return self
        def order(self, *args, **kwargs):
            return self
        def limit(self, *args, **kwargs):
            return self
        def range(self, *args, **kwargs):
            return self
        async def execute(self):
            class Result:
                data = [
                    {
                        "id": str(uuid4()),
                        "source_ip": "185.220.101.45",
                        "threat_score": 85.0,
                        "severity": "HIGH",
                        "recommendation": "MONITOR",
                        "reasoning": ["Known suspicious source"],
                        "scored_at": datetime.now(timezone.utc).isoformat(),
                    }
                ]
                count = 1
            return Result()

    def table(self, name):
        return self.TableMock()

    async def list(self, order_by="scored_at", descending=True, page=1, page_size=50):
        items = [
            {
                "id": str(uuid4()),
                "source_ip": "185.220.101.45",
                "threat_score": 85.0,
                "severity": "HIGH",
                "recommendation": "MONITOR",
                "reasoning": ["Known suspicious source"],
                "scored_at": datetime.now(timezone.utc).isoformat(),
            }
        ]
        return items, len(items)


class MockFirewallActionRepository:
    class TableMock:
        def __init__(self, parent):
            self.parent = parent
        def insert(self, data):
            return self
        def select(self, *args, **kwargs):
            return self
        def eq(self, *args, **kwargs):
            return self
        def order(self, *args, **kwargs):
            return self
        def range(self, *args, **kwargs):
            return self
        async def execute(self):
            class Result:
                data = [
                    {"action": "BLOCK", "created_at": "2026-01-01T00:00:00Z"},
                    {"action": "UNBLOCK", "created_at": "2026-01-01T00:00:01Z"}
                ]
                count = 2
            return Result()

    class DBMock:
        def __init__(self, parent):
            self.parent = parent
        def table(self, name):
            return self.parent.TableMock(self.parent)

    def __init__(self):
        self.inserted = []
        self._db = self.DBMock(self)

    async def insert(self, record):
        record_id = uuid4()
        row = {
            "id": record_id,
            "ip": record["ip"],
            "action": record["action"],
            "reason": record.get("reason"),
            "source": record.get("source", "USER"),
            "created_at": datetime.now(timezone.utc),
        }
        self.inserted.append(row)
        return row

    async def list(self, order_by="created_at", descending=True, page=1, page_size=50):
        return self.inserted, len(self.inserted)

    async def get_blocked_ips(self):
        return [r["ip"] for r in self.inserted if r["action"] == "BLOCK"]


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    app.dependency_overrides[get_packet_repo] = lambda: MockPacketRepository()
    app.dependency_overrides[get_firewall_repo] = lambda: MockFirewallLogRepository()
    app.dependency_overrides[get_threat_score_repo] = lambda: MockThreatScoreRepository()
    app.dependency_overrides[get_threat_alert_repo] = lambda: MockThreatAlertRepository()
    
    mock_action_repo = MockFirewallActionRepository()
    app.dependency_overrides[get_firewall_action_repo] = lambda: mock_action_repo

    with TestClient(app) as c:
        yield c
    
    app.dependency_overrides.clear()


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestOperationsRoutes:
    def test_list_packets(self, client):
        resp = client.get("/api/v1/packets")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert len(data["items"]) == 1
        assert data["items"][0]["source_ip"] == "192.168.1.45"
        assert "flow_features" in data["items"][0]

    def test_list_firewall_logs(self, client):
        resp = client.get("/api/v1/operations/firewall")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert len(data["items"]) == 1
        assert data["items"][0]["action"] == "BLOCK"

    def test_list_threats(self, client):
        resp = client.get("/api/v1/threats")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert len(data["items"]) == 1
        assert data["items"][0]["threat_score"] == 85.0

    def test_threat_history_route(self, client):
        resp = client.get("/api/v1/threats/history")
        assert resp.status_code == 200

    def test_high_threats_filter(self, client):
        resp = client.get("/api/v1/threats/high")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 1

    def test_critical_threats_filter(self, client):
        resp = client.get("/api/v1/threats/critical")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 1

    def test_dashboard_stats(self, client):
        resp = client.get("/api/v1/dashboard/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["threat_score"] == 85
        assert data["total_packets_count"] == 13
        assert data["packet_classification"]["normal"] == 10
        assert len(data["malicious_ips"]) == 1


class TestFirewallActionRoutes:
    def test_block_ip(self, client):
        body = {"ip": "185.220.101.45", "reason": "Testing block"}
        resp = client.post("/api/v1/firewall-action/block", json=body)
        assert resp.status_code == 200
        data = resp.json()
        assert data["action"] == "BLOCK"
        assert data["ip"] == "185.220.101.45"
        assert data["reason"] == "Testing block"

    def test_unblock_ip(self, client):
        body = {"ip": "185.220.101.45"}
        resp = client.post("/api/v1/firewall-action/unblock", json=body)
        assert resp.status_code == 200
        data = resp.json()
        assert data["action"] == "UNBLOCK"

    def test_whitelist_ip(self, client):
        body = {"ip": "192.168.1.10"}
        resp = client.post("/api/v1/firewall-action/whitelist", json=body)
        assert resp.status_code == 200
        data = resp.json()
        assert data["action"] == "WHITELIST"


class TestCopilotRoutes:
    def test_copilot_context(self, client):
        resp = client.get("/api/v1/copilot/context")
        assert resp.status_code == 200
        data = resp.json()
        assert "latest_alerts" in data
        assert "critical_threats" in data
        assert "blocked_ips" in data
        assert "top_attack_types" in data
        assert "system_health" in data
