from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from uuid import uuid4

from app.main import app
from app.repositories import get_threat_alert_repo, get_packet_repo
from app.services.threat_response.alert_service import AlertService
from app.services.threat_response.alert_generator import AlertGenerator

# ── Mock Threat Alert Repository ──────────────────────────────────────────────

class MockThreatAlertRepository:
    def __init__(self):
        self.alerts = []
        self._db = self

    async def get_by_id(self, record_id: str):
        for alert in self.alerts:
            if alert["alert_id"] == record_id:
                return alert
        return None

    async def update(self, record_id: str, data: dict):
        for alert in self.alerts:
            if alert["alert_id"] == record_id:
                alert.update(data)
                alert["updated_at"] = datetime.now(timezone.utc).isoformat()
                return alert
        return None

    async def insert_alert(self, data: dict):
        alert_id = str(uuid4())
        alert = {
            "alert_id": alert_id,
            **data
        }
        self.alerts.append(alert)
        return alert

    async def update_alert(self, alert_id: str, data: dict):
        return await self.update(alert_id, data)

    async def get_all(self, page: int = 1, page_size: int = 50):
        # Sort by created_at desc
        sorted_alerts = sorted(self.alerts, key=lambda x: x.get("created_at", ""), reverse=True)
        offset = (page - 1) * page_size
        return sorted_alerts[offset:offset + page_size], len(self.alerts)

    async def get_by_severity(self, severities: list[str], page: int = 1, page_size: int = 50):
        filtered = [a for a in self.alerts if a.get("severity") in severities]
        sorted_alerts = sorted(filtered, key=lambda x: x.get("created_at", ""), reverse=True)
        offset = (page - 1) * page_size
        return sorted_alerts[offset:offset + page_size], len(filtered)

    async def get_history(
        self,
        severity=None,
        status=None,
        ip=None,
        start_date=None,
        end_date=None,
        page: int = 1,
        page_size: int = 50,
    ):
        filtered = []
        for a in self.alerts:
            if severity and a.get("severity") != severity:
                continue
            if status and a.get("status") != status:
                continue
            if ip and a.get("source_ip") != ip:
                continue
            if start_date:
                dt = datetime.fromisoformat(a.get("created_at"))
                if dt < start_date:
                    continue
            if end_date:
                dt = datetime.fromisoformat(a.get("created_at"))
                if dt > end_date:
                    continue
            filtered.append(a)

        sorted_alerts = sorted(filtered, key=lambda x: x.get("created_at", ""), reverse=True)
        offset = (page - 1) * page_size
        return sorted_alerts[offset:offset + page_size], len(filtered)

    async def update_status(self, alert_id: str, status: str, timeline_event: dict):
        alert = await self.get_by_id(alert_id)
        if not alert:
            return None
        
        timeline = alert.get("timeline") or []
        timeline.append(timeline_event)
        alert["status"] = status
        alert["timeline"] = timeline
        alert["updated_at"] = datetime.now(timezone.utc).isoformat()
        return alert

    async def get_stats(self) -> dict:
        stats = {
            "total_alerts": len(self.alerts),
            "critical_alerts": 0,
            "high_alerts": 0,
            "open_alerts": 0,
            "investigating_alerts": 0,
            "blocked_alerts": 0,
            "resolved_alerts": 0,
            "active_investigations": 0,
            "false_positives": 0
        }
        for a in self.alerts:
            sev = a.get("severity")
            stat = a.get("status")
            act = a.get("action")

            if sev == "CRITICAL":
                stats["critical_alerts"] += 1
            elif sev == "HIGH":
                stats["high_alerts"] += 1

            if stat == "OPEN":
                stats["open_alerts"] += 1
            elif stat == "INVESTIGATING":
                stats["investigating_alerts"] += 1
                stats["active_investigations"] += 1
            elif stat == "RESOLVED":
                stats["resolved_alerts"] += 1
            elif stat == "FALSE_POSITIVE":
                stats["false_positives"] += 1

            if act == "BLOCK":
                stats["blocked_alerts"] += 1

        return stats

    async def increment_occurrence(self, alert_id: str, updated_fields: dict):
        alert = await self.get_by_id(alert_id)
        if not alert:
            return None
        
        count = alert.get("occurrence_count", 1) + 1
        timeline = alert.get("timeline") or []
        timeline.append({
            "event": "DUPLICATE_OCCURRENCE",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "occurrence_number": count,
            "threat_score": updated_fields.get("threat_score")
        })

        alert.update(updated_fields)
        alert["occurrence_count"] = count
        alert["timeline"] = timeline
        alert["updated_at"] = datetime.now(timezone.utc).isoformat()
        return alert

    async def find_active_alert_by_ip(self, ip: str, timeframe_seconds: int):
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=timeframe_seconds)
        for a in self.alerts:
            if a.get("source_ip") == ip and a.get("status") in ["OPEN", "INVESTIGATING"]:
                dt = datetime.fromisoformat(a.get("updated_at"))
                if dt >= cutoff:
                    return a
        return None


class MockPacketRepository:
    async def get_stats(self, since=None):
        return {"Normal": 10, "Suspicious": 2, "Malicious": 1}

# ── Fixtures ──────────────────────────────────────────────────────────────────

mock_alert_repo = MockThreatAlertRepository()

@pytest.fixture(scope="module")
def client():
    app.dependency_overrides[get_threat_alert_repo] = lambda: mock_alert_repo
    app.dependency_overrides[get_packet_repo] = lambda: MockPacketRepository()
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

# ── Tests ─────────────────────────────────────────────────────────────────────

class TestThreatAlerts:
    @pytest.mark.asyncio
    async def test_alert_generation_rules(self):
        # 1. Test generator skips SAFE / LOW / MEDIUM
        service = AlertService(mock_alert_repo, duplicate_timeframe_minutes=1)
        generator = AlertGenerator(service)
        
        # Test low severity
        low_threat = {
            "source_ip": "1.1.1.1",
            "severity": "LOW",
            "action": "ALLOW",
            "threat_score": 15.0,
            "explanation": ["Normal activity"]
        }
        res = await generator.generate_alert(low_threat)
        assert res is None

    @pytest.mark.asyncio
    async def test_alert_creation_and_duplication(self):
        # Clear existing alerts
        mock_alert_repo.alerts = []

        # 1. Trigger first CRITICAL threat alert
        alert1_data = {
            "source_ip": "192.168.1.150",
            "severity": "CRITICAL",
            "action": "BLOCK",
            "threat_score": 95.0,
            "explanation": ["Known malicious command center connection attempt", "Highly anomalous payload size"],
            "trace_id": str(uuid4()),
            "model1_score": 0.96,
            "model2_score": 0.88,
            "model3_score": 0.99,
            "model1_classification": "Malicious",
            "model2_severity": "Critical",
            "model3_severity": "Critical"
        }

        service = AlertService(mock_alert_repo, duplicate_timeframe_minutes=10)
        generator = AlertGenerator(service)

        alert1 = await generator.generate_alert(alert1_data)
        
        assert alert1 is not None
        assert alert1["occurrence_count"] == 1
        assert alert1["status"] == "OPEN"
        assert len(alert1["timeline"]) == 1
        assert alert1["timeline"][0]["event"] == "CREATED"
        assert "blocking" in alert1["summary"]  # Recommendation check

        # 2. Trigger same threat again (should update count and timeline, not insert a new row)
        alert2_data = alert1_data.copy()
        alert2_data["threat_score"] = 98.0
        
        alert2 = await generator.generate_alert(alert2_data)
        assert alert2["alert_id"] == alert1["alert_id"]
        assert alert2["occurrence_count"] == 2
        assert alert2["threat_score"] == 98.0
        assert len(alert2["timeline"]) == 2
        assert alert2["timeline"][1]["event"] == "DUPLICATE_OCCURRENCE"
        assert len(mock_alert_repo.alerts) == 1  # Deduplicated!

    def test_list_threats_endpoints(self, client):
        # Test GET /threats
        resp = client.get("/api/v1/threats")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert len(data["items"]) == 1
        assert data["items"][0]["source_ip"] == "192.168.1.150"
        assert data["items"][0]["occurrence_count"] == 2
        assert "scored_at" in data["items"][0]  # Backwards compatibility check
        assert "reasoning" in data["items"][0]  # Backwards compatibility check

        # Test GET /threats/open
        resp = client.get("/api/v1/threats/open")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 1

        # Test GET /threats/high
        resp = client.get("/api/v1/threats/high")
        assert resp.status_code == 200
        assert len(resp.json()["items"]) == 1

        # Test GET /threats/stats
        resp = client.get("/api/v1/threats/stats")
        assert resp.status_code == 200
        stats = resp.json()
        assert stats["total_alerts"] == 1
        assert stats["critical_alerts"] == 1
        assert stats["open_alerts"] == 1

    def test_lifecycle_status_transitions(self, client):
        alert_id = mock_alert_repo.alerts[0]["alert_id"]

        # Update status to INVESTIGATING
        resp = client.patch(f"/api/v1/threats/{alert_id}/status", json={
            "status": "INVESTIGATING",
            "notes": "Analyst looking into this IP reputation and payloads."
        })
        assert resp.status_code == 200
        updated = resp.json()
        assert updated["status"] == "INVESTIGATING"
        assert len(updated["timeline"]) == 3
        assert updated["timeline"][-1]["event"] == "STATUS_CHANGE_TO_INVESTIGATING"

        # Check stats endpoint reflects change
        resp = client.get("/api/v1/threats/stats")
        stats = resp.json()
        assert stats["open_alerts"] == 0
        assert stats["investigating_alerts"] == 1
        assert stats["active_investigations"] == 1

        # Try updating to invalid status
        resp = client.patch(f"/api/v1/threats/{alert_id}/status", json={
            "status": "BLOCKED",
            "notes": "Invalid state check"
        })
        assert resp.status_code == 400
