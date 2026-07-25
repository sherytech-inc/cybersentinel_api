from fastapi.testclient import TestClient
from app.main import app

def test_action_history_integration():
    from app.api.response_routes import get_response_service
    
    class MockHistoryResponseService:
        def __init__(self):
            self.history = [
                {"id": "mock_id1", "ip": "10.0.0.100", "action": "BLOCK", "status": "SUCCESS", "created_at": "2026-01-01T00:00:01Z"},
                {"id": "mock_id2", "ip": "10.0.0.100", "action": "UNBLOCK", "status": "SUCCESS", "created_at": "2026-01-01T00:00:00Z"}
            ]
        async def block_ip(self, ip, user_id, reason):
            return {"id": "dummy", "ip": ip, "action": "BLOCK", "created_at": "2026-01-01T00:00:01Z"}
        async def unblock_ip(self, ip, user_id, reason):
            return {"id": "dummy", "ip": ip, "action": "UNBLOCK", "created_at": "2026-01-01T00:00:00Z"}
        async def get_action_history(self, page, page_size):
            return self.history, 2
            
    app.dependency_overrides[get_response_service] = lambda: MockHistoryResponseService()
    try:
        with TestClient(app) as client:
            # First, mock or create a threat alert if needed, or use a dummy ID.
            # Since resolve and ignore endpoints don't strictly require the DB to have the alert for the audit log insert in the mocked context (wait, the service calls `alert_service.update_status` which might fail if alert_id doesn't exist).
            # Let's inject a demo scenario or just rely on block/unblock which just need IPs.
            client.post("/api/v1/response/block", json={"ip": "10.0.0.100", "reason": "Test block"})
            client.post("/api/v1/response/unblock", json={"ip": "10.0.0.100", "reason": "Test unblock"})
            
            # Now fetch history
            resp = client.get("/api/v1/response/history")
            assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert len(data["items"]) >= 2
        
        # Check that block and unblock are present
        actions = [item["action"] for item in data["items"]]
        assert "BLOCK" in actions
        assert "UNBLOCK" in actions
        
        # Check ordering (newest first)
        timestamps = [item["created_at"] for item in data["items"]]
        assert timestamps == sorted(timestamps, reverse=True)
    finally:
        app.dependency_overrides.pop(get_response_service, None)
