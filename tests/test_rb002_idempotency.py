from fastapi.testclient import TestClient
from app.main import app
import pytest

def test_block_idempotency():
    from app.api.response_routes import get_response_service
    from fastapi import HTTPException
    
    class MockIdempotentResponseService:
        def __init__(self):
            self.blocked_ips = set()
            
        async def block_ip(self, ip, user_id, reason):
            if ip in self.blocked_ips:
                raise HTTPException(status_code=409, detail="IP is already blocked")
            self.blocked_ips.add(ip)
            return {"id": "dummy", "ip": ip, "action": "BLOCK", "created_at": "2026-01-01T00:00:00Z"}
            
    mock_service = MockIdempotentResponseService()
    app.dependency_overrides[get_response_service] = lambda: mock_service
    try:
        with TestClient(app) as client:
            # First block
            response1 = client.post("/api/v1/response/block", json={"ip": "10.0.0.99", "reason": "Testing block"})
            assert response1.status_code == 200, f"Expected 200, got {response1.status_code}: {response1.text}"
            
            # Second block
            response2 = client.post("/api/v1/response/block", json={"ip": "10.0.0.99", "reason": "Testing block again"})
            assert response2.status_code == 409, f"Expected 409, got {response2.status_code}: {response2.text}"
            
            # Also check RB-019 recorded/enforced
            data = response1.json()
            assert data.get("recorded") is True
        assert data.get("enforced") is False
        assert data.get("message") == "Action recorded but not enforced at OS level."
    finally:
        app.dependency_overrides.pop(get_response_service, None)
