import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.api.response_routes import get_response_service

class MockService:
    async def resolve_threat(self, alert_id, user_id, notes):
        return True
    async def ignore_threat(self, alert_id, user_id, notes):
        return True

@pytest.fixture
def client():
    app.dependency_overrides[get_response_service] = lambda: MockService()
    yield TestClient(app)
    app.dependency_overrides.pop(get_response_service, None)

def test_resolve_with_empty_body(client):
    response = client.post("/api/v1/response/threats/dummy/resolve", json={})
    assert response.status_code != 422, f"Expected validation to pass, got 422: {response.text}"
    assert response.status_code == 200

def test_resolve_with_notes(client):
    response = client.post("/api/v1/response/threats/dummy/resolve", json={"notes": "test notes"})
    assert response.status_code == 200

def test_ignore_with_empty_body(client):
    response = client.post("/api/v1/response/threats/dummy/ignore", json={})
    assert response.status_code == 200

def test_ignore_with_notes(client):
    response = client.post("/api/v1/response/threats/dummy/ignore", json={"notes": "test ignore notes"})
    assert response.status_code == 200

