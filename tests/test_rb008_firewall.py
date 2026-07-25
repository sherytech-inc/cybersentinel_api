import pytest
from fastapi.testclient import TestClient
from app.main import app

def test_firewall_logs():
    with TestClient(app) as client:
        response = client.get("/api/v1/operations/firewall?page=1&page_size=10")
        assert response.status_code == 200
        data = response.json()
        items = data.get("items", [])
        
        for item in items:
            assert "source_ip" in item
            if item.get("destination_port") is not None:
                assert isinstance(item["destination_port"], int)
            assert "action" in item
            assert "logged_at" in item
            assert "reason" not in item

def test_firewall_actions():
    with TestClient(app) as client:
        response = client.get("/api/v1/firewall-action/actions?page=1&page_size=10")
        assert response.status_code == 200
        data = response.json()
        items = data.get("items", [])
        
        for item in items:
            assert "ip" in item
            assert "action" in item
            assert "source" in item
            assert "created_at" in item
            assert "destination_port" not in item
            assert "rule_name" not in item
