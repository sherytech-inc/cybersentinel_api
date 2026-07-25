import asyncio
import pytest
from fastapi import status
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock

from app.main import app
from app.services.websocket.connection_manager import get_websocket_hub

# ── Tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_websocket_hub_connection_metrics():
    hub = get_websocket_hub()
    
    # Verify initial metrics
    metrics = hub.get_metrics()
    assert metrics["active_connections"] == 0
    assert metrics["packets_sent"] == 0
    assert metrics["threats_sent"] == 0
    
    # Mock WebSocket connection
    mock_ws = AsyncMock()
    mock_ws.accept = AsyncMock()
    mock_ws.send_json = AsyncMock()
    
    # Test connect (which also sends initial state snapshot)
    # We temporarily patch _send_initial_state to avoid database lookups in simple unit test
    original_send = hub._send_initial_state
    hub._send_initial_state = AsyncMock()
    
    await hub.connect(mock_ws)
    
    assert mock_ws in hub.active_connections
    assert hub.get_metrics()["active_connections"] == 1
    hub._send_initial_state.assert_called_once_with(mock_ws)
    
    # Test broadcast increments metric
    await hub.broadcast(event_type="new_threat", payload={"alert_id": "ALT-123"})
    mock_ws.send_json.assert_called_once()
    assert hub.get_metrics()["threats_sent"] == 1
    
    # Test disconnect
    await hub.disconnect(mock_ws)
    assert mock_ws not in hub.active_connections
    assert hub.get_metrics()["active_connections"] == 0
    
    # Restore original method
    hub._send_initial_state = original_send


@pytest.mark.asyncio
async def test_websocket_hub_packet_batching():
    hub = get_websocket_hub()
    hub.packet_queue.clear()
    
    # Queue up a few packets
    await hub.queue_packet({"id": 1, "size": 100})
    await hub.queue_packet({"id": 2, "size": 200})
    
    assert len(hub.packet_queue) == 2
    
    # Setup mock WebSocket
    mock_ws = AsyncMock()
    hub.active_connections.add(mock_ws)
    
    # Run a single batch cycle
    # Since run_packet_batch_loop runs forever, we can test the queue clearing and broadcast manually
    batch = list(hub.packet_queue)
    hub.packet_queue.clear()
    
    await hub.broadcast("packet_batch", {"packets": batch})
    
    mock_ws.send_json.assert_called_once()
    sent_data = mock_ws.send_json.call_args[0][0]
    assert sent_data["event_type"] == "packet_batch"
    assert len(sent_data["payload"]["packets"]) == 2
    assert sent_data["payload"]["packets"][0]["id"] == 1
    
    hub.active_connections.remove(mock_ws)


def test_ws_stats_endpoint():
    client = TestClient(app)
    resp = client.get("/api/v1/system/ws-stats")
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert "active_connections" in data
    assert "packets_sent" in data
    assert "threats_sent" in data
