import uuid
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.api.auth_dependencies import SupabaseUserIdentity
from app.main import app
from app.services.websocket.connection_manager import get_websocket_hub


VALID_TOKEN = "valid-supabase-jwt"
LOCAL_TOKEN = "valid-local-token"
USER = SupabaseUserIdentity(user_id=uuid.uuid4(), email="analyst@example.com")


@pytest.fixture
def websocket_dependencies(monkeypatch):
    monkeypatch.setenv("CYBERSENTINEL_LOCAL_TOKEN", LOCAL_TOKEN)
    hub = get_websocket_hub()
    original_initial_state = hub._send_initial_state

    async def send_initial_state(websocket, access_token=None):
        assert access_token == VALID_TOKEN
        await websocket.send_json({"type": "initial_state", "payload": {}})

    hub._send_initial_state = send_initial_state
    yield hub
    hub._send_initial_state = original_initial_state
    hub.active_connections.clear()


def test_valid_jwt_and_local_token_receive_ack_before_initial_state(
    websocket_dependencies,
):
    with patch(
        "app.api.auth_dependencies.get_verified_supabase_user",
        new=AsyncMock(return_value=USER),
    ) as verify_jwt, patch(
        "app.api.auth_dependencies.get_current_analyst_for_token",
        new=AsyncMock(),
    ) as resolve_analyst:
        with TestClient(app) as client:
            with client.websocket_connect("/ws/events") as websocket:
                websocket.send_json({
                    "type": "auth",
                    "token": VALID_TOKEN,
                    "local_token": LOCAL_TOKEN,
                })

                assert websocket.receive_json() == {
                    "type": "auth_ack",
                    "status": "success",
                }
                assert websocket.receive_json()["type"] == "initial_state"

        verify_jwt.assert_awaited_once()
        resolve_analyst.assert_awaited_once_with(
            user=USER,
            access_token=VALID_TOKEN,
        )


def test_invalid_jwt_closes_with_policy_violation(websocket_dependencies):
    with patch(
        "app.api.auth_dependencies.get_verified_supabase_user",
        new=AsyncMock(side_effect=ValueError("invalid token")),
    ):
        with TestClient(app) as client:
            with client.websocket_connect("/ws/events") as websocket:
                websocket.send_json({
                    "type": "auth",
                    "token": "invalid-jwt",
                    "local_token": LOCAL_TOKEN,
                })
                with pytest.raises(WebSocketDisconnect) as closed:
                    websocket.receive_json()

    assert closed.value.code == 1008


def test_invalid_local_token_closes_before_profile_lookup(websocket_dependencies):
    with patch(
        "app.api.auth_dependencies.get_verified_supabase_user",
        new=AsyncMock(return_value=USER),
    ), patch(
        "app.api.auth_dependencies.get_current_analyst_for_token",
        new=AsyncMock(),
    ) as resolve_analyst:
        with TestClient(app) as client:
            with client.websocket_connect("/ws/events") as websocket:
                websocket.send_json({
                    "type": "auth",
                    "token": VALID_TOKEN,
                    "local_token": "wrong-local-token",
                })
                with pytest.raises(WebSocketDisconnect) as closed:
                    websocket.receive_json()

    assert closed.value.code == 1008
    resolve_analyst.assert_not_awaited()
