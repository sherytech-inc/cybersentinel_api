from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta, timezone
import uuid

import jwt
import pytest
from fastapi import status
from postgrest.exceptions import APIError

from app.api.auth_dependencies import (
    SupabaseUserIdentity,
    get_verified_supabase_user,
)
from app.main import app


TEST_USER_ID = uuid.UUID("7996d00a-1c0d-4b64-b891-ace17d258025")
TEST_EMAIL = "analyst@example.com"


def _identity() -> SupabaseUserIdentity:
    return SupabaseUserIdentity(user_id=TEST_USER_ID, email=TEST_EMAIL)


def _rpc_db(*, data=None, error=None):
    db = MagicMock()
    execute = AsyncMock()
    if error is not None:
        execute.side_effect = error
    else:
        execute.return_value = SimpleNamespace(data=data)
    db.rpc.return_value.execute = execute
    return db


@pytest.fixture
def verified_user():
    app.dependency_overrides[get_verified_supabase_user] = _identity
    yield
    app.dependency_overrides.pop(get_verified_supabase_user, None)


@pytest.mark.asyncio
async def test_valid_approved_user_bootstrap_uses_only_jwt_scoped_rpc(
    async_client,
    verified_user,
):
    profile = {
        "user_id": str(TEST_USER_ID),
        "email": TEST_EMAIL,
        "display_name": "Test Analyst",
        "role": "analyst",
        "is_active": True,
    }
    db = _rpc_db(data=profile)

    with patch("app.api.auth_routes.get_db_client", AsyncMock(return_value=db)):
        response = await async_client.post(
            "/api/v1/auth/bootstrap-profile",
            headers={"Authorization": "Bearer verified-jwt"},
        )

    assert response.status_code == 200
    assert response.json()["profile"] == profile
    db.rpc.assert_called_once_with("bootstrap_current_user_profile", {})
    db.table.assert_not_called()


@pytest.mark.asyncio
async def test_missing_bearer_token_returns_401(async_client):
    response = await async_client.post("/api/v1/auth/bootstrap-profile")

    assert response.status_code == 401
    assert "token" not in response.text.lower()


@pytest.mark.asyncio
async def test_expired_bearer_token_returns_sanitized_401(
    async_client,
    monkeypatch,
):
    from app.core.config import get_settings

    settings = get_settings()
    previous_secret = settings.SUPABASE_JWT_SECRET
    test_secret = "auth-bootstrap-expired-token-test-secret"
    settings.SUPABASE_JWT_SECRET = test_secret
    monkeypatch.setenv("ALLOW_DEV_AUTH", "false")
    monkeypatch.setenv("APP_ENV", "production")
    token = jwt.encode(
        {
            "sub": str(TEST_USER_ID),
            "email": TEST_EMAIL,
            "aud": "authenticated",
            "iss": f"{settings.SUPABASE_URL.rstrip('/')}/auth/v1",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
        },
        test_secret,
        algorithm="HS256",
    )

    try:
        response = await async_client.post(
            "/api/v1/auth/bootstrap-profile",
            headers={"Authorization": f"Bearer {token}"},
        )
    finally:
        settings.SUPABASE_JWT_SECRET = previous_secret

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid authentication token."}
    assert token not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("reason", "expected_status"),
    [
        ("authentication_required", 401),
        ("authenticated_email_missing", 401),
        ("account_not_authorized", 403),
        ("account_disabled", 403),
        ("invalid_authorization_role", 503),
    ],
)
async def test_rpc_rejections_are_safely_mapped(
    async_client,
    verified_user,
    reason,
    expected_status,
):
    db = _rpc_db(
        error=APIError(
            {
                "code": "42501",
                "message": reason,
                "details": "sensitive database detail",
                "hint": "sensitive database hint",
            }
        )
    )

    with patch("app.api.auth_routes.get_db_client", AsyncMock(return_value=db)):
        response = await async_client.post(
            "/api/v1/auth/bootstrap-profile",
            headers={"Authorization": "Bearer verified-jwt"},
        )

    assert response.status_code == expected_status
    assert response.json()["detail"] in {
        reason,
        "profile_authorization_configuration_invalid",
    }
    assert "sensitive" not in response.text


@pytest.mark.asyncio
async def test_unexpected_rpc_failure_is_sanitized(
    async_client,
    verified_user,
):
    db = _rpc_db(error=RuntimeError("database host and secret details"))

    with patch("app.api.auth_routes.get_db_client", AsyncMock(return_value=db)):
        response = await async_client.post(
            "/api/v1/auth/bootstrap-profile",
            headers={"Authorization": "Bearer verified-jwt"},
        )

    assert response.status_code == 503
    assert response.json() == {"detail": "profile_storage_unavailable"}
    assert "database host" not in response.text


@pytest.mark.asyncio
async def test_invalid_rpc_profile_is_configuration_failure(
    async_client,
    verified_user,
):
    db = _rpc_db(
        data={
            "user_id": str(TEST_USER_ID),
            "email": TEST_EMAIL,
            "display_name": "Test Analyst",
            "role": "owner",
            "is_active": True,
        }
    )

    with patch("app.api.auth_routes.get_db_client", AsyncMock(return_value=db)):
        response = await async_client.post(
            "/api/v1/auth/bootstrap-profile",
            headers={"Authorization": "Bearer verified-jwt"},
        )

    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert response.json() == {"detail": "profile_storage_unavailable"}
