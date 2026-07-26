import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Depends, APIRouter
import uuid
import jwt
from unittest.mock import patch, MagicMock

from app.api.auth_dependencies import get_current_analyst, require_admin, AnalystIdentity

# Create a small app to test dependencies
app = FastAPI()
router = APIRouter()

@router.get("/me", response_model=AnalystIdentity)
async def get_me(analyst: AnalystIdentity = Depends(get_current_analyst)):
    return analyst

@router.get("/admin_only", response_model=AnalystIdentity)
async def get_admin(analyst: AnalystIdentity = Depends(require_admin)):
    return analyst

app.include_router(router)

client = TestClient(app)

def test_dev_admin_logic_bypass():
    # If ALLOW_DEV_AUTH is true and DEV_AUTH_TOKEN is matched or dev-test-<uuid>
    import os
    os.environ["ALLOW_DEV_AUTH"] = "true"
    os.environ["APP_ENV"] = "development"
    
    test_id = "00000000-0000-0000-0000-123456789abc"
    token = f"dev-test-{test_id}"
    
    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["user_id"] == test_id
    assert data["role"] == "admin"
    
    # Check require_admin logic
    response_admin = client.get("/admin_only", headers={"Authorization": f"Bearer {token}"})
    assert response_admin.status_code == 200

@pytest.mark.asyncio
@patch('app.api.auth_dependencies.get_db_client')
async def test_jwt_active_user(mock_get_db):
    import os
    os.environ["ALLOW_DEV_AUTH"] = "false"
    os.environ["APP_ENV"] = "production"
    
    from app.core.config import get_settings
    settings = get_settings()
    settings.SUPABASE_JWT_SECRET = "super-secret-key-for-testing-only"
    
    test_id = str(uuid.uuid4())
    payload = {
        "sub": test_id,
        "email": "analyst@example.com",
        "aud": "authenticated",
        "iss": f"{settings.SUPABASE_URL.rstrip('/')}/auth/v1" if settings.SUPABASE_URL else None
    }
    
    token = jwt.encode(payload, settings.SUPABASE_JWT_SECRET, algorithm="HS256")
    
    from unittest.mock import AsyncMock
    mock_db = MagicMock()
    mock_response = MagicMock()
    mock_response.data = {
        "user_id": test_id,
        "is_active": True,
        "role": "analyst",
        "display_name": "Test Analyst"
    }
    
    execute_mock = AsyncMock(return_value=mock_response)
    mock_db.table.return_value.select.return_value.eq.return_value.single.return_value.execute = execute_mock
    mock_get_db.return_value = mock_db
    
    # We must patch get_db_client inside auth_dependencies
    with patch('app.api.auth_dependencies.get_db_client', return_value=mock_db):
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == test_id
        assert data["role"] == "analyst"
        
        # Test require_admin blocks it
        response_admin = client.get("/admin_only", headers={"Authorization": f"Bearer {token}"})
        assert response_admin.status_code == 403

@pytest.mark.asyncio
@patch('app.api.auth_dependencies.get_db_client')
async def test_jwt_deactivated_user(mock_get_db):
    import os
    os.environ["ALLOW_DEV_AUTH"] = "false"
    os.environ["APP_ENV"] = "production"
    
    from app.core.config import get_settings
    settings = get_settings()
    settings.SUPABASE_JWT_SECRET = "super-secret-key-for-testing-only"
    
    test_id = str(uuid.uuid4())
    payload = {
        "sub": test_id,
        "email": "fired@example.com",
        "aud": "authenticated",
        "iss": f"{settings.SUPABASE_URL.rstrip('/')}/auth/v1" if settings.SUPABASE_URL else None
    }
    
    token = jwt.encode(payload, settings.SUPABASE_JWT_SECRET, algorithm="HS256")
    
    from unittest.mock import AsyncMock
    mock_db = MagicMock()
    mock_response = MagicMock()
    mock_response.data = {
        "user_id": test_id,
        "is_active": False,
        "role": "analyst"
    }
    
    execute_mock = AsyncMock(return_value=mock_response)
    mock_db.table.return_value.select.return_value.eq.return_value.single.return_value.execute = execute_mock
    
    with patch('app.api.auth_dependencies.get_db_client', return_value=mock_db):
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 403
        assert "deactivated" in response.json()["detail"].lower()

@pytest.mark.asyncio
@patch('app.api.auth_routes.get_db_client')
async def test_bootstrap_profile(mock_get_db):
    import os
    os.environ["ALLOW_DEV_AUTH"] = "false"
    os.environ["APP_ENV"] = "production"
    
    from app.core.config import get_settings
    settings = get_settings()
    settings.SUPABASE_JWT_SECRET = "super-secret-key-for-testing-only"
    
    test_id = str(uuid.uuid4())
    payload = {
        "sub": test_id,
        "email": "analyst@example.com",
        "aud": "authenticated",
        "iss": f"{settings.SUPABASE_URL.rstrip('/')}/auth/v1" if settings.SUPABASE_URL else None
    }
    
    token = jwt.encode(payload, settings.SUPABASE_JWT_SECRET, algorithm="HS256")
    
    from unittest.mock import AsyncMock
    mock_db = MagicMock()
    
    rpc_resp = MagicMock()
    rpc_resp.data = {
        "user_id": test_id,
        "email": "analyst@example.com",
        "role": "analyst",
        "is_active": True,
        "display_name": "Test Analyst"
    }
    execute_rpc_mock = AsyncMock(return_value=rpc_resp)
    mock_db.rpc.return_value.execute = execute_rpc_mock
    
    mock_get_db.return_value = mock_db
    
    from app.main import app
    client = TestClient(app)
    
    response = client.post("/api/v1/auth/bootstrap-profile", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["profile"]["user_id"] == test_id
    mock_db.rpc.assert_called_once_with("bootstrap_current_user_profile", {})
    mock_db.table.assert_not_called()
