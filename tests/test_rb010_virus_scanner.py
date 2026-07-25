import pytest
from app.schemas.operations import ScanStatus

@pytest.mark.asyncio
async def test_rb010_scan_url_not_configured(async_client):
    # Because we don't have an API key set, it should return not_configured 
    # (if the real client handles no-api-key)
    response = await async_client.post("/api/v1/virus/scan?target=http://example.com&type=url")
    # According to our updated operations_routes.py, if the status is not_configured, it returns 200 or 503
    # In operations_routes, if it is unavailable it raises 503. If not_configured is not handled explicitly it returns 200.
    assert response.status_code in [200, 503]
    if response.status_code == 200:
        data = response.json()
        assert data["status"] in ["not_configured", "unavailable"]

@pytest.mark.asyncio
async def test_rb010_scan_file_invalid_target(async_client):
    # If we pass type=file but we don't support file picker, we might expect invalid_target if we don't pass a valid hash
    response = await async_client.post("/api/v1/virus/scan?target=invalid_hash&type=hash")
    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Invalid hash format. SHA-256 hash must be exactly 64 hexadecimal characters."

@pytest.mark.asyncio
async def test_rb010_firewall_upload_unsupported_format(async_client):
    from app.main import app
    from app.api.auth_dependencies import require_admin, AnalystIdentity
    from app.api.operations_routes import get_virus_repo
    import uuid
    app.dependency_overrides[require_admin] = lambda: AnalystIdentity(
        user_id=uuid.uuid4(),
        email="admin@example.com",
        display_name="Admin",
        role="admin"
    )
    try:
        response = await async_client.post("/api/v1/operations/firewall/upload", files={"file": ("fake.log", b"fake data")})
        assert response.status_code == 422
        data = response.json()
        assert data["detail"]["status"] == "unsupported_format"
    finally:
        app.dependency_overrides.pop(get_virus_repo, None)
        app.dependency_overrides.pop(require_admin, None)
