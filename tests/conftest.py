"""Pytest configuration for CyberSentinel API tests."""
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app

@pytest.fixture(autouse=True, scope="session")
async def initialize_database():
    from app.database.client import init_db
    await init_db()

@pytest.fixture
async def async_client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

@pytest.fixture(autouse=True, scope="function")
def clear_dependency_overrides():
    from app.api.auth_dependencies import get_current_analyst
    import uuid
    from app.api.auth_dependencies import AnalystIdentity
    
    def override_get_current_analyst():
        return AnalystIdentity(
            user_id=uuid.uuid4(),
            email="test@example.com",
            display_name="Test Analyst",
            role="admin"
        )
    app.dependency_overrides[get_current_analyst] = override_get_current_analyst
    yield
    app.dependency_overrides.pop(get_current_analyst, None)
