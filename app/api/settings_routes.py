from fastapi import APIRouter, Depends, HTTPException, status
from app.api.auth_dependencies import get_current_analyst, require_admin, AnalystIdentity
from app.schemas.settings import (
    IntegrationsResponse,
    IntegrationTestResponse,
    IntegrationProvider
)
from app.services.settings.integration_status_service import IntegrationStatusService
from app.core.config import get_settings

router = APIRouter(prefix="/api/v1/settings", tags=["Settings"])

def get_integration_status_service(settings=Depends(get_settings)) -> IntegrationStatusService:
    return IntegrationStatusService(settings)

@router.get("/integrations", response_model=IntegrationsResponse)
async def get_integrations(
    analyst: AnalystIdentity = Depends(get_current_analyst),
    service: IntegrationStatusService = Depends(get_integration_status_service)
):
    """
    Returns the backend configuration status of all integrations.
    Requires authenticated user.
    """
    return await service.get_integrations_status()

@router.post("/integrations/{provider}/test", response_model=IntegrationTestResponse)
async def test_integration(
    provider: IntegrationProvider,
    analyst: AnalystIdentity = Depends(require_admin),
    service: IntegrationStatusService = Depends(get_integration_status_service)
):
    """
    Tests the connection to a specific provider.
    Requires administrator privileges.
    """
    return await service.test_connection(provider)
