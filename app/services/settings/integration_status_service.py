import logging
import httpx
from datetime import datetime, timezone
from app.core.config import Settings
from app.schemas.settings import (
    IntegrationProvider,
    IntegrationState,
    IntegrationStatus,
    IntegrationsResponse,
    IntegrationTestResponse,
)

logger = logging.getLogger(__name__)


def is_configured(value: str | None) -> bool:
    if not value or not value.strip():
        return False
    return value.strip().lower() not in {"changeme", "your_api_key_here"}


def mask_key(value: str | None) -> str | None:
    if not is_configured(value):
        return None
    normalized = value.strip()
    if len(normalized) <= 4:
        return "••••"
    return "••••" + normalized[-4:]

class IntegrationStatusService:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def get_integrations_status(self) -> IntegrationsResponse:
        vt_configured = is_configured(self.settings.VIRUSTOTAL_API_KEY)
        vt_status = IntegrationStatus(
            provider=IntegrationProvider.virustotal.value,
            configured=vt_configured,
            state=IntegrationState.configured if vt_configured else IntegrationState.not_configured,
            masked_hint=mask_key(self.settings.VIRUSTOTAL_API_KEY),
            message="VirusTotal is configured in the local service." if vt_configured else "VirusTotal is not configured.",
            last_checked_at=None
        )

        abuse_configured = is_configured(self.settings.ABUSEIPDB_API_KEY)
        abuse_status = IntegrationStatus(
            provider=IntegrationProvider.abuseipdb.value,
            configured=abuse_configured,
            state=IntegrationState.configured if abuse_configured else IntegrationState.not_configured,
            masked_hint=mask_key(self.settings.ABUSEIPDB_API_KEY),
            message="AbuseIPDB is configured in the local service." if abuse_configured else "AbuseIPDB is not configured.",
            last_checked_at=None
        )

        groq_configured = is_configured(self.settings.GROQ_API_KEY)
        groq_status = IntegrationStatus(
            provider=IntegrationProvider.groq.value,
            configured=groq_configured,
            state=IntegrationState.configured if groq_configured else IntegrationState.not_configured,
            masked_hint=mask_key(self.settings.GROQ_API_KEY),
            message="Groq is configured in the local service." if groq_configured else "Groq is not configured.",
            last_checked_at=None
        )

        return IntegrationsResponse(
            virustotal=vt_status,
            abuseipdb=abuse_status,
            groq=groq_status
        )

    async def test_connection(self, provider: IntegrationProvider) -> IntegrationTestResponse:
        now = datetime.now(timezone.utc)
        keys = {
            IntegrationProvider.virustotal: self.settings.VIRUSTOTAL_API_KEY,
            IntegrationProvider.abuseipdb: self.settings.ABUSEIPDB_API_KEY,
            IntegrationProvider.groq: self.settings.GROQ_API_KEY,
        }
        configured = is_configured(keys[provider])
        if not configured:
            return IntegrationTestResponse(
                provider=provider.value,
                configured=False,
                state=IntegrationState.not_configured,
                message="Integration is not configured.",
                tested_at=now,
            )
        urls = {
            IntegrationProvider.virustotal: "https://www.virustotal.com/api/v3/users/current",
            IntegrationProvider.abuseipdb: "https://api.abuseipdb.com/api/v2/check",
            IntegrationProvider.groq: "https://api.groq.com/openai/v1/models",
        }
        headers = {
            IntegrationProvider.virustotal: {"x-apikey": keys[provider]},
            IntegrationProvider.abuseipdb: {"Key": keys[provider]},
            IntegrationProvider.groq: {"Authorization": f"Bearer {keys[provider]}"},
        }[provider]
        params = {"ipAddress": "8.8.8.8"} if provider == IntegrationProvider.abuseipdb else None
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(urls[provider], headers=headers, params=params)
            if response.status_code == 429:
                state = IntegrationState.quota_exceeded
                message = "Integration is rate limited."
            elif response.status_code in {401, 403}:
                state = IntegrationState.authentication_failed
                message = "Integration credentials were rejected."
            elif response.status_code >= 400:
                state = IntegrationState.unavailable
                message = "Integration is temporarily unavailable."
            else:
                state = IntegrationState.reachable
                message = "Integration is reachable."
        except Exception as exc:
            logger.warning("Integration test unavailable | provider=%s type=%s", provider.value, type(exc).__name__)
            state = IntegrationState.unavailable
            message = "Integration is temporarily unavailable."
        return IntegrationTestResponse(
            provider=provider.value,
            configured=True,
            state=state,
            message=message,
            tested_at=now
        )
