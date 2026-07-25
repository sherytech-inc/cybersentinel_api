from pydantic import BaseModel
from enum import Enum
from typing import Optional
from datetime import datetime

class IntegrationState(str, Enum):
    not_configured = "not_configured"
    configured = "configured"
    reachable = "reachable"
    authentication_failed = "authentication_failed"
    quota_exceeded = "quota_exceeded"
    unavailable = "unavailable"
    not_tested = "not_tested"
    cloud_managed = "cloud_managed"

class IntegrationProvider(str, Enum):
    virustotal = "virustotal"
    abuseipdb = "abuseipdb"
    groq = "groq"

class IntegrationStatus(BaseModel):
    provider: str
    configured: bool
    state: IntegrationState
    masked_hint: Optional[str] = None
    message: str
    last_checked_at: Optional[datetime] = None

class IntegrationsResponse(BaseModel):
    virustotal: IntegrationStatus
    abuseipdb: IntegrationStatus
    groq: IntegrationStatus

class IntegrationTestResponse(BaseModel):
    provider: str
    configured: bool
    state: IntegrationState
    message: str
    tested_at: datetime
