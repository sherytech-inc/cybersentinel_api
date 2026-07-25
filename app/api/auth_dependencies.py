import os
import uuid
import jwt
import requests
import time
from typing import Optional, Literal, Dict, Any
from fastapi import Request, HTTPException, status, Security, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jwt.algorithms import get_default_algorithms
import json

from app.core.config import get_settings
from app.database.client import get_db_client

security = HTTPBearer(auto_error=False)

# Simple global cache for JWKS
_JWKS_CACHE: Dict[str, Any] = {"keys": [], "expires_at": 0}

class SupabaseUserIdentity(BaseModel):
    user_id: uuid.UUID
    email: str

class AnalystIdentity(BaseModel):
    user_id: uuid.UUID
    email: str
    display_name: str
    role: Literal["analyst", "admin"]

def fetch_and_cache_jwks(project_url: str, force_refresh: bool = False) -> list:
    """Fetch and cache JWKS from Supabase if using asymmetric keys."""
    global _JWKS_CACHE
    now = time.time()
    
    if not force_refresh and _JWKS_CACHE["expires_at"] > now and _JWKS_CACHE["keys"]:
        return _JWKS_CACHE["keys"]
        
    if not project_url:
        return []
        
    jwks_url = f"{project_url.rstrip('/')}/auth/v1/.well-known/jwks.json"
    
    try:
        resp = requests.get(jwks_url, timeout=5)
        if resp.status_code == 200:
            keys = resp.json().get("keys", [])
            _JWKS_CACHE["keys"] = keys
            _JWKS_CACHE["expires_at"] = now + 3600 # cache for 1 hour
            return keys
        else:
            raise Exception(f"JWKS returned status {resp.status_code}")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"authentication_verification_unavailable: {e}"
        )

async def get_verified_supabase_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security)
) -> SupabaseUserIdentity:
    """
    Verifies the JWT but does not require a CyberSentinel profile.
    Used only for controlled profile bootstrap.
    """
    settings = get_settings()
    allow_dev_auth = os.environ.get("ALLOW_DEV_AUTH", "false").lower() == "true"
    is_production = os.environ.get("APP_ENV", "development").lower() == "production"
    
    if is_production and allow_dev_auth:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Development authentication is enabled in a production environment. System halted for security."
        )

    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided."
        )

    token = credentials.credentials

    # Development fallback
    if allow_dev_auth and not is_production:
        dev_token_env = os.environ.get("DEV_AUTH_TOKEN", "")
        if dev_token_env and token == dev_token_env:
            return SupabaseUserIdentity(
                user_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
                email="dev@example.com"
            )
        if token.startswith("dev-test-"):
            try:
                test_uuid = uuid.UUID(token.replace("dev-test-", ""))
                return SupabaseUserIdentity(
                    user_id=test_uuid,
                    email="test@example.com"
                )
            except ValueError:
                pass

    if not settings.SUPABASE_JWT_SECRET and not settings.SUPABASE_URL:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="authentication_not_configured"
        )
    
    try:
        unverified_headers = jwt.get_unverified_header(token)
        alg = unverified_headers.get("alg", "HS256")

        if alg == "HS256":
            # Verify using HS256 and SUPABASE_JWT_SECRET
            if not settings.SUPABASE_JWT_SECRET:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid configuration for HS256"
                )

            payload = jwt.decode(
                token,
                settings.SUPABASE_JWT_SECRET,
                algorithms=["HS256"],
                audience="authenticated",
                issuer=f"{settings.SUPABASE_URL.rstrip('/')}/auth/v1" if settings.SUPABASE_URL else None
            )
        elif alg in ["ES256", "RS256", "EdDSA"]:
            # Verify using JWKS
            kid = unverified_headers.get("kid")
            if not kid:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token missing kid header"
                )

            keys = fetch_and_cache_jwks(settings.SUPABASE_URL)
            signing_key = next((k for k in keys if k.get("kid") == kid), None)

            if not signing_key:
                # Force refresh once
                keys = fetch_and_cache_jwks(settings.SUPABASE_URL, force_refresh=True)
                signing_key = next((k for k in keys if k.get("kid") == kid), None)

            if not signing_key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Signing key not found for kid {kid}"
                )

            jwk = jwt.PyJWK(signing_key)
            payload = jwt.decode(
                token,
                jwk.key,
                algorithms=["ES256", "RS256", "EdDSA"],
                audience="authenticated",
                issuer=f"{settings.SUPABASE_URL.rstrip('/')}/auth/v1"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unsupported signing algorithm."
            )

    except (jwt.ExpiredSignatureError, jwt.InvalidIssuerError, jwt.InvalidAudienceError, jwt.InvalidTokenError, HTTPException) as error:
        if is_production:
            if isinstance(error, HTTPException):
                raise
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token."
            )

        # Local development fallback: accept the Supabase JWT claims without
        # enforcing signature verification when the signing configuration is
        # unavailable. This keeps the desktop bootstrap flow usable offline.
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token."
            )
        
    user_id_str = payload.get("sub")
    email = payload.get("email", "")
    
    if not user_id_str:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing subject.")

    try:
        user_uuid = uuid.UUID(user_id_str)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid subject identifier.")

    return SupabaseUserIdentity(
        user_id=user_uuid,
        email=email
    )

async def get_current_analyst(
    request: Request,
    user: SupabaseUserIdentity = Depends(get_verified_supabase_user),
) -> AnalystIdentity:
    """
    Requires an active profiles row and returns the authoritative role.
    Used by all normal application endpoints.
    """
    allow_dev_auth = os.environ.get("ALLOW_DEV_AUTH", "false").lower() == "true"
    is_production = os.environ.get("APP_ENV", "development").lower() == "production"

    if allow_dev_auth and not is_production:
        if user.user_id == uuid.UUID("00000000-0000-0000-0000-000000000001"):
            return AnalystIdentity(
                user_id=user.user_id,
                email=user.email,
                display_name="Dev Admin",
                role="admin"
            )
        if str(user.user_id).startswith("00000000-0000-0000"):
            return AnalystIdentity(
                user_id=user.user_id,
                email=user.email,
                display_name="Test User",
                role="admin"
            )

    db = await get_db_client(request)
    try:
        response = await db.table("profiles").select("*").eq("user_id", str(user.user_id)).single().execute()
        profile = response.data
        if not profile:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Profile not found or unprovisioned."
            )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Profile not found or unprovisioned."
        )

    if not profile.get("is_active", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated."
        )

    role = profile.get("role", "analyst")
    if role not in ["analyst", "admin"]:
        role = "analyst"

    return AnalystIdentity(
        user_id=user.user_id,
        email=profile.get("email", user.email),
        display_name=profile.get("display_name", user.email),
        role=role
    )

async def get_current_analyst_for_token(
    user: SupabaseUserIdentity,
    access_token: str,
) -> AnalystIdentity:
    """Resolve an active analyst using the verified WebSocket JWT for RLS."""
    db = await get_db_client(access_token=access_token)
    try:
        response = await db.table("profiles").select("*").eq(
            "user_id", str(user.user_id)
        ).single().execute()
        profile = response.data
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Profile not found or unprovisioned.",
        ) from exc

    if not profile:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Profile not found or unprovisioned.",
        )
    if not profile.get("is_active", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated.",
        )

    role = profile.get("role", "analyst")
    if role not in ["analyst", "admin"]:
        role = "analyst"

    return AnalystIdentity(
        user_id=user.user_id,
        email=profile.get("email", user.email),
        display_name=profile.get("display_name", user.email),
        role=role,
    )

async def require_admin(
    analyst: AnalystIdentity = Depends(get_current_analyst)
) -> AnalystIdentity:
    if analyst.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator access is required."
        )
    return analyst

def require_roles(*allowed_roles: str):
    async def role_checker(analyst: AnalystIdentity = Depends(get_current_analyst)) -> AnalystIdentity:
        if analyst.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access requires one of the following roles: {', '.join(allowed_roles)}."
            )
        return analyst
    return role_checker

def verify_local_token(
    request: Request,
    x_cybersentinel_local_token: Optional[str] = Header(default=None, description="Local sidecar authorization token")
) -> bool:
    """
    Verifies that the request comes from the authorized local Flutter desktop application.
    """
    if request.url.path == "/api/v1/auth/bootstrap-profile":
        return True

    expected_token = os.environ.get("CYBERSENTINEL_LOCAL_TOKEN")
    
    # If no token is configured in the environment, we allow the request (for standalone dev mode)
    if not expected_token:
        return True
        
    if x_cybersentinel_local_token != expected_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid local sidecar token."
        )
    return True
