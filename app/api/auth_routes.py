import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status
from postgrest.exceptions import APIError

from app.api.auth_dependencies import (
    SupabaseUserIdentity,
    get_verified_supabase_user,
)
from app.database.client import get_db_client

router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])
logger = logging.getLogger(__name__)


def _bootstrap_error_status(error: APIError) -> tuple[int, str]:
    reason = (error.message or "").strip().lower()
    if reason in {"authentication_required", "authenticated_email_missing"}:
        return status.HTTP_401_UNAUTHORIZED, reason
    if reason in {"account_not_authorized", "account_disabled"}:
        return status.HTTP_403_FORBIDDEN, reason
    if reason == "invalid_authorization_role":
        return (
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "profile_authorization_configuration_invalid",
        )
    return status.HTTP_503_SERVICE_UNAVAILABLE, "profile_storage_unavailable"


@router.post("/bootstrap-profile")
async def bootstrap_profile(
    request: Request,
    user: SupabaseUserIdentity = Depends(get_verified_supabase_user),
) -> Dict[str, Any]:
    """
    Bootstrap the caller's profile through the audited, creator-scoped RPC.

    The database client carries the same verified JWT, so auth.uid() and the
    signed email claim are authoritative inside the SECURITY DEFINER function.
    """
    normalized_email = user.email.strip().lower()
    if not normalized_email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authenticated_email_missing",
        )

    try:
        db = await get_db_client(request)
    except Exception:
        logger.error("Profile database client unavailable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="profile_storage_unavailable",
        )

    try:
        response = await db.rpc(
            "bootstrap_current_user_profile",
            {},
        ).execute()
    except APIError as error:
        status_code, detail = _bootstrap_error_status(error)
        logger.warning(
            "Profile bootstrap RPC rejected | code=%s reason=%s",
            error.code or "unknown",
            detail,
        )
        raise HTTPException(
            status_code=status_code,
            detail=detail,
        ) from error
    except Exception as error:
        logger.error(
            "Profile bootstrap RPC unavailable | type=%s",
            type(error).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="profile_storage_unavailable",
        ) from error

    profile = response.data
    if isinstance(profile, list):
        profile = profile[0] if len(profile) == 1 else None
    if (
        not isinstance(profile, dict)
        or str(profile.get("user_id")) != str(user.user_id)
        or str(profile.get("email", "")).strip().lower() != normalized_email
        or profile.get("is_active") is not True
        or profile.get("role") not in {"analyst", "admin"}
    ):
        logger.error("Profile bootstrap RPC returned an invalid result")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="profile_storage_unavailable",
        )

    return {
        "status": "success",
        "profile": profile,
    }
