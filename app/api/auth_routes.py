import logging
from fastapi import APIRouter, Depends, HTTPException, Request, status
from typing import Dict, Any

from app.api.auth_dependencies import get_verified_supabase_user, SupabaseUserIdentity
from app.database.client import get_db_client
from app.core.config import get_settings

router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])
logger = logging.getLogger(__name__)

@router.post("/bootstrap-profile")
async def bootstrap_profile(
    request: Request,
    user: SupabaseUserIdentity = Depends(get_verified_supabase_user)
) -> Dict[str, Any]:
    """
    Atomic and body-independent verification of user registration.
    Triggered by Flutter after successful Supabase Auth (Email or Google).
    """
    settings = get_settings()
    normalized_email = user.email.strip().lower()

    if not normalized_email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The authenticated account does not contain a valid email.",
        )

    try:
        db = await get_db_client(request)
    except Exception:
        logger.exception("Profile database client initialization failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="profile_storage_unavailable",
        )
    
    if settings.ALLOW_SELF_REGISTRATION:
        # Create user in authorized_users if not exists
        try:
            await db.table("authorized_users").upsert({
                "email": normalized_email,
                "role": "analyst",
                "display_name": normalized_email,
                "is_active": True
            }, on_conflict="email", ignore_duplicates=True).execute()
        except Exception as e:
            logger.error("Error upserting authorized_user: %s", e)
            # Proceed anyway, authorized_users select will catch failure
    
    # Check authorized_users
    try:
        auth_user_resp = await db.table("authorized_users").select("*").eq("email", normalized_email).single().execute()
        auth_user = auth_user_resp.data
        if not auth_user:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This account has not been authorized to access CyberSentinel."
            )
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has not been authorized to access CyberSentinel."
        )
        
    if not auth_user.get("is_active", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This CyberSentinel account has been disabled."
        )

    role = auth_user.get("role", "analyst")
    display_name = auth_user.get("display_name", normalized_email)

    # Upsert the profile with retry-safe convergence
    profile_data = {
        "user_id": str(user.user_id),
        "email": normalized_email,
        "display_name": display_name,
        "role": role,
        "is_active": True
    }
    
    try:
        res = await db.table("profiles").upsert(
            profile_data, 
            on_conflict="user_id"
        ).execute()
        
        if not res.data:
            raise Exception("Upsert failed to return data")
            
        profile = res.data[0]
    except Exception as e:
        logger.error("Error during profile bootstrap: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to complete profile registration."
        )
        
    return {
        "status": "success",
        "profile": profile
    }
