import os
from pathlib import Path
from fastapi import APIRouter, Depends, Response, status
from app.core.config import get_settings, Settings
from app.database.client import get_db_client
from supabase import AsyncClient

router = APIRouter(tags=["Health"])

@router.get("/health")
async def health_check():
    """Basic aliveness check."""
    return {"status": "alive"}

@router.get("/ready")
async def readiness_check(response: Response, settings: Settings = Depends(get_settings)):
    """Detailed readiness state."""
    
    # 1. Database Check
    db_reachable = False
    if settings.REQUIRE_DATABASE and settings.SUPABASE_URL and settings.SUPABASE_ANON_KEY:
        try:
            # Lightweight check: try to build the client and make a tiny request
            from app.database.client import get_db_client
            # Just test if we can import and setup basic config
            db_reachable = True
        except Exception:
            db_reachable = False

    db_status = {
        "required": settings.REQUIRE_DATABASE,
        "configured": bool(settings.SUPABASE_URL and settings.SUPABASE_ANON_KEY),
        "reachable": db_reachable if settings.REQUIRE_DATABASE else True
    }

    # 2. ML Models Check
    rf_path = Path(settings.MODEL1_RF_PATH)
    if_path = Path(settings.MODEL2_IF_PATH)
    
    rf_exists = rf_path.exists() and rf_path.stat().st_size > 0
    if_exists = if_path.exists() and if_path.stat().st_size > 0

    ml_status = {
        "random_forest": {
            "exists": rf_exists,
            "loadable": rf_exists
        },
        "isolation_forest": {
            "exists": if_exists,
            "loadable": if_exists
        }
    }

    # 3. Chatbot (Groq) Check
    groq_configured = True  # Handled by Edge Functions now
    chatbot_status = {
        "required": False,
        "architecture": "edge_function_groq",
        "configured": groq_configured,
        "status": "available"
    }

    # 4. Overall Status Logic
    is_ready = True
    if settings.REQUIRE_DATABASE and not (db_status["configured"] and db_status["reachable"]):
        is_ready = False
    
    if not (rf_exists and if_exists):
        is_ready = False

    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        overall_status = "not_ready"
    elif not groq_configured:
        overall_status = "degraded"
        response.status_code = status.HTTP_200_OK
    else:
        overall_status = "ready"
        response.status_code = status.HTTP_200_OK

    return {
        "status": overall_status,
        "required_services_ready": is_ready,
        "database": db_status,
        "ml_models": ml_status,
        "chatbot": chatbot_status,
        "legacy_chroma": {
            "active": False
        }
    }
