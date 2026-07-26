"""
CyberSentinel API — Application Entry Point
============================================
Registers all routers. Manages startup/shutdown lifecycle.
"""
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import configure_logging, get_settings
from app.services.intelligence.cache import init_cache
from app.database.client import init_db  # <-- Added Database Import
from app.api.health_routes import router as health_router
from app.api.intelligence_routes import router as intelligence_router
from app.api.decision_routes import router as decision_router
from app.services.packet_capture.capture_service import init_capture_service, get_capture_service
from app.api.packet_routes import router as packet_router
from app.api.analyze_routes import router as analyze_router
from app.api.operations_routes import router as operations_router
from app.api.firewall_log_routes import router as firewall_log_router
from app.api.firewall_action_routes import router as firewall_action_router
from app.api.copilot_routes import router as copilot_router
from app.api.scanner_routes import router as scanner_router
from app.api.system_routes import router as system_router
from app.api.response_routes import router as response_router
from app.api.reporting_routes import router as reporting_router
from app.api.demo_routes import router as demo_router
from app.api.timeline_routes import router as timeline_router
from app.api.settings_routes import router as settings_router
from app.api.capture_routes import router as capture_router
from app.services.websocket.connection_manager import get_websocket_hub
import asyncio
import os
import signal

logger = logging.getLogger(__name__)
_settings = get_settings()


async def monitor_managed_parent(parent_pid: int, interval: float = 0.5) -> None:
    """Stop this managed sidecar when its exact Flutter owner disappears."""
    while True:
        await asyncio.sleep(interval)
        try:
            os.kill(parent_pid, 0)
        except ProcessLookupError:
            logger.info("Managed parent exited; stopping sidecar.")
            os.kill(os.getpid(), signal.SIGTERM)
            return
        except PermissionError:
            # The parent still exists but cannot be inspected further.
            continue


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging(_settings)
    logger.info("Starting %s v%s", _settings.APP_NAME, _settings.APP_VERSION)
    
    # 1. Initialize Intelligence Cache
    init_cache(ttl_seconds=_settings.CACHE_TTL_SECONDS, max_size=_settings.CACHE_MAX_SIZE)
    logger.info("Intelligence cache ready")
    
    # 2. Validate Required ML Artifacts
    from pathlib import Path
    if not (Path(_settings.MODEL1_RF_PATH).exists() and Path(_settings.MODEL2_IF_PATH).exists()):
        logger.warning("Required ML artifacts missing at startup. Analysis features will fail.")

    # 3. Initialize Database Connection Pool
    if _settings.REQUIRE_DATABASE:
        await init_db()
        logger.info("Database client ready")
    else:
        logger.warning("REQUIRE_DATABASE is false. Running in degraded mode without DB.")
    
    # 4. Initialize Packet Capture Service
    init_capture_service()
    logger.info("Packet capture service ready")
    
    # 4. Start Central WebSocket Hub Event Loops
    hub = get_websocket_hub()
    app.state.heartbeat_task = asyncio.create_task(hub.run_heartbeat_loop())
    app.state.packet_batch_task = asyncio.create_task(hub.run_packet_batch_loop())
    parent_pid_value = os.environ.get("CYBERSENTINEL_PARENT_PID", "")
    if parent_pid_value.isdigit():
        app.state.parent_watchdog_task = asyncio.create_task(
            monitor_managed_parent(int(parent_pid_value))
        )
    logger.info("WebSocket Hub background tasks started")
    
    # 6. (Removed Integrations Warning because it is now managed by cloud control plane)

    # load_model1_artifacts(_settings)   # uncomment when integrating Models 1+2
    # load_model2_artifacts(_settings)
    yield
    # Stop WS tasks
    if hasattr(app.state, "heartbeat_task"):
        app.state.heartbeat_task.cancel()
    if hasattr(app.state, "packet_batch_task"):
        app.state.packet_batch_task.cancel()
    if hasattr(app.state, "parent_watchdog_task"):
        app.state.parent_watchdog_task.cancel()
        
    # Stop capture on shutdown if running
    try:
        service = get_capture_service()
        await service.stop()
    except Exception as e:
        logger.error("Error stopping capture service on shutdown: %s", e)
    logger.info("Shutdown complete")


app = FastAPI(
    title=_settings.APP_NAME,
    version=_settings.APP_VERSION,
    description=(
        "CyberSentinel API\n\n"
        "**Model 1** — Packet Classifier (Random Forest)\n"
        "**Model 2** — Anomaly Detector (Isolation Forest)\n"
        "**Model 3** — Threat Intelligence (AbuseIPDB + VirusTotal + GeoIP)\n"
        "**Model 4** — Decision Engine (Score Fusion + Recommendations)\n"
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "X-Request-ID"],
    expose_headers=["X-Request-ID", "Content-Disposition"],
)

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
import uuid

class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        req_id = request.headers.get("X-Request-ID")
        if not req_id:
            req_id = str(uuid.uuid4())
        
        # We inject the correlation ID into the logging context here if desired, 
        # but for now we just echo it back and log basic request info.
        logger.info("Request started: %s %s (X-Request-ID: %s)", request.method, request.url.path, req_id)
        
        response = await call_next(request)
        response.headers["X-Request-ID"] = req_id
        return response

app.add_middleware(RequestIDMiddleware)

# ── Routers ───────────────────────────────────────────────────────────────────
from fastapi import Depends
from app.api.auth_dependencies import verify_local_token

local_auth = [Depends(verify_local_token)]

app.include_router(health_router)         # Health and Readiness (No token needed)
app.include_router(intelligence_router, dependencies=local_auth)   # Model 3
app.include_router(decision_router, dependencies=local_auth)       # Model 4
app.include_router(packet_router, dependencies=local_auth)         # Packet Capture
app.include_router(analyze_router, dependencies=local_auth)        # Unified Analyze API
app.include_router(operations_router, dependencies=local_auth)         # Operations Queries
app.include_router(firewall_log_router, dependencies=local_auth)       # Read-only firewall log analysis
app.include_router(firewall_action_router, dependencies=local_auth)    # Firewall Actions
app.include_router(copilot_router, dependencies=local_auth)            # AI Copilot Context
app.include_router(scanner_router, dependencies=local_auth)            # Local VirusTotal scanner
app.include_router(system_router, dependencies=local_auth)             # System diagnostics & WS stats
app.include_router(response_router, dependencies=local_auth)           # Threat Response Center
app.include_router(reporting_router, dependencies=local_auth)          # Reports & Intelligence Center
app.include_router(demo_router, dependencies=local_auth)               # Demo Injection
app.include_router(timeline_router, dependencies=local_auth)           # Investigation Timeline
app.include_router(settings_router, dependencies=local_auth)           # Settings & Integrations
app.include_router(capture_router, dependencies=local_auth)            # Capture Settings

from app.api.auth_routes import router as auth_router
app.include_router(auth_router)

@app.get("/", tags=["Root"])
async def root() -> dict:
    return {"service": _settings.APP_NAME, "version": _settings.APP_VERSION, "status": "online", "docs": "/docs"}


# ── Unified Event Bus WebSocket Endpoint ──────────────────────────────────────
from fastapi import WebSocket, WebSocketDisconnect

@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    """Unified WebSocket connection stream for threats, status updates, batches, and heartbeats."""
    await websocket.accept()
    
    from fastapi.security import HTTPAuthorizationCredentials
    from app.api.auth_dependencies import (
        get_current_analyst_for_token,
        get_verified_supabase_user,
    )
    
    try:
        # Wait up to 10 seconds for auth payload
        import asyncio
        data = await asyncio.wait_for(websocket.receive_json(), timeout=10.0)
        if data.get("type") != "auth" or "token" not in data:
            logger.warning("Invalid WebSocket auth payload")
            await websocket.close(code=1008)
            return
            
        token = data["token"]
        local_token = data.get("local_token")
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        
        user = await get_verified_supabase_user(creds)

        # Check Local Token for WebSocket before performing scoped data access.
        import os
        expected_token = os.environ.get("CYBERSENTINEL_LOCAL_TOKEN")
        if expected_token:
            header_token = websocket.headers.get("x-cybersentinel-local-token")
            if (header_token != expected_token) and (local_token != expected_token):
                logger.warning("WebSocket local sidecar token verification failed.")
                await websocket.close(code=1008)
                return

        await get_current_analyst_for_token(user=user, access_token=token)
        await websocket.send_json({"type": "auth_ack", "status": "success"})
    except Exception as exc:
        logger.warning(
            "WebSocket authentication failed: %s", type(exc).__name__
        )
        await websocket.close(code=1008)
        return

    hub = get_websocket_hub()
    # connect handles adding to active_connections, but we already accepted
    # We will modify hub.connect slightly or just add directly
    hub.active_connections.add(websocket)
    logger.info("Client connected to unified WebSocket hub. Total: %d", len(hub.active_connections))
    await hub._send_initial_state(websocket, access_token=token)
    
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await hub.disconnect(websocket)
    except Exception as exc:
        logger.error("Error in websocket connection: %s", exc)
        await hub.disconnect(websocket)
