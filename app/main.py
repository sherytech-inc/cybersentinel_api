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
from app.api.intelligence_routes import router as intelligence_router
from app.api.decision_routes import router as decision_router

logger = logging.getLogger(__name__)
_settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging(_settings)
    logger.info("Starting %s v%s", _settings.APP_NAME, _settings.APP_VERSION)
    
    # 1. Initialize Intelligence Cache
    init_cache(ttl_seconds=_settings.CACHE_TTL_SECONDS, max_size=_settings.CACHE_MAX_SIZE)
    logger.info("Intelligence cache ready")
    
    # 2. Initialize Database Connection Pool
    await init_db()  # <-- Added Database Initialization
    logger.info("Database client ready")
    
    # load_model1_artifacts(_settings)   # uncomment when integrating Models 1+2
    # load_model2_artifacts(_settings)
    yield
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
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(intelligence_router)   # Model 3
app.include_router(decision_router)       # Model 4


@app.get("/", tags=["Root"])
async def root() -> dict:
    return {"service": _settings.APP_NAME, "version": _settings.APP_VERSION, "status": "online", "docs": "/docs"}