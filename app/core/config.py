"""
CyberSentinel API — Core Configuration
=======================================
Single source of truth for ALL settings across every model, phase, and service.
Thresholds for Model 4 scoring are here — tune without touching any other file.
"""
import logging
from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS_DIR = PROJECT_ROOT / "app" / "artifacts"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ───────────────────────────────────────────────────────────
    APP_NAME: str = "CyberSentinel API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # ── Supabase ──────────────────────────────────────────────────────────────
    SUPABASE_URL: str = ""
    SUPABASE_ANON_KEY: str = ""
    SUPABASE_SERVICE_ROLE_KEY: str = ""
    DATABASE_URL: str = ""

    # ── ML Artifact Paths ─────────────────────────────────────────────────────
    MODEL1_RF_PATH: str = str(ARTIFACTS_DIR / "model1" / "random_forest_best.pkl")
    MODEL1_SCALER_PATH: str = str(ARTIFACTS_DIR / "model1" / "best_scaler.pkl")
    MODEL1_ENCODER_PATH: str = str(ARTIFACTS_DIR / "model1" / "encoder.pkl")
    MODEL2_IF_PATH: str = str(ARTIFACTS_DIR / "model2" / "isolation_forest_model.pkl")
    MODEL2_SCALER_PATH: str = str(ARTIFACTS_DIR / "model2" / "robust_scaler.pkl")
    MODEL2_ENCODER_PATH: str = str(ARTIFACTS_DIR / "model2" / "onehot_encoder.pkl")

    # ── Threat Intelligence Keys ──────────────────────────────────────────────
    ABUSEIPDB_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_BASE_URL: str = "https://api.abuseipdb.com/api/v2"
    ABUSEIPDB_MAX_AGE_DAYS: int = 90
    ABUSEIPDB_TIMEOUT: float = 10.0
    VIRUSTOTAL_BASE_URL: str = "https://www.virustotal.com/api/v3"
    VIRUSTOTAL_TIMEOUT: float = 15.0
    GEOIP_BASE_URL: str = "http://ip-api.com/json"
    GEOIP_TIMEOUT: float = 5.0

    # ── HTTP Resilience ───────────────────────────────────────────────────────
    HTTP_MAX_RETRIES: int = 3
    HTTP_RETRY_BACKOFF: float = 1.5
    HTTP_RETRY_STATUSES: list[int] = [429, 500, 502, 503, 504]

    # ── Intelligence Cache ────────────────────────────────────────────────────
    CACHE_TTL_SECONDS: int = 3600
    CACHE_MAX_SIZE: int = 10_000

    # ── Model 3 Internal Scoring Weights ──────────────────────────────────────
    SCORE_WEIGHT_ABUSEIPDB: float = 0.40
    SCORE_WEIGHT_VIRUSTOTAL: float = 0.40
    SCORE_WEIGHT_GEO: float = 0.20

    # ── Model 4 — Decision Engine Weights ─────────────────────────────────────
    # Tune these without touching any other file.
    M4_WEIGHT_MODEL1: float = 0.50   # Random Forest classifier
    M4_WEIGHT_MODEL2: float = 0.20   # Isolation Forest anomaly
    M4_WEIGHT_MODEL3: float = 0.30   # Threat intelligence composite

    # Model 3 sub-weights used inside the M4 intel scorer
    M4_W3_ABUSE: float = 0.70        # AbuseIPDB share inside Model 3
    M4_W3_VT: float = 0.30           # VirusTotal share inside Model 3

    # ── Model 4 — Severity Thresholds ────────────────────────────────────────
    M4_SAFE_MAX: float = 25.0
    M4_LOW_MAX: float = 50.0
    M4_MEDIUM_MAX: float = 75.0
    M4_HIGH_MAX: float = 90.0
    # 91–100 → Critical

    # ── Model 4 — Action Thresholds ──────────────────────────────────────────
    M4_ACTION_ALLOW_MAX: float = 25.0
    M4_ACTION_MONITOR_MAX: float = 50.0
    M4_ACTION_INVESTIGATE_MAX: float = 75.0
    M4_ACTION_ALERT_MAX: float = 90.0
    # 91–100 → BLOCK

    # ── AI Copilot ────────────────────────────────────────────────────────────
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    GROQ_MAX_TOKENS: int = 2048
    GROQ_TEMPERATURE: float = 0.1

    # ── Reporting ─────────────────────────────────────────────────────────────
    REPORT_OUTPUT_DIR: str = str(PROJECT_ROOT / "reports")

    # ── CORS ──────────────────────────────────────────────────────────────────
    CORS_ORIGINS: list[str] = ["*"]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def configure_logging(settings: Settings) -> None:
    level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )