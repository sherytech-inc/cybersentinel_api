"""
CyberSentinel — Copilot Context Routes
========================================
Provides a summarized context payload for the AI Copilot / RAG chatbot.
Designed for future integration with LLM + MITRE knowledge base.
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from supabase import AsyncClient

from app.api.auth_dependencies import AnalystIdentity, get_current_analyst
from app.core.config import get_settings
from app.database.client import get_db_client

from app.repositories import (
    get_threat_score_repo,
    get_firewall_action_repo,
    get_packet_repo,
)
from app.repositories.repositories import (
    ThreatScoreRepository,
    FirewallActionRepository,
    PacketRepository,
)
from app.services.packet_capture.capture_service import get_capture_service
from app.schemas.copilot import (
    CopilotContextResponse,
    AlertSummary,
    AttackTypeSummary,
    SystemHealthSummary,
    CopilotChatRequest,
    CopilotChatResponse,
    CopilotContextUsed,
)
from app.services.chatbot.llm_service import (
    LLMConfigurationError,
    LLMRateLimitError,
    LLMTimeoutError,
    LLMUnavailableError,
)
from app.services.chatbot.router import ChatRouter

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/copilot", tags=["Copilot"])
_request_times: dict[str, deque[float]] = defaultdict(deque)
_session_locks: dict[str, asyncio.Lock] = {}

NOT_CONFIGURED = "AI Analyst is unavailable because the language-model service is not configured."
TEMPORARILY_UNAVAILABLE = "AI Analyst is temporarily unavailable. Packet capture and threat monitoring are still running."
TEMPORARILY_BUSY = "AI Analyst is temporarily busy. Please try again shortly."


def _rate_limited(key: str) -> bool:
    settings = get_settings()
    now = time.monotonic()
    window = settings.COPILOT_RATE_LIMIT_WINDOW_SECONDS
    times = _request_times[key]
    while times and now - times[0] >= window:
        times.popleft()
    if len(times) >= settings.COPILOT_RATE_LIMIT_MAX_REQUESTS:
        return True
    times.append(now)
    return False


@router.post("/chat", response_model=CopilotChatResponse)
async def post_copilot_chat(
    body: CopilotChatRequest,
    analyst: AnalystIdentity = Depends(get_current_analyst),
    db: AsyncClient = Depends(get_db_client),
):
    """Answer through Groq using bounded server-authoritative live context."""
    capture_state = "unavailable"
    has_live_context = False
    try:
        capture = get_capture_service().get_status()
        capture_state = str(capture.get("state") or "stopped")
        has_live_context = True
    except Exception:
        pass

    context_used = CopilotContextUsed(
        capture_state=capture_state,
        has_live_context=has_live_context,
    )

    key = f"{analyst.user_id}:{body.session_id}"
    if _rate_limited(key):
        return CopilotChatResponse(
            session_id=body.session_id, intent="RATE_LIMITED", response=TEMPORARILY_BUSY,
            context_used=context_used, timestamp=datetime.now(timezone.utc), available=False,
        )

    lock = _session_locks.setdefault(key, asyncio.Lock())
    if lock.locked():
        return CopilotChatResponse(
            session_id=body.session_id, intent="BUSY", response=TEMPORARILY_BUSY,
            context_used=context_used, timestamp=datetime.now(timezone.utc), available=False,
        )

    try:
        async with lock:
            result = await ChatRouter().ask(db, body.session_id, body.message.strip())
        built_context = result.get("context_used") or {}
        return CopilotChatResponse(
            session_id=body.session_id,
            intent=result.get("intent", "GENERAL_CYBER"),
            response=result["response"],
            context_used=CopilotContextUsed(
                capture_state=str(built_context.get("capture_state", capture_state)),
                has_live_context=bool(built_context.get("live_context_available", has_live_context)),
            ),
            timestamp=datetime.now(timezone.utc),
            available=True,
        )
    except LLMConfigurationError:
        message = NOT_CONFIGURED
    except LLMRateLimitError:
        message = TEMPORARILY_BUSY
    except (LLMTimeoutError, LLMUnavailableError):
        message = TEMPORARILY_UNAVAILABLE
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning("Copilot request unavailable | type=%s", type(exc).__name__)
        message = TEMPORARILY_UNAVAILABLE
    finally:
        if not lock.locked():
            _session_locks.pop(key, None)

    return CopilotChatResponse(
        session_id=body.session_id,
        intent="UNAVAILABLE",
        response=message,
        context_used=context_used,
        timestamp=datetime.now(timezone.utc),
        available=False,
    )


@router.get("/context", response_model=CopilotContextResponse)
async def get_copilot_context(
    threat_repo: ThreatScoreRepository = Depends(get_threat_score_repo),
    fw_repo: FirewallActionRepository = Depends(get_firewall_action_repo),
    packet_repo: PacketRepository = Depends(get_packet_repo),
):
    """
    Build a summarized context payload for the AI Copilot.

    This endpoint aggregates recent alerts, critical threats, blocked IPs,
    attack type distribution, and system health into a single payload
    designed for injection into LLM prompts via RAG.
    """
    # Latest alerts (last 10 analyzed threats)
    recent_threats, _ = await threat_repo.list(
        order_by="scored_at", descending=True, page_size=10
    )
    latest_alerts = [
        AlertSummary(
            ip=r.get("source_ip", "unknown"),
            severity=r.get("severity", "UNKNOWN"),
            action=r.get("recommendation", "MONITOR"),
            reasons=r.get("reasoning", []) or [],
        )
        for r in recent_threats
    ]

    # Critical threats (score > 90)
    try:
        critical_result = await (
            threat_repo._db.table("threat_scores")
            .select("*")
            .gt("threat_score", 90.0)
            .order("scored_at", desc=True)
            .limit(10)
            .execute()
        )
        critical_threats = [
            AlertSummary(
                ip=r.get("source_ip", "unknown"),
                severity=r.get("severity", "CRITICAL"),
                action=r.get("recommendation", "BLOCK"),
                reasons=r.get("reasoning", []) or [],
            )
            for r in (critical_result.data or [])
        ]
    except Exception:
        critical_threats = []

    # Blocked IPs
    blocked_ips = await fw_repo.get_blocked_ips()

    # Packet stats for attack types
    packet_stats = await packet_repo.get_stats()
    top_attack_types = []
    if packet_stats.get("Malicious", 0) > 0:
        top_attack_types.append(AttackTypeSummary(type="Malicious Traffic", count=packet_stats["Malicious"]))
    if packet_stats.get("Suspicious", 0) > 0:
        top_attack_types.append(AttackTypeSummary(type="Suspicious Traffic", count=packet_stats["Suspicious"]))

    # System health from capture service
    try:
        capture = get_capture_service()
        status = capture.get_status()
        system_health = SystemHealthSummary(
            status="operational",
            capture_state=status.get("state", "idle"),
            packets_captured=status.get("packets_captured", 0),
        )
    except Exception:
        system_health = SystemHealthSummary()

    return CopilotContextResponse(
        latest_alerts=latest_alerts,
        critical_threats=critical_threats,
        blocked_ips=blocked_ips,
        top_attack_types=top_attack_types,
        system_health=system_health,
    )

