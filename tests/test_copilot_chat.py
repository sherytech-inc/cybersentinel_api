import asyncio
import uuid

import httpx
import pytest
from fastapi import Depends, FastAPI

from app.api import copilot_routes
from app.api.auth_dependencies import AnalystIdentity
from app.api.auth_dependencies import verify_local_token
from app.core.config import get_settings
from app.schemas.copilot import CopilotChatRequest
from app.services.chatbot.context_builder import ContextBuilder
from app.services.chatbot.llm_service import (
    LLMConfigurationError,
    LLMRateLimitError,
    LLMService,
    LLMTimeoutError,
)
from app.services.chatbot.router import ChatRouter


def analyst() -> AnalystIdentity:
    return AnalystIdentity(
        user_id=uuid.uuid4(),
        email="analyst@example.com",
        display_name="Analyst",
        role="analyst",
    )


@pytest.mark.asyncio
async def test_chat_route_requires_local_token_and_bearer_jwt(monkeypatch):
    test_app = FastAPI()
    test_app.include_router(
        copilot_routes.router, dependencies=[Depends(verify_local_token)]
    )
    monkeypatch.setenv("CYBERSENTINEL_LOCAL_TOKEN", "local-test-token")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=test_app), base_url="http://test"
    ) as client:
        missing_local = await client.post(
            "/api/v1/copilot/chat", json={"session_id": "s", "message": "status"}
        )
        missing_jwt = await client.post(
            "/api/v1/copilot/chat",
            headers={"X-CyberSentinel-Local-Token": "local-test-token"},
            json={"session_id": "s", "message": "status"},
        )
    assert missing_local.status_code == 403
    assert missing_jwt.status_code == 401


@pytest.mark.asyncio
async def test_missing_groq_key_is_controlled(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "GROQ_API_KEY", None)
    service = LLMService()
    with pytest.raises(LLMConfigurationError):
        await service.chat([{"role": "user", "content": "status"}])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (LLMConfigurationError("missing"), "not configured"),
        (LLMTimeoutError("timeout"), "temporarily unavailable"),
        (LLMRateLimitError("busy"), "temporarily busy"),
    ],
)
async def test_route_maps_groq_failures_safely(monkeypatch, error, expected):
    class FailingRouter:
        async def ask(self, db, session_id, user_input):
            raise error

    monkeypatch.setattr(copilot_routes, "ChatRouter", FailingRouter)
    copilot_routes._request_times.clear()
    response = await copilot_routes.post_copilot_chat(
        CopilotChatRequest(session_id=str(uuid.uuid4()), message="status"),
        analyst(),
        object(),
    )
    assert response.available is False
    assert expected in response.response
    assert "traceback" not in response.response.lower()


@pytest.mark.asyncio
async def test_duplicate_session_request_is_rejected(monkeypatch):
    entered = asyncio.Event()
    release = asyncio.Event()

    class SlowRouter:
        async def ask(self, db, session_id, user_input):
            entered.set()
            await release.wait()
            return {
                "intent": "THREAT_SUMMARY",
                "response": "Monitoring is inactive; that does not establish safety.",
                "context_used": {"capture_state": "stopped", "live_context_available": True},
            }

    monkeypatch.setattr(copilot_routes, "ChatRouter", SlowRouter)
    copilot_routes._request_times.clear()
    identity = analyst()
    body = CopilotChatRequest(session_id="same-session", message="status")
    first = asyncio.create_task(copilot_routes.post_copilot_chat(body, identity, object()))
    await entered.wait()
    second = await copilot_routes.post_copilot_chat(body, identity, object())
    release.set()
    await first
    assert second.available is False
    assert "busy" in second.response.lower()


@pytest.mark.asyncio
async def test_context_is_bounded_and_truthful_when_inactive(monkeypatch):
    class Capture:
        flow_manager = type("FlowManager", (), {"get_recent_completed": lambda self, limit: []})()

        def get_status(self):
            return {
                "state": "stopped",
                "interface": "en0",
                "packets_captured": 12,
                "packets_per_second": 0,
                "analysis": {"analyzed_packets": 10, "pending_packets": 0},
                "flows": {},
            }

    class Query:
        def select(self, *_): return self
        def order(self, *_, **__): return self
        def limit(self, *_): return self
        async def execute(self): return type("Result", (), {"data": []})()

    class DB:
        def table(self, _): return Query()

    monkeypatch.setattr(
        "app.services.chatbot.context_builder.get_capture_service", lambda: Capture()
    )
    context = await ContextBuilder().build(DB(), "THREAT_SUMMARY", "status")
    assert context["capture_state"] == "stopped"
    assert context["monitoring_active"] is False
    assert context["captured_count"] == 12
    assert len(context["recent_flows"]) <= 10
    assert len(context["recent_alerts"]) <= 5


@pytest.mark.asyncio
async def test_context_exposes_latest_completed_ephemeral_flow(monkeypatch):
    class CompletedFlow:
        def model_dump(self):
            return {
                "flow_id": "flow-1",
                "src_ip": "192.168.1.10",
                "dst_ip": "1.1.1.1",
                "src_port": 50000,
                "dst_port": 443,
                "protocol": "TCP",
            }

    class Capture:
        flow_manager = type(
            "FlowManager",
            (),
            {"get_recent_completed": lambda self, limit: [CompletedFlow()]},
        )()

        def get_status(self):
            return {
                "state": "running",
                "interface": "en0",
                "packets_captured": 5,
                "analysis": {"analyzed_packets": 2, "pending_packets": 3},
                "flows": {},
            }

    class Query:
        def select(self, *_): return self
        def order(self, *_, **__): return self
        def limit(self, *_): return self
        async def execute(self):
            return type("Result", (), {"data": [{
                "source_ip": "192.168.1.10",
                "analysis_status": "complete",
                "model1_prediction": "Normal",
                "model2_anomaly_score": 0.12,
                "model3_available": False,
                "threat_score": 8.0,
                "severity": "LOW",
                "recommendation": "ALLOW",
            }]})()

    class DB:
        def table(self, _): return Query()

    monkeypatch.setattr(
        "app.services.chatbot.context_builder.get_capture_service", lambda: Capture()
    )
    context = await ContextBuilder().build(
        DB(), "THREAT_SUMMARY", "Explain the latest analyzed flow"
    )

    assert context["recent_flows"][0]["flow_id"] == "flow-1"
    assert context["recent_flows"][0]["analysis_status"] == "complete"
    assert context["recent_flows"][0]["threat_score"] == 8.0


@pytest.mark.asyncio
async def test_llm_timeout_and_rate_limit_mapping(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "GROQ_API_KEY", "configured-for-test")

    async def timeout_post(*args, **kwargs):
        raise httpx.ReadTimeout("timeout")

    monkeypatch.setattr(httpx.AsyncClient, "post", timeout_post)
    with pytest.raises(LLMTimeoutError):
        await LLMService().chat([{"role": "user", "content": "status"}])


@pytest.mark.asyncio
async def test_history_persistence_failure_does_not_fail_response(monkeypatch):
    async def build_context(self, db, intent, user_input):
        return {"capture_state": "stopped", "monitoring_active": False}

    async def history(self, session_id, limit=10):
        return []

    async def failed_insert(self, data):
        raise RuntimeError("optional persistence unavailable")

    async def answer(self, messages):
        return "Monitoring is inactive; no current safety conclusion is available."

    monkeypatch.setattr(
        "app.services.chatbot.router.ContextBuilder.build", build_context
    )
    monkeypatch.setattr(
        "app.services.chatbot.router.CopilotConversationRepository.get_session_history",
        history,
    )
    monkeypatch.setattr(
        "app.services.chatbot.router.CopilotConversationRepository.insert",
        failed_insert,
    )
    monkeypatch.setattr("app.services.chatbot.router.LLMService.chat", answer)

    result = await ChatRouter().ask(object(), "session", "Is monitoring active?")
    assert result["response"].startswith("Monitoring is inactive")
