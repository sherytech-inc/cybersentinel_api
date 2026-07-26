import asyncio
import json
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
from app.services.chatbot.router import ChatRouter, ContextUnavailableError
from app.services.websocket.connection_manager import WebSocketHub


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
        (
            LLMConfigurationError("groq_not_configured"),
            copilot_routes.NOT_CONFIGURED,
        ),
        (LLMTimeoutError("timeout"), copilot_routes.TEMPORARILY_UNAVAILABLE),
        (LLMRateLimitError("busy"), copilot_routes.RATE_LIMITED),
        (
            LLMConfigurationError("groq_configuration_rejected"),
            copilot_routes.TEMPORARILY_UNAVAILABLE,
        ),
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
    assert response.response == expected
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
                "session_id": "session-last",
                "packets_captured": 12,
                "packets_per_second": 0,
                "analysis": {
                    "completed_packets": 7,
                    "partial_packets": 2,
                    "pending_packets": 0,
                    "failed_packets": 1,
                    "deferred_packets": 0,
                    "cancelled_packets": 2,
                },
                "flows": {
                    "last_reliable_score": 18.0,
                    "highest_severity": "LOW",
                },
            }

    class Query:
        def select(self, *_): return self
        def eq(self, *_): return self
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
    assert context["analyzed_count"] == 9
    assert context["complete_count"] == 7
    assert context["partial_count"] == 2
    assert context["not_analyzed_count"] == 0
    assert (
        context["analyzed_count"]
        + context["failed_count"]
        + context["deferred_count"]
        + context["cancelled_count"]
        + context["not_analyzed_count"]
        + context["pending_count"]
        == context["captured_count"]
    )
    assert context["session_scope"] == "last_in_memory_session"
    assert context["last_reliable_score"] == 18.0
    assert context["packet_rate"] == 0.0
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
                "model3_intel_score": 0.0,
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
    assert context["recent_flows"][0]["model3"]["availability"] == "unavailable"
    assert context["recent_flows"][0]["model3"]["intelligence_score"] == 0.0
    assert context["latest_analyzed_flow"]["flow_id"] == "flow-1"


@pytest.mark.asyncio
async def test_context_includes_bounded_real_alerts_and_enforcement_results(
    monkeypatch,
):
    class Capture:
        flow_manager = type(
            "FlowManager",
            (),
            {"get_recent_completed": lambda self, limit: []},
        )()

        def get_status(self):
            return {
                "state": "running",
                "interface": "en0",
                "packets_captured": 20,
                "analysis": {"analyzed_packets": 10, "pending_packets": 10},
            }

    class Query:
        def __init__(self, rows):
            self.rows = rows

        def select(self, *_): return self
        def eq(self, *_): return self
        def order(self, *_, **__): return self
        def limit(self, *_): return self
        async def execute(self):
            return type("Result", (), {"data": self.rows})()

    class DB:
        def table(self, name):
            if name == "threat_alerts":
                return Query(
                    [
                        {
                            "alert_id": "alert-1",
                            "source_ip": "198.51.100.8",
                            "severity": "HIGH",
                            "status": "INVESTIGATING",
                            "action": "INVESTIGATE",
                            "threat_score": 82.0,
                            "summary": "Suspicious flow",
                            "model1_classification": "Suspicious",
                            "model1_score": 0.91,
                            "model2_score": 88.0,
                            "model3_score": None,
                            "timeline": [
                                {
                                    "event": "CREATED",
                                    "context": {
                                        "flow_id": "flow-1",
                                        "analysis_status": "partial",
                                    },
                                }
                            ],
                            "created_at": "2026-07-26T00:00:00Z",
                            "updated_at": "2026-07-26T00:01:00Z",
                        }
                    ]
                )
            if name == "audit_logs":
                return Query(
                    [
                        {
                            "id": "action-1",
                            "resource_id": "alert-1",
                            "ip_address": "198.51.100.8",
                            "action": "BLOCK",
                            "payload": {
                                "recorded": True,
                                "enforced": False,
                                "status": "RECORDED_ONLY",
                                "result": "recorded_only",
                            },
                            "created_at": "2026-07-26T00:02:00Z",
                        }
                    ]
                )
            return Query([])

    monkeypatch.setattr(
        "app.services.chatbot.context_builder.get_capture_service",
        lambda: Capture(),
    )
    context = await ContextBuilder().build(
        DB(),
        "EXPLAIN_ALERT",
        "Was this IP actually blocked?",
    )
    assert len(context["recent_alerts"]) == 1
    assert context["open_alerts"][0]["alert_id"] == "alert-1"
    assert context["open_alerts"][0]["flow_id"] == "flow-1"
    assert context["recent_response_actions"][0]["enforced"] is False
    assert (
        context["recent_response_actions"][0]["enforcement_status"]
        == "not_enforced"
    )
    assert context["recent_response_actions"][0]["status"] == "RECORDED_ONLY"
    assert len(context["recent_alerts"]) <= ContextBuilder.ALERT_LIMIT


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


@pytest.mark.asyncio
async def test_active_pending_and_terminal_status_context(monkeypatch):
    class Flow:
        def __init__(self, flow_id):
            self.flow_id = flow_id

        def model_dump(self):
            return {
                "flow_id": self.flow_id,
                "src_ip": f"192.0.2.{self.flow_id[-1]}",
                "dst_ip": "198.51.100.1",
                "src_port": 50000,
                "dst_port": 443,
                "protocol": "TCP",
                "total_packets": 2,
            }

    class Capture:
        flow_manager = type(
            "FlowManager",
            (),
            {
                "get_recent_completed": lambda self, limit: [
                    Flow("flow-1"),
                    Flow("flow-2"),
                    Flow("flow-3"),
                ]
            },
        )()

        def get_status(self):
            return {
                "state": "running",
                "interface": "en0",
                "session_id": "session-live",
                "packets_captured": 9,
                "packets_per_second": 4.5,
                "analysis": {
                    "completed_packets": 2,
                    "partial_packets": 2,
                    "pending_packets": 3,
                    "failed_packets": 2,
                    "deferred_packets": 0,
                    "cancelled_packets": 0,
                    "queue_depth": 2,
                    "queue_capacity": 64,
                },
                "flows": {
                    "last_reliable_score": 42.0,
                    "highest_severity": "MEDIUM",
                },
            }

    rows = [
        {
            "flow_id": "flow-1",
            "session_id": "session-live",
            "analysis_status": "complete",
            "ml_prediction": "Normal",
            "ml_confidence": 0.0,
            "anomaly_score": 0.0,
            "model3_available": True,
            "model3_intelligence_score": 0.0,
            "threat_score": 8.0,
            "severity": "LOW",
            "action": "ALLOW",
            "packet_ids": ["p1", "p2"],
        },
        {
            "flow_id": "flow-2",
            "session_id": "session-live",
            "analysis_status": "partial",
            "model3_available": False,
            "threat_score": 42.0,
            "severity": "MEDIUM",
            "action": "INVESTIGATE",
            "packet_ids": ["p3", "p4"],
        },
        {
            "flow_id": "flow-3",
            "session_id": "session-live",
            "analysis_status": "failed",
            "model3_available": None,
            "packet_ids": ["p5", "p6"],
        },
    ]

    class Query:
        def __init__(self, data):
            self.data = data

        def select(self, *_): return self
        def eq(self, *_): return self
        def order(self, *_, **__): return self
        def limit(self, *_): return self
        async def execute(self):
            return type("Result", (), {"data": self.data})()

    class DB:
        def table(self, name):
            return Query([])

    monkeypatch.setattr(
        "app.services.chatbot.context_builder.get_capture_service",
        lambda: Capture(),
    )
    monkeypatch.setattr(
        "app.services.chatbot.context_builder.get_websocket_hub",
        lambda: type(
            "Hub",
            (),
            {
                "get_recent_analysis_context": (
                    lambda self, limit, session_id=None: rows
                )
            },
        )(),
    )
    context = await ContextBuilder().build(
        DB(),
        "THREAT_SUMMARY",
        "Why are packets pending?",
    )
    assert context["capture_mode"] == "live"
    assert context["pending_count"] == 3
    assert context["monitoring_assessment"] == "monitoring_active_analysis_pending"
    assert [flow["analysis_status"] for flow in context["recent_flows"]] == [
        "complete",
        "partial",
        "failed",
    ]
    assert context["recent_flows"][0]["model1"]["confidence"] == 0.0
    assert context["recent_flows"][1]["model3"]["availability"] == "unavailable"
    assert context["recent_flows"][2]["threat_score"] is None


@pytest.mark.asyncio
async def test_resolved_and_ignored_alerts_are_not_open(monkeypatch):
    class Capture:
        flow_manager = type(
            "FlowManager",
            (),
            {"get_recent_completed": lambda self, limit: []},
        )()

        def get_status(self):
            return {
                "state": "stopped",
                "packets_captured": 0,
                "analysis": {},
                "flows": {},
            }

    alerts = [
        {"alert_id": "resolved", "status": "RESOLVED", "severity": "HIGH"},
        {
            "alert_id": "ignored",
            "status": "FALSE_POSITIVE",
            "severity": "HIGH",
        },
        {
            "alert_id": "open",
            "status": "OPEN",
            "severity": "CRITICAL",
        },
    ]

    class Query:
        def __init__(self, rows):
            self.rows = rows

        def select(self, *_): return self
        def eq(self, *_): return self
        def order(self, *_, **__): return self
        def limit(self, *_): return self
        async def execute(self):
            return type("Result", (), {"data": self.rows})()

    class DB:
        def table(self, name):
            return Query(alerts if name == "threat_alerts" else [])

    monkeypatch.setattr(
        "app.services.chatbot.context_builder.get_capture_service",
        lambda: Capture(),
    )
    context = await ContextBuilder().build(DB(), "EXPLAIN_ALERT", "open threats")
    assert {item["status"] for item in context["recent_alerts"]} == {
        "RESOLVED",
        "FALSE_POSITIVE",
        "OPEN",
    }
    assert [item["alert_id"] for item in context["open_alerts"]] == ["open"]


@pytest.mark.asyncio
async def test_context_and_conversation_are_strictly_bounded(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "COPILOT_CONTEXT_MAX_CHARS", 2_000)

    class Capture:
        flow_manager = type(
            "FlowManager",
            (),
            {"get_recent_completed": lambda self, limit: []},
        )()

        def get_status(self):
            return {
                "state": "stopped",
                "packets_captured": 0,
                "analysis": {},
                "flows": {},
            }

    large_alerts = [
        {
            "alert_id": f"alert-{index}",
            "status": "OPEN",
            "severity": "HIGH",
            "summary": "x" * 5_000,
        }
        for index in range(20)
    ]
    large_actions = [
        {
            "id": f"action-{index}",
            "resource_id": f"alert-{index}",
            "action": "BLOCK",
            "payload": {
                "status": "RECORDED_ONLY",
                "enforced": False,
                "message": "y" * 5_000,
            },
        }
        for index in range(20)
    ]

    class Query:
        def __init__(self, rows):
            self.rows = rows

        def select(self, *_): return self
        def eq(self, *_): return self
        def order(self, *_, **__): return self
        def limit(self, *_): return self
        async def execute(self):
            return type("Result", (), {"data": self.rows})()

    class DB:
        def table(self, name):
            if name == "threat_alerts":
                return Query(large_alerts)
            if name == "audit_logs":
                return Query(large_actions)
            return Query([])

    monkeypatch.setattr(
        "app.services.chatbot.context_builder.get_capture_service",
        lambda: Capture(),
    )
    context = await ContextBuilder().build(DB(), "EXPLAIN_ALERT", "latest alert")
    assert len(json.dumps(context, default=str)) <= 2_000
    assert len(context.get("recent_alerts", [])) <= ContextBuilder.ALERT_LIMIT
    assert len(context.get("recent_response_actions", [])) <= ContextBuilder.ACTION_LIMIT


@pytest.mark.asyncio
async def test_prompt_contains_truthful_state_and_report_rules(monkeypatch):
    captured_messages = []

    async def build_context(self, db, intent, user_input):
        return {
            "capture_state": "stopped",
            "monitoring_active": False,
            "report_guidance": {"export_performed": False},
        }

    async def history(self, session_id, limit=10):
        return [
            {"role": "user", "content": "old-" + ("x" * 5_000)},
            {"role": "assistant", "content": "previous"},
        ]

    async def insert(self, data):
        return data

    async def answer(self, messages):
        captured_messages.extend(messages)
        return "Please open Reports to generate an export."

    monkeypatch.setattr(
        "app.services.chatbot.router.ContextBuilder.build",
        build_context,
    )
    monkeypatch.setattr(
        "app.services.chatbot.router.CopilotConversationRepository.get_session_history",
        history,
    )
    monkeypatch.setattr(
        "app.services.chatbot.router.CopilotConversationRepository.insert",
        insert,
    )
    monkeypatch.setattr("app.services.chatbot.router.LLMService.chat", answer)

    await ChatRouter().ask(object(), "session", "Can you generate a report?")
    prompt = captured_messages[0]["content"]
    assert "Monitoring is currently inactive." in prompt
    assert "No completed analysis is currently available." in prompt
    assert "operating-system firewall enforcement was not performed" in prompt
    assert "Never claim a report was generated or downloaded" in prompt
    assert "packet counts, not flow counts" in prompt
    assert "Do not redirect a summary question to Reports" in prompt
    history_messages = [
        message for message in captured_messages if message["role"] != "system"
    ][:-1]
    assert max(len(message["content"]) for message in history_messages) <= 2_000


@pytest.mark.asyncio
async def test_context_failure_has_distinct_safe_message(monkeypatch):
    class FailingRouter:
        async def ask(self, db, session_id, user_input):
            raise ContextUnavailableError("context_unavailable")

    monkeypatch.setattr(copilot_routes, "ChatRouter", FailingRouter)
    copilot_routes._request_times.clear()
    response = await copilot_routes.post_copilot_chat(
        CopilotChatRequest(session_id=str(uuid.uuid4()), message="status"),
        analyst(),
        object(),
    )
    assert response.available is False
    assert response.response == copilot_routes.CONTEXT_UNAVAILABLE


@pytest.mark.asyncio
async def test_live_analysis_context_is_retained_without_storage_or_clients(
    monkeypatch,
):
    class Capture:
        def get_status(self):
            return {"session_id": "session-live"}

    monkeypatch.setattr(
        "app.services.packet_capture.capture_service.get_capture_service",
        lambda: Capture(),
    )
    hub = WebSocketHub()
    await hub.broadcast(
        "packet_analysis_update",
        {
            "flow_id": "flow-live",
            "packet_ids": [f"packet-{index}" for index in range(20)],
            "analysis_status": "partial",
            "severity": "MEDIUM",
            "ml_prediction": "Suspicious",
            "ml_confidence": 0.81,
            "anomaly_score": -0.12,
            "threat_score": 54.0,
            "action": "INVESTIGATE",
            "model3_available": False,
            "model3_intelligence_score": None,
            "model_results": {
                "model1": {
                    "classification": "suspicious",
                    "anomaly_probability": 0.81,
                },
                "model2": {"anomaly_score": -0.12, "is_anomaly": True},
                "model3": None,
            },
        },
    )

    retained = hub.get_recent_analysis_context(
        10,
        session_id="session-live",
    )
    assert len(retained) == 1
    assert retained[0]["flow_id"] == "flow-live"
    assert retained[0]["analysis_status"] == "partial"
    assert retained[0]["model3_available"] is False
    assert len(retained[0]["packet_ids"]) == ContextBuilder.PACKET_ID_LIMIT


@pytest.mark.asyncio
async def test_unmatched_live_analysis_is_still_available_as_latest_flow(
    monkeypatch,
):
    builder = ContextBuilder()
    context = builder._merge_recent_flows(
        [],
        [
            {
                "flow_id": "flow-live-only",
                "packet_ids": ["packet-1"],
                "src_ip": "10.0.0.8",
                "dst_ip": "1.1.1.1",
                "src_port": 51234,
                "dst_port": 443,
                "protocol": "TCP",
                "analysis_status": "complete",
                "threat_score": 12.5,
                "severity": "SAFE",
                "model3_available": False,
            }
        ],
        [],
        [],
    )

    assert context[0]["flow_id"] == "flow-live-only"
    assert context[0]["source_ip"] == "10.0.0.8"
    assert context[0]["analysis_status"] == "complete"
    assert context[0]["threat_score"] == 12.5


@pytest.mark.asyncio
async def test_deferred_updates_do_not_evict_completed_analysis_context(
    monkeypatch,
):
    class Capture:
        def get_status(self):
            return {"session_id": "session-live"}

    monkeypatch.setattr(
        "app.services.packet_capture.capture_service.get_capture_service",
        lambda: Capture(),
    )
    hub = WebSocketHub()
    await hub.broadcast(
        "packet_analysis_update",
        {
            "flow_id": "flow-complete",
            "packet_ids": ["packet-complete"],
            "analysis_status": "complete",
            "severity": "SAFE",
            "threat_score": 8.0,
        },
    )
    for index in range(30):
        await hub.broadcast(
            "packet_analysis_update",
            {
                "flow_id": f"flow-deferred-{index}",
                "packet_ids": [f"packet-deferred-{index}"],
                "analysis_status": "deferred",
                "severity": "NOT ANALYZED",
            },
        )

    retained = hub.get_recent_analysis_context(
        10,
        session_id="session-live",
    )
    assert [row["flow_id"] for row in retained] == ["flow-complete"]
