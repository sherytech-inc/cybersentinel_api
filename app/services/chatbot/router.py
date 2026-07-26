import json
import logging

from app.repositories.repositories import CopilotConversationRepository
from app.services.chatbot.context_builder import ContextBuilder
from app.services.chatbot.llm_service import LLMService
from app.services.chatbot.query_classifier import QueryClassifier

logger = logging.getLogger(__name__)


class ContextUnavailableError(RuntimeError):
    pass


TRUTHFUL_SYSTEM_PROMPT = """You are CyberSentinel's AI Security Analyst. Be concise and clear for a non-technical user unless technical detail is requested. Use only the supplied CyberSentinel context. Never invent packet, flow, model, intelligence, alert, score, severity, action, or export values.

Truth rules:
- When monitoring_active is false, say: "Monitoring is currently inactive." Never treat inactivity or zero alerts as proof of safety.
- When monitoring is active and pending_count is above zero, say: "Monitoring is active, but analysis is still pending."
- Only describe low risk when completed analysis supports it: "Completed analysis currently indicates low risk."
- For partial analysis say: "The result is partial because one or more analysis sources were unavailable."
- For failed analysis say: "The flow could not be fully analyzed."
- When no complete or valid partial flow exists, say: "No completed analysis is currently available."
- Model 3 unavailable means external threat intelligence was unavailable; it is not a numeric zero and is not evidence of safety.
- RECORDED_ONLY or enforced=false means: "The action was recorded, but operating-system firewall enforcement was not performed." Never say an IP was actually blocked unless enforced is true.
- last_in_memory_session is temporary last-session context retained by the current backend process. Do not claim it is durable after restart.
- captured_count, analyzed_count, pending_count, complete_count, partial_count, failed_count, deferred_count, cancelled_count, and not_analyzed_count are packet counts, not flow counts.
- For current-session or last-session summary questions, summarize the supplied counts and reliable analysis evidence directly. Do not redirect a summary question to Reports.
- Only for full report or export requests, direct the user to Reports. Never claim a report was generated or downloaded unless export_performed is true.
- If reliable live context is unavailable, say so explicitly.

Ground every recommendation in available evidence."""


class ChatRouter:
    HISTORY_LIMIT = 10
    HISTORY_MESSAGE_MAX_CHARS = 2_000
    HISTORY_TOTAL_MAX_CHARS = 12_000

    async def ask(self, db, session_id: str, user_input: str) -> dict:
        intent = QueryClassifier().classify(user_input)
        try:
            context = await ContextBuilder().build(db, intent, user_input)
        except Exception as exc:
            logger.warning(
                "Copilot context construction failed | type=%s",
                type(exc).__name__,
            )
            raise ContextUnavailableError("context_unavailable") from exc
        repo = CopilotConversationRepository(db)
        try:
            history_records = await repo.get_session_history(
                session_id,
                limit=self.HISTORY_LIMIT,
            )
        except Exception:
            history_records = []

        messages = [
            {"role": "system", "content": TRUTHFUL_SYSTEM_PROMPT},
            {"role": "system", "content": f"CyberSentinel context: {json.dumps(context, default=str)}"},
        ]
        bounded_history: list[dict] = []
        history_chars = 0
        for record in reversed(history_records[-self.HISTORY_LIMIT :]):
            role = record.get("role")
            content = record.get("content")
            if role in {"user", "assistant"} and isinstance(content, str):
                bounded_content = content[: self.HISTORY_MESSAGE_MAX_CHARS]
                if history_chars + len(bounded_content) > self.HISTORY_TOTAL_MAX_CHARS:
                    continue
                history_chars += len(bounded_content)
                bounded_history.append(
                    {"role": role, "content": bounded_content}
                )
        messages.extend(reversed(bounded_history))
        messages.append({"role": "user", "content": user_input})

        llm = LLMService()
        response_text = await llm.chat(messages)
        for role, content, used_context in (
            ("user", user_input, {}),
            ("assistant", response_text, context),
        ):
            try:
                await repo.insert({
                    "session_id": session_id,
                    "role": role,
                    "content": content,
                    "context_used": used_context,
                    "model_used": llm.model,
                })
            except Exception as exc:
                logger.warning("Copilot history persistence skipped | type=%s", type(exc).__name__)
        return {"intent": intent, "response": response_text, "context_used": context}
