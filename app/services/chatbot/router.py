import json
import logging

from app.repositories.repositories import CopilotConversationRepository
from app.services.chatbot.context_builder import ContextBuilder
from app.services.chatbot.llm_service import LLMService
from app.services.chatbot.query_classifier import QueryClassifier

logger = logging.getLogger(__name__)

TRUTHFUL_SYSTEM_PROMPT = """You are CyberSentinel's AI Security Analyst. Be concise and clear for a non-technical user unless technical detail is requested. Use only the supplied CyberSentinel context. Never invent packet, flow, model, intelligence, alert, score, severity, or action values. Monitoring inactive is not evidence that the network is safe. Pending analysis is not safe. Describe partial and failed analysis as incomplete. Distinguish monitoring inactive, monitoring active with pending analysis, completed low-risk analysis, partial analysis, and failed analysis. If reliable context is unavailable, say so explicitly. Ground recommended actions in available evidence."""


class ChatRouter:
    async def ask(self, db, session_id: str, user_input: str) -> dict:
        intent = QueryClassifier().classify(user_input)
        context = await ContextBuilder().build(db, intent, user_input)
        repo = CopilotConversationRepository(db)
        try:
            history_records = await repo.get_session_history(session_id, limit=10)
        except Exception:
            history_records = []

        messages = [
            {"role": "system", "content": TRUTHFUL_SYSTEM_PROMPT},
            {"role": "system", "content": f"CyberSentinel context: {json.dumps(context, default=str)}"},
        ]
        for record in history_records[-10:]:
            role = record.get("role")
            content = record.get("content")
            if role in {"user", "assistant"} and isinstance(content, str):
                messages.append({"role": role, "content": content[:4000]})
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
