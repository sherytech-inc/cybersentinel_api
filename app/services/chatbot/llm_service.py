import asyncio
import logging

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)


class LLMUnavailableError(RuntimeError):
    pass


class LLMTimeoutError(LLMUnavailableError):
    pass


class LLMRateLimitError(LLMUnavailableError):
    pass


class LLMConfigurationError(LLMUnavailableError):
    pass


class LLMService:
    def __init__(self):
        self.settings = get_settings()
        self.api_key = self.settings.GROQ_API_KEY
        self.model = self.settings.GROQ_MODEL
        self.max_tokens = self.settings.GROQ_MAX_TOKENS
        self.temperature = self.settings.GROQ_TEMPERATURE
        self.endpoint = "https://api.groq.com/openai/v1/chat/completions"

    async def chat(self, messages: list[dict]) -> str:
        if not self.api_key:
            raise LLMConfigurationError("groq_not_configured")
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }
        try:
            timeout = httpx.Timeout(self.settings.GROQ_REQUEST_TIMEOUT_SECONDS)
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    self.endpoint, headers=headers, json=payload
                )
            if response.status_code == 429:
                raise LLMRateLimitError("groq_rate_limited")
            if response.status_code in {400, 401, 403, 404, 422}:
                logger.warning("Groq configuration rejected | status=%s", response.status_code)
                raise LLMConfigurationError("groq_configuration_rejected")
            response.raise_for_status()
            data = response.json()
            return str(data["choices"][0]["message"]["content"])
        except asyncio.CancelledError:
            raise
        except (httpx.TimeoutException, asyncio.TimeoutError) as exc:
            raise LLMTimeoutError("groq_timeout") from exc
        except (LLMRateLimitError, LLMConfigurationError):
            raise
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            logger.warning("Groq request unavailable | type=%s", type(exc).__name__)
            raise LLMUnavailableError("groq_unavailable") from exc
