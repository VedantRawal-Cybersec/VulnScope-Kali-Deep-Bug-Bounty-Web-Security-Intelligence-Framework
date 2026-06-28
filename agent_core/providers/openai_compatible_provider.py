from __future__ import annotations

import os
from typing import Any

from agent_core.providers.base_provider import BaseProvider, ProviderResponse


class OpenAICompatibleProvider(BaseProvider):
    provider_name = "openai-compatible"
    env_key = "OPENAI_API_KEY"
    default_model = "configured-default"
    base_url = "https://api.openai.com/v1/chat/completions"

    def chat(self, messages: list[dict[str, str]], temperature: float = 0.1, max_tokens: int = 1200) -> ProviderResponse:
        if not self.api_key:
            return ProviderResponse(self.provider_name, self.model, False, "", error=f"{self.env_key} is not configured")
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        ok, data, error = self._post_json(
            self.base_url,
            {"authorization": f"Bearer {self.api_key}", "content-type": "application/json"},
            payload,
        )
        if not ok or data is None:
            return ProviderResponse(self.provider_name, self.model, False, "", error=error)
        choices = data.get("choices", [])
        text = ""
        if choices:
            text = choices[0].get("message", {}).get("content", "")
        return ProviderResponse(self.provider_name, self.model, True, text, raw=data)


class OpenAIProvider(OpenAICompatibleProvider):
    provider_name = "openai"
    env_key = "OPENAI_API_KEY"
    default_model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    base_url = "https://api.openai.com/v1/chat/completions"


class DeepSeekProvider(OpenAICompatibleProvider):
    provider_name = "deepseek"
    env_key = "DEEPSEEK_API_KEY"
    default_model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
    base_url = "https://api.deepseek.com/chat/completions"


class GroqProvider(OpenAICompatibleProvider):
    provider_name = "groq"
    env_key = "GROQ_API_KEY"
    default_model = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
    base_url = "https://api.groq.com/openai/v1/chat/completions"


class OpenRouterProvider(OpenAICompatibleProvider):
    provider_name = "openrouter"
    env_key = "OPENROUTER_API_KEY"
    default_model = os.getenv("OPENROUTER_MODEL", "openrouter/auto")
    base_url = "https://openrouter.ai/api/v1/chat/completions"

    def chat(self, messages: list[dict[str, str]], temperature: float = 0.1, max_tokens: int = 1200) -> ProviderResponse:
        if not self.api_key:
            return ProviderResponse(self.provider_name, self.model, False, "", error="OPENROUTER_API_KEY is not configured")
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        ok, data, error = self._post_json(
            self.base_url,
            {
                "authorization": f"Bearer {self.api_key}",
                "content-type": "application/json",
                "http-referer": "https://github.com/VedantRawal-Cybersec/VulnScope",
                "x-title": "VulnScope",
            },
            payload,
        )
        if not ok or data is None:
            return ProviderResponse(self.provider_name, self.model, False, "", error=error)
        choices = data.get("choices", [])
        text = choices[0].get("message", {}).get("content", "") if choices else ""
        return ProviderResponse(self.provider_name, self.model, True, text, raw=data)
